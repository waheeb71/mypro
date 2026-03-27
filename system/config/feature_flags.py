"""
CyberNexus NGFW — Feature Flag Manager
=======================================
Single source of truth for all runtime feature toggles.

Features:
- Hot-reload: changes to features.yaml take effect within 5 seconds
- Thread-safe: safe to read from any thread
- Zero-restart: no service restart required on flag change
- Singleton: use FeatureFlagManager.instance() everywhere

Usage:
    flags = FeatureFlagManager.instance()
    if flags.is_enabled("ai_engine.enabled"):
        ai_score = await ai.score(ctx)
"""

import threading
import time
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# Strongly-typed Feature Flag dataclass
# ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DataPlaneFlags:
    enabled: bool = True
    ebpf_acceleration: bool = False
    tls_inspection: bool = False
    connection_tracking: bool = True
    per_core_processing: bool = False
    fail_mode: str = "open"              # "open" | "close"


@dataclass(frozen=True)
class EventBusFlags:
    enabled: bool = False
    backend: str = "memory"              # "nats" | "kafka" | "memory"
    nats_url: str = "nats://localhost:4222"
    reconnect_wait_s: int = 2
    max_reconnect: int = 60
    publish_timeout_s: float = 1.0


@dataclass(frozen=True)
class AIEngineFlags:
    enabled: bool = True
    mode: str = "async"                  # "inline" | "async" | "disabled"
    model_version: str = "v1.0.0"
    inline_blocking: bool = False
    fallback_on_failure: bool = True
    inference_timeout_ms: int = 5000
    confidence_threshold: float = 0.85


@dataclass(frozen=True)
class ObservabilityFlags:
    enabled: bool = True
    metrics: bool = True
    logs: bool = True
    tracing: bool = False
    log_level: str = "INFO"
    metrics_port: int = 9090
    otlp_endpoint: str = "http://localhost:4317"


@dataclass(frozen=True)
class ThreatIntelFlags:
    enabled: bool = False
    refresh_interval_minutes: int = 15
    block_threshold: float = 0.85


@dataclass(frozen=True)
class PluginFlags:
    enabled: bool = True
    sandbox: str = "restricted_python"   # "wasm" | "restricted_python" | "none"
    hot_reload: bool = True
    plugin_dir: str = "plugins/"
    max_execution_ms: int = 100


@dataclass(frozen=True)
class HAFlags:
    enabled: bool = False
    mode: str = "active-passive"
    etcd_endpoints: tuple = ("localhost:2379",)


@dataclass(frozen=True)
class SecurityFlags:
    mtls_internal: bool = False
    rate_limiting: bool = True
    rate_limit_per_ip: int = 100
    ddos_protection: bool = True


@dataclass(frozen=True)
class OptimizerFlags:
    enabled: bool = True
    auto_apply: bool = False
    unused_threshold_days: int = 30


@dataclass(frozen=True)
class FeatureFlags:
    """
    Immutable snapshot of all feature flags at a point in time.
    Re-created on hot-reload — old references remain valid during the swap.
    """
    data_plane: DataPlaneFlags = DataPlaneFlags()
    event_bus: EventBusFlags = EventBusFlags()
    ai_engine: AIEngineFlags = AIEngineFlags()
    observability: ObservabilityFlags = ObservabilityFlags()
    threat_intel: ThreatIntelFlags = ThreatIntelFlags()
    plugins: PluginFlags = PluginFlags()
    ha: HAFlags = HAFlags()
    security: SecurityFlags = SecurityFlags()
    optimizer: OptimizerFlags = OptimizerFlags()


# ─────────────────────────────────────────────────────────────────────
# Feature Flag Manager — Singleton with hot-reload
# ─────────────────────────────────────────────────────────────────────

class FeatureFlagManager:
    """
    Thread-safe, hot-reloadable feature flag manager.

    Reads `system/config/features.yaml` on startup and watches for changes.
    All reads are O(1) attribute access — no I/O on the hot path.

    Usage:
        flags = FeatureFlagManager.instance()
        if flags.current.ai_engine.enabled:
            ...
        if flags.is_ai_inline():
            ...
    """

    _instance: Optional["FeatureFlagManager"] = None
    _lock = threading.RLock()

    def __init__(self, config_path: Optional[Path] = None):
        self._path = config_path or (
            Path(__file__).parent / "features.yaml"
        )
        self._flags: FeatureFlags = self._load()
        self._rw_lock = threading.RLock()
        self._reload_callbacks: list = []

        # Background watcher thread
        self._watcher = threading.Thread(
            target=self._watch_loop,
            name="FeatureFlag-Watcher",
            daemon=True,
        )
        self._watcher.start()
        logger.info(f"[FeatureFlags] Loaded from {self._path}")

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "FeatureFlagManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    @property
    def current(self) -> FeatureFlags:
        """Return the current immutable flags snapshot. Thread-safe."""
        with self._rw_lock:
            return self._flags

    def is_enabled(self, dot_path: str) -> bool:
        """
        Convenient dot-path access.
        Example: flags.is_enabled("ai_engine.inline_blocking")
        """
        try:
            parts = dot_path.split(".")
            obj = self._flags
            for part in parts:
                obj = getattr(obj, part)
            return bool(obj)
        except AttributeError:
            logger.warning(f"[FeatureFlags] Unknown flag: {dot_path}")
            return False

    def on_reload(self, callback) -> None:
        """Register a callback to be called when flags are hot-reloaded."""
        self._reload_callbacks.append(callback)

    def force_reload(self) -> FeatureFlags:
        """Force immediate reload from disk (for API endpoint use)."""
        return self._do_reload()

    # ── Convenience Helpers ────────────────────────────────────────

    def is_event_bus_active(self) -> bool:
        return self.current.event_bus.enabled

    def is_ai_inline(self) -> bool:
        ai = self.current.ai_engine
        return ai.enabled and ai.mode == "inline"

    def is_ai_async(self) -> bool:
        ai = self.current.ai_engine
        return ai.enabled and ai.mode == "async"

    def is_ai_disabled(self) -> bool:
        ai = self.current.ai_engine
        return not ai.enabled or ai.mode == "disabled"

    def fail_open(self) -> bool:
        return self.current.data_plane.fail_mode == "open"

    # ── Internal ───────────────────────────────────────────────────

    def _load(self) -> FeatureFlags:
        """Parse features.yaml and build a FeatureFlags snapshot."""
        try:
            raw = yaml.safe_load(self._path.read_text(encoding="utf-8"))
            f = raw.get("features", {})

            dp = f.get("data_plane", {})
            eb = f.get("event_bus", {})
            ai = f.get("ai_engine", {})
            obs = f.get("observability", {})
            ti = f.get("threat_intel", {})
            pl = f.get("plugins", {})
            ha = f.get("ha", {})
            sec = f.get("security", {})
            opt = f.get("optimizer", {})

            return FeatureFlags(
                data_plane=DataPlaneFlags(
                    enabled=dp.get("enabled", True),
                    ebpf_acceleration=dp.get("ebpf_acceleration", False),
                    tls_inspection=dp.get("tls_inspection", False),
                    connection_tracking=dp.get("connection_tracking", True),
                    per_core_processing=dp.get("per_core_processing", False),
                    fail_mode=dp.get("fail_mode", "open"),
                ),
                event_bus=EventBusFlags(
                    enabled=eb.get("enabled", False),
                    backend=eb.get("backend", "memory"),
                    nats_url=eb.get("nats_url", "nats://localhost:4222"),
                    reconnect_wait_s=eb.get("reconnect_wait_s", 2),
                    max_reconnect=eb.get("max_reconnect", 60),
                    publish_timeout_s=eb.get("publish_timeout_s", 1.0),
                ),
                ai_engine=AIEngineFlags(
                    enabled=ai.get("enabled", True),
                    mode=ai.get("mode", "async"),
                    model_version=ai.get("model_version", "v1.0.0"),
                    inline_blocking=ai.get("inline_blocking", False),
                    fallback_on_failure=ai.get("fallback_on_failure", True),
                    inference_timeout_ms=ai.get("inference_timeout_ms", 5000),
                    confidence_threshold=ai.get("confidence_threshold", 0.85),
                ),
                observability=ObservabilityFlags(
                    enabled=obs.get("enabled", True),
                    metrics=obs.get("metrics", True),
                    logs=obs.get("logs", True),
                    tracing=obs.get("tracing", False),
                    log_level=obs.get("log_level", "INFO"),
                    metrics_port=obs.get("metrics_port", 9090),
                    otlp_endpoint=obs.get("otlp_endpoint", "http://localhost:4317"),
                ),
                threat_intel=ThreatIntelFlags(
                    enabled=ti.get("enabled", False),
                    refresh_interval_minutes=ti.get("refresh_interval_minutes", 15),
                    block_threshold=ti.get("block_threshold", 0.85),
                ),
                plugins=PluginFlags(
                    enabled=pl.get("enabled", True),
                    sandbox=pl.get("sandbox", "restricted_python"),
                    hot_reload=pl.get("hot_reload", True),
                    plugin_dir=pl.get("plugin_dir", "plugins/"),
                    max_execution_ms=pl.get("max_execution_ms", 100),
                ),
                ha=HAFlags(
                    enabled=ha.get("enabled", False),
                    mode=ha.get("mode", "active-passive"),
                    etcd_endpoints=tuple(ha.get("etcd_endpoints", ["localhost:2379"])),
                ),
                security=SecurityFlags(
                    mtls_internal=sec.get("mtls_internal", False),
                    rate_limiting=sec.get("rate_limiting", True),
                    rate_limit_per_ip=sec.get("rate_limit_per_ip", 100),
                    ddos_protection=sec.get("ddos_protection", True),
                ),
                optimizer=OptimizerFlags(
                    enabled=opt.get("enabled", True),
                    auto_apply=opt.get("auto_apply", False),
                    unused_threshold_days=opt.get("unused_threshold_days", 30),
                ),
            )
        except Exception as exc:
            logger.error(f"[FeatureFlags] Failed to load {self._path}: {exc}")
            return FeatureFlags()   # safe defaults

    def _do_reload(self) -> FeatureFlags:
        new_flags = self._load()
        with self._rw_lock:
            self._flags = new_flags
        logger.info("[FeatureFlags] Hot-reloaded ✓")
        for cb in self._reload_callbacks:
            try:
                cb(new_flags)
            except Exception as e:
                logger.warning(f"[FeatureFlags] Reload callback error: {e}")
        return new_flags

    def _watch_loop(self):
        """Background thread: reload when features.yaml mtime changes."""
        last_mtime: float = 0.0
        try:
            last_mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            pass

        while True:
            time.sleep(5)
            try:
                mtime = self._path.stat().st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    self._do_reload()
            except FileNotFoundError:
                pass
            except Exception as exc:
                logger.error(f"[FeatureFlags] Watcher error: {exc}")
