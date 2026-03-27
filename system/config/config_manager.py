"""
CyberNexus NGFW — Config Manager v2
=====================================
Versioned, hot-reloadable configuration with rollback support.

Priority (highest → lowest):
  1. Environment variables
  2. features.yaml / base.yaml (watched, hot-reload)
  3. Defaults

Features:
  ✅ Hot reload on file change (no restart)
  ✅ Versioned snapshots (rollback)
  ✅ JSON diff between versions
  ✅ API endpoints: /config/versions, /config/diff, /config/rollback

Usage:
    cfg = ConfigManager.instance()
    val = cfg.get("firewall.default_action", default="BLOCK")
    snapshot_id = cfg.snapshot()
    await cfg.rollback(snapshot_id)
"""

import copy
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Config Snapshot
# ──────────────────────────────────────────────────────────────────────

class ConfigSnapshot:
    def __init__(self, version_id: str, data: dict, source: str = "auto"):
        self.version_id  = version_id
        self.data        = copy.deepcopy(data)
        self.created_at  = datetime.now(timezone.utc).isoformat()
        self.source      = source    # "auto" | "api" | "cli"

    def to_dict(self) -> dict:
        return {
            "version_id":  self.version_id,
            "created_at":  self.created_at,
            "source":      self.source,
        }


# ──────────────────────────────────────────────────────────────────────
# Config Manager
# ──────────────────────────────────────────────────────────────────────

class ConfigManager:
    """
    Singleton versioned config manager.

    Merges:
      - ENV variables (prefix NGFW_)
      - base.yaml
      - features.yaml

    Thread-safe for concurrent read-heavy workloads.
    Snapshots stored in-memory (last 50 versions).
    """

    _instance: Optional["ConfigManager"] = None
    _lock = threading.RLock()
    MAX_SNAPSHOTS = 50

    def __init__(self, config_dir: Optional[Path] = None):
        self._dir = config_dir or Path(__file__).parent
        self._data: dict = {}
        self._snapshots: List[ConfigSnapshot] = []
        self._rw_lock = threading.RLock()
        self._version_counter = 0
        self._reload_callbacks: list = []

        self._load_and_merge()

        # File watcher
        self._watcher = threading.Thread(
            target=self._watch_loop,
            name="ConfigManager-Watcher",
            daemon=True,
        )
        self._watcher.start()
        logger.info("[ConfigManager] Started ✓")

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "ConfigManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    def get(self, dot_path: str, default: Any = None) -> Any:
        """
        Read a config value by dot-notation path.
        Example: cfg.get("firewall.rules.default_action", "BLOCK")
        """
        with self._rw_lock:
            obj = self._data
            for key in dot_path.split("."):
                if not isinstance(obj, dict) or key not in obj:
                    return default
                obj = obj[key]
            return obj

    def get_all(self) -> dict:
        with self._rw_lock:
            return copy.deepcopy(self._data)

    def snapshot(self, source: str = "api") -> str:
        """Take a named snapshot of the current config. Returns version_id."""
        with self._rw_lock:
            snap = self._make_snapshot(source)
        logger.info(f"[ConfigManager] Snapshot created: {snap.version_id}")
        return snap.version_id

    def rollback(self, version_id: str) -> bool:
        """
        Restore config to a previous snapshot.
        Returns True on success, False if version not found.
        """
        with self._rw_lock:
            target = next((s for s in self._snapshots if s.version_id == version_id), None)
            if target is None:
                logger.warning(f"[ConfigManager] Snapshot not found: {version_id}")
                return False

            # Take a snapshot of current before rollback
            self._make_snapshot("pre-rollback")
            self._data = copy.deepcopy(target.data)
            logger.info(f"[ConfigManager] Rolled back to: {version_id}")
            self._notify_callbacks()
            return True

    def list_snapshots(self) -> List[dict]:
        with self._rw_lock:
            return [s.to_dict() for s in reversed(self._snapshots)]

    def diff(self, version_id_a: str, version_id_b: str) -> dict:
        """Compare two snapshots and return a human-readable diff."""
        with self._rw_lock:
            snap_a = next((s for s in self._snapshots if s.version_id == version_id_a), None)
            snap_b = next((s for s in self._snapshots if s.version_id == version_id_b), None)

        if not snap_a or not snap_b:
            return {"error": "One or both versions not found"}

        return self._compute_diff(snap_a.data, snap_b.data)

    def force_reload(self) -> dict:
        """Force immediate reload from disk (for API endpoint use)."""
        old = copy.deepcopy(self._data)
        self._load_and_merge()
        diff = self._compute_diff(old, self._data)
        logger.info(f"[ConfigManager] Force-reloaded. Changes: {list(diff.keys())}")
        return diff

    def on_reload(self, callback) -> None:
        self._reload_callbacks.append(callback)

    # ── Internal ───────────────────────────────────────────────────

    def _load_and_merge(self) -> None:
        """Merge all config sources in priority order."""
        merged: dict = {}

        # 1. Load base.yaml (lowest priority file)
        base_path = self._dir / "base.yaml"
        if base_path.exists():
            try:
                with open(base_path, encoding="utf-8") as f:
                    base = yaml.safe_load(f) or {}
                merged = self._deep_merge(merged, base)
            except Exception as exc:
                logger.error(f"[ConfigManager] Failed to load base.yaml: {exc}")

        # 2. Load features.yaml
        features_path = self._dir / "features.yaml"
        if features_path.exists():
            try:
                with open(features_path, encoding="utf-8") as f:
                    features = yaml.safe_load(f) or {}
                merged = self._deep_merge(merged, features)
            except Exception as exc:
                logger.error(f"[ConfigManager] Failed to load features.yaml: {exc}")

        # 3. Override with ENV variables (NGFW_ prefix)
        for key, value in os.environ.items():
            if key.startswith("NGFW_"):
                dot_key = key[5:].lower().replace("__", ".")
                self._set_nested(merged, dot_key, value)

        with self._rw_lock:
            self._data = merged
            self._make_snapshot("auto-load")

        self._notify_callbacks()

    def _make_snapshot(self, source: str = "auto") -> ConfigSnapshot:
        self._version_counter += 1
        snap = ConfigSnapshot(
            version_id=f"v{self._version_counter}",
            data=self._data,
            source=source,
        )
        self._snapshots.append(snap)
        # Keep only last MAX_SNAPSHOTS
        if len(self._snapshots) > self.MAX_SNAPSHOTS:
            self._snapshots = self._snapshots[-self.MAX_SNAPSHOTS:]
        return snap

    def _watch_loop(self) -> None:
        watch_files = [
            self._dir / "base.yaml",
            self._dir / "features.yaml",
        ]
        last_mtimes: Dict[Path, float] = {}
        for f in watch_files:
            try:
                last_mtimes[f] = f.stat().st_mtime
            except FileNotFoundError:
                last_mtimes[f] = 0.0

        while True:
            time.sleep(5)
            changed = False
            for f in watch_files:
                try:
                    mtime = f.stat().st_mtime
                    if mtime != last_mtimes[f]:
                        last_mtimes[f] = mtime
                        changed = True
                        logger.info(f"[ConfigManager] Detected change in {f.name}")
                except FileNotFoundError:
                    pass

            if changed:
                self._load_and_merge()
                logger.info("[ConfigManager] Hot-reloaded ✓")

    def _notify_callbacks(self) -> None:
        for cb in self._reload_callbacks:
            try:
                cb(self._data)
            except Exception as exc:
                logger.warning(f"[ConfigManager] Callback error: {exc}")

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    @staticmethod
    def _set_nested(d: dict, dot_key: str, value: str) -> None:
        keys = dot_key.split(".")
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value

    @staticmethod
    def _compute_diff(a: dict, b: dict, prefix: str = "") -> dict:
        diff: dict = {}
        all_keys = set(a.keys()) | set(b.keys())
        for key in all_keys:
            full_key = f"{prefix}.{key}" if prefix else key
            va, vb = a.get(key), b.get(key)
            if isinstance(va, dict) and isinstance(vb, dict):
                nested = ConfigManager._compute_diff(va, vb, full_key)
                diff.update(nested)
            elif va != vb:
                diff[full_key] = {"before": va, "after": vb}
        return diff
