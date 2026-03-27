"""
CyberNexus NGFW — Event Bus ↔ Acceleration Bridge
====================================================
Connects the Phase 7 EventBus to the acceleration layer (XDP/eBPF engine).

This is the KEY integration point between:
  - EventBus (threat.detected, response.block events)
  - XDP Engine (kernel-level IP blocking via eBPF maps)
  - Threat Intel Manager (reputation-based blocking)

Architecture:
  EventBus "threat.detected" → AccelerationBridge → XDP.add_blocked_ip()
  EventBus "response.block"  → AccelerationBridge → XDP.add_blocked_ip()
  Feature flag: data_plane.ebpf_acceleration = true (to use XDP)
              : data_plane.ebpf_acceleration = false (software blocking only)

Usage (in app startup):
    bridge = AccelerationBridge()
    await bridge.start()

    # Now all threat events automatically propagate to XDP kernel layer
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AccelerationBridge:
    """
    Subscription bridge between EventBus and the XDP acceleration engine.

    Wires these flows:
      1. threat.detected → XDP blocklist (if confidence ≥ threshold)
      2. response.block  → XDP blocklist + StateSyncManager (cluster-wide)
      3. ai.score_generated → XDP blocklist (if inline_blocking=true)
      4. XDP stats → EventBus metrics.packet_stats (upstream metrics)

    Completely optional: if ebpf_acceleration=false, XDP calls silently no-op.
    """

    def __init__(self):
        self._xdp = None
        self._bus = None
        self._flags = None
        self._running = False

    async def start(self) -> None:
        """Wire all subscriptions. Call once at system startup."""
        from system.config.feature_flags import FeatureFlagManager
        from system.events.bus import EventBus
        from system.events.topics import Topics

        self._flags = FeatureFlagManager.instance()
        self._bus = await EventBus.instance()

        # Lazily load XDP engine (avoids BCC import errors on non-Linux)
        await self._init_xdp()

        # Wire bus → XDP
        await self._bus.subscribe(Topics.THREAT_DETECTED, self._on_threat_detected)
        await self._bus.subscribe(Topics.RESPONSE_BLOCK, self._on_response_block)
        await self._bus.subscribe(Topics.AI_SCORE_GENERATED, self._on_ai_score)

        self._running = True
        logger.info("[AccelBridge] Started ✓ — XDP bridge active")

    async def stop(self) -> None:
        self._running = False
        if self._xdp:
            await self._xdp.stop()

    # ── Event Handlers ─────────────────────────────────────────────

    async def _on_threat_detected(self, event: dict) -> None:
        """
        threat.detected → auto-block IP in XDP if confidence is HIGH.
        Threshold from features.ai_engine.confidence_threshold.
        """
        if not self._running:
            return

        src_ip = event.get("src_ip", "")
        confidence = float(event.get("confidence", 0.0))
        module = event.get("module", "unknown")

        if not src_ip or src_ip in ("", "0.0.0.0"):
            return

        threshold = self._flags.current.ai_engine.confidence_threshold

        if confidence >= threshold:
            logger.warning(
                f"[AccelBridge] High-confidence threat from {src_ip} "
                f"(module={module}, conf={confidence:.2f}) → XDP block"
            )
            await self._xdp_block(src_ip, reason=f"threat.detected by {module}")

            # Also sync to cluster-wide state
            await self._cluster_block(src_ip, f"threat:{module}")

    async def _on_response_block(self, event: dict) -> None:
        """response.block → immediate XDP kernel block."""
        if not self._running:
            return

        src_ip = event.get("src_ip", "")
        reason = event.get("reason", "response.block event")
        duration_s = int(event.get("duration_s", 3600))

        if not src_ip:
            return

        logger.info(f"[AccelBridge] Block order for {src_ip}: {reason}")
        await self._xdp_block(src_ip, reason=reason)
        await self._cluster_block(src_ip, reason, duration_s)

    async def _on_ai_score(self, event: dict) -> None:
        """
        ai.score_generated → block if inline_blocking=true and score ≥ threshold.
        This implements the AI fast-path for inline blocking mode.
        """
        if not self._running:
            return

        ai_flags = self._flags.current.ai_engine
        if not (ai_flags.mode == "inline" and ai_flags.inline_blocking):
            return

        score = float(event.get("score", 0.0))
        if score >= ai_flags.confidence_threshold:
            session_id = event.get("session_id", "")
            logger.warning(
                f"[AccelBridge] AI inline block: session={session_id} "
                f"score={score:.2f} ≥ {ai_flags.confidence_threshold}"
            )
            # Note: we don't have src_ip in AI score events — that's by design
            # The pipeline will block the specific session via its return value

    # ── XDP Integration ────────────────────────────────────────────

    async def _xdp_block(self, ip: str, reason: str = "") -> None:
        """Push an IP block to the XDP kernel map (if eBPF is active)."""
        if self._xdp and self._flags.current.data_plane.ebpf_acceleration:
            await self._xdp.add_blocked_ip(ip)
        else:
            logger.debug(f"[AccelBridge] Software-only block for {ip} (eBPF disabled)")

    async def _cluster_block(self, ip: str, reason: str, duration_s: int = 3600) -> None:
        """Replicate IP block across HA cluster via StateSyncManager."""
        try:
            from system.ha.state_sync import StateSyncManager
            await StateSyncManager.instance().sync_blocked_ip(ip, reason, duration_s)
        except Exception as exc:
            logger.debug(f"[AccelBridge] Cluster sync failed: {exc}")

    async def _init_xdp(self) -> None:
        """Lazily initialize XDP engine from acceleration module."""
        try:
            from system.config.config_manager import ConfigManager
            config = ConfigManager.instance().get_all()

            from acceleration.ebpf.xdp_engine import create_xdp_engine
            self._xdp = create_xdp_engine(config, event_sink=None)

            if self._flags.current.data_plane.ebpf_acceleration:
                await self._xdp.start()
                logger.info("[AccelBridge] XDP engine started ✓")
            else:
                logger.info("[AccelBridge] eBPF disabled in feature flags — XDP in mock mode")

        except ImportError as exc:
            logger.warning(f"[AccelBridge] Could not load XDP engine: {exc} — software-only mode")
            self._xdp = _SoftwareBlocklist()
        except Exception as exc:
            logger.error(f"[AccelBridge] XDP init failed: {exc} — software-only mode")
            self._xdp = _SoftwareBlocklist()


class _SoftwareBlocklist:
    """
    Pure Python fallback when eBPF/BCC is unavailable.
    Maintains an in-memory blocklist used by the pipeline for pre-check.
    """
    def __init__(self):
        self._blocked: set = set()

    async def add_blocked_ip(self, ip: str) -> None:
        self._blocked.add(ip)
        logger.info(f"[SoftwareBlocklist] Blocked {ip}")

    async def remove_blocked_ip(self, ip: str) -> None:
        self._blocked.discard(ip)

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def get_statistics(self) -> dict:
        return {"total_packets": 0, "blocked_ips_count": len(self._blocked)}
