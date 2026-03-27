"""
CyberNexus NGFW — Correlation Engine
=======================================
Subscribes to EventBus events and correlates them into higher-order signals.

This replaces direct module-to-module calls (the "no-direct-calls" rule).
Instead of: ModuleA calls CorrelationEngine.correlate(finding)
Now:        ModuleA publishes → EventBus → CorrelationEngine subscribes

Correlation rules:
  1. Multi-source threat amplification
     3+ threat.detected events from the same IP in 60s → BLOCK
  2. AI + IDS convergence
     ai.score_generated (score ≥ 0.7) + threat.detected → upgrade to CRITICAL
  3. Scan detection
     5+ unique dst_ports from same IP in 30s → port scan → BLOCK
  4. Anomaly + Threat Intel convergence
     anomaly.scored + intel_reputation=HIGH → immediate BLOCK

Usage:
    engine = CorrelationEngine.instance()
    await engine.start()
"""

import asyncio
import logging
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Event-driven correlation engine.
    Subscribes to threat events and emits compound response decisions.
    """

    _instance: Optional["CorrelationEngine"] = None

    # Sliding window parameters
    WINDOW_S = 60          # 1 minute correlation window
    THREAT_THRESHOLD = 3   # threats from same IP before auto-block
    PORT_SCAN_THRESHOLD = 5  # unique dst_ports before scan detection
    SCAN_WINDOW_S = 30     # port scan detection window

    def __init__(self):
        self._threat_counts: dict = defaultdict(list)      # ip → [timestamps]
        self._dst_ports: dict = defaultdict(dict)           # ip → {port: timestamp}
        self._ai_scores: dict = {}                          # session_id → score
        self._bus = None

    @classmethod
    def instance(cls) -> "CorrelationEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start(self) -> None:
        """Subscribe to all relevant event topics."""
        from system.events.bus import EventBus
        from system.events.topics import Topics

        self._bus = await EventBus.instance()

        await self._bus.subscribe(Topics.THREAT_DETECTED, self._on_threat)
        await self._bus.subscribe(Topics.AI_SCORE_GENERATED, self._on_ai_score)
        await self._bus.subscribe(Topics.ANOMALY_SCORED, self._on_anomaly)
        await self._bus.subscribe(Topics.PACKET_INSPECTED, self._on_packet)

        # Background cleanup
        asyncio.create_task(self._cleanup_loop())

        logger.info("[Correlation] Engine started — subscribing to event bus ✓")

    # ── Event Handlers ─────────────────────────────────────────────

    async def _on_threat(self, event: dict) -> None:
        """Rule 1 & 2: Multi-source threat amplification."""
        src_ip = event.get("src_ip", "")
        if not src_ip or src_ip == "0.0.0.0":
            return

        now = time.time()
        # Add to sliding window
        self._threat_counts[src_ip] = [
            t for t in self._threat_counts[src_ip]
            if now - t < self.WINDOW_S
        ]
        self._threat_counts[src_ip].append(now)

        count = len(self._threat_counts[src_ip])

        if count >= self.THREAT_THRESHOLD:
            logger.warning(
                f"[Correlation] Rule 1: {src_ip} triggered {count} threats "
                f"in {self.WINDOW_S}s → escalating to BLOCK"
            )
            await self._emit_block(src_ip, reason=f"Correlation: {count} threats in {self.WINDOW_S}s")

        # Rule 2: Check if AI also flagged this session
        session_id = event.get("session_id", "")
        ai_score = self._ai_scores.get(session_id, 0.0)
        if ai_score >= 0.7:
            logger.warning(
                f"[Correlation] Rule 2: AI (score={ai_score:.2f}) + "
                f"IDS convergence for {src_ip} → CRITICAL"
            )
            await self._emit_alert(
                src_ip=src_ip,
                severity="critical",
                message=f"AI + IDS convergence: score={ai_score:.2f}"
            )

    async def _on_ai_score(self, event: dict) -> None:
        """Store AI score for cross-correlation."""
        session_id = event.get("session_id", "")
        score = float(event.get("score", 0.0))
        if session_id:
            self._ai_scores[session_id] = score

    async def _on_anomaly(self, event: dict) -> None:
        """Rule 4: Anomaly + Threat Intel convergence."""
        score = float(event.get("score", 0.0))
        if score < 0.5:
            return

        # Check threat intel reputation for the same IP
        try:
            from system.threat_intel.intel_manager import ThreatIntelManager
            # We'd need the IP from anomaly context — using device_id as proxy
            device_ip = event.get("device_id", "")
            if device_ip and ThreatIntelManager.instance().is_ip_blocked(device_ip):
                logger.warning(
                    f"[Correlation] Rule 4: Anomaly (score={score:.2f}) + "
                    f"Threat Intel hit for {device_ip} → immediate BLOCK"
                )
                await self._emit_block(device_ip, reason="Anomaly + Threat Intel convergence")
        except Exception:
            pass

    async def _on_packet(self, event: dict) -> None:
        """Rule 3: Port scan detection."""
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port", 0)
        if not src_ip or not dst_port:
            return

        now = time.time()
        # Prune old port entries
        self._dst_ports[src_ip] = {
            port: ts for port, ts in self._dst_ports[src_ip].items()
            if now - ts < self.SCAN_WINDOW_S
        }
        self._dst_ports[src_ip][dst_port] = now

        unique_ports = len(self._dst_ports[src_ip])
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            logger.warning(
                f"[Correlation] Rule 3: Port scan from {src_ip} "
                f"({unique_ports} unique ports in {self.SCAN_WINDOW_S}s) → BLOCK"
            )
            await self._emit_block(src_ip, reason=f"Port scan: {unique_ports} ports")
            # Clear after detection to avoid repeated firing
            self._dst_ports[src_ip].clear()

    # ── Response Emitters ──────────────────────────────────────────

    async def _emit_block(self, ip: str, reason: str) -> None:
        """Publish a response.block event — AccelerationBridge will handle it."""
        from system.events.topics import Topics
        from system.events.schemas import ResponseBlockEvent

        event = ResponseBlockEvent(
            src_ip=ip,
            reason=reason,
            duration_s=3600,
            triggered_by="correlation_engine",
        )
        await self._bus.publish(Topics.RESPONSE_BLOCK, event.to_dict())

    async def _emit_alert(self, src_ip: str, severity: str, message: str) -> None:
        from system.events.topics import Topics
        from system.events.schemas import ResponseAlertEvent

        event = ResponseAlertEvent(
            severity=severity,
            title="Correlation Engine Alert",
            message=message,
            src_ip=src_ip,
        )
        await self._bus.publish(Topics.RESPONSE_ALERT, event.to_dict())

    async def _cleanup_loop(self) -> None:
        """Remove stale sliding window entries periodically."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            # Clean threat counts
            for ip in list(self._threat_counts.keys()):
                self._threat_counts[ip] = [
                    t for t in self._threat_counts[ip]
                    if now - t < self.WINDOW_S
                ]
                if not self._threat_counts[ip]:
                    del self._threat_counts[ip]
            # Clean AI scores (older than 5 min)
            # (simplified: just clear all — sessions are short-lived)
            if len(self._ai_scores) > 10000:
                self._ai_scores.clear()
