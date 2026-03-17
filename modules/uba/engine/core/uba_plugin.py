"""
Enterprise NGFW — UBA Inspector Plugin

Bridges the NGFW inspection pipeline to the UBA behavioral engine.
Extracts user identity from the InspectionContext metadata and calls
the UserProfiler to analyze behavior in real time.

Key design decisions:
- Plugin runs on TCP traffic only (port selection configurable via UBAConfig)
- User identity expected in context.metadata["username"] — populated by
  auth-session tracking middleware or LDAP/AD correlation
- Result is "ALLOW" normally; "BLOCK" only in enforce+critical mode
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from system.inspection_core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionResult,
    InspectionFinding, InspectionAction, PluginPriority,
)
from modules.uba.engine.core.user_profiler import UserProfiler

logger = logging.getLogger(__name__)


class UBAPlugin(InspectorPlugin):
    """
    Real-time User Behavior Analytics plugin.

    Registers as priority LOWEST so it runs after all other inspectors
    (it only contributes an additional behavioral risk signal, not a
    hard firewall rule — unless mode='enforce').
    """

    PLUGIN_NAME = "uba"

    def __init__(
        self,
        db_manager=None,
        config=None,         # UBAConfig DB row
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.LOWEST,
            logger=logger or logging.getLogger(__name__),
        )
        self.profiler = UserProfiler(db_manager=db_manager, config=config)
        self.config = config
        self._mode = getattr(config, 'mode', 'monitor') if config else 'monitor'

    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Inspect any TCP traffic that carries an identified username.
        Without a username there is nothing to profile.
        """
        username = (context.metadata or {}).get("username")
        return bool(username) and context.protocol in ("TCP", "UDP", "HTTP", "SMTP")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes,
    ) -> InspectionResult:
        """Run UBA pipeline and return InspectionResult."""
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        meta = context.metadata or {}
        username        = meta.get("username", "")
        peer_group      = meta.get("peer_group", "")
        bytes_xfer      = float(meta.get("bytes_transferred", len(data)))
        session_dur     = float(meta.get("session_duration", 0.0))

        if not username:
            return result

        try:
            analysis = self.profiler.analyze(
                username=username,
                source_ip=context.src_ip,
                target_service=f"{context.protocol}:{context.dst_port}",
                bytes_transferred=bytes_xfer,
                session_duration=session_dur,
                event_time=context.timestamp,
                peer_group=peer_group,
            )

            # Populate findings if anomalies detected
            if analysis.detectors_triggered:
                for flag in analysis.detectors_triggered:
                    severity = self._flag_severity(analysis.risk_level)
                    result.findings.append(InspectionFinding(
                        plugin_name=self.name,
                        severity=severity,
                        category="UBA",
                        description=flag,
                        confidence=analysis.anomaly_score,
                        recommends_block=(analysis.action == "block"),
                        metadata={
                            "risk_level":  analysis.risk_level,
                            "risk_score":  analysis.risk_score,
                            "username":    username,
                        },
                    ))

            # Take action based on mode + risk
            if analysis.action == "block":
                result.action = InspectionAction.BLOCK
            elif analysis.action == "alert" and analysis.risk_level in ("high", "critical"):
                result.action = InspectionAction.LOG_ONLY

            result.metadata["uba"] = {
                "username":   username,
                "risk_score": analysis.risk_score,
                "risk_level": analysis.risk_level,
                "anomaly_score": analysis.anomaly_score,
            }

        except Exception as exc:
            self.logger.error("UBAPlugin inspection error: %s", exc, exc_info=True)

        result.processing_time_ms = (time.time() - start) * 1000
        return result

    @staticmethod
    def _flag_severity(risk_level: str) -> str:
        return {
            "critical": "CRITICAL",
            "high":     "HIGH",
            "medium":   "MEDIUM",
            "low":      "INFO",
        }.get(risk_level, "INFO")
