"""
Enterprise CyberNexus — QoS Inspector Plugin

Lightweight InspectorPlugin that integrates the QoSManager into the
inspection pipeline. Runs at LOWEST priority (after all security checks)
to apply bandwidth shaping without blocking security decisions.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from system.inspection_core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionResult,
    InspectionFinding, InspectionAction, PluginPriority,
)

logger = logging.getLogger(__name__)


class QoSPlugin(InspectorPlugin):
    """
    Quality of Service bandwidth-enforcement plugin.

    In 'monitor' mode: logs throttle decisions but always allows traffic.
    In 'enforce' mode: drops packets that exceed the configured rate limit.
    """

    PLUGIN_NAME = "qos"

    def __init__(
        self,
        db_manager=None,
        config=None,         # QoSConfig DB row
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.LOWEST,
            logger=logger or logging.getLogger(__name__),
        )
        self._mode = "monitor"
        self._qos_manager = None

        try:
            from modules.qos.qos_manager import QoSManager
            cfg_dict = {}
            if config:
                cfg_dict = {
                    "enabled":                config.enabled,
                    "default_user_rate_bytes": config.default_user_rate_bytes,
                    "default_user_burst_bytes":config.default_user_burst_bytes,
                }
            self._qos_manager = QoSManager(config=cfg_dict)
            if config:
                self._mode = getattr(config, 'mode', 'monitor')
            self.logger.info("QoSPlugin initialized (mode=%s)", self._mode)
        except Exception as exc:
            self.logger.warning("QoSPlugin: QoSManager init failed: %s", exc)

    def can_inspect(self, context: InspectionContext) -> bool:
        return context.protocol in ("TCP", "UDP")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes,
    ) -> InspectionResult:
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        if self._qos_manager is None or not self._qos_manager.enabled:
            return result

        payload_size = len(data)
        src_ip = context.src_ip or "0.0.0.0"

        # Use synchronous bucket check (RateLimiterEngine from engine/rate_limiter.py)
        from modules.qos.engine.rate_limiter import RateLimiterEngine
        if not hasattr(self, '_rate_engine'):
            self._rate_engine = RateLimiterEngine()
            self._rate_engine.default_fill_rate = self._qos_manager.default_per_ip_rate
            self._rate_engine.default_capacity  = self._qos_manager.default_per_ip_burst

        allowed = self._rate_engine.check_traffic(src_ip, payload_size)

        if not allowed:
            finding = InspectionFinding(
                plugin_name=self.name,
                severity="INFO",
                category="QoS",
                description=f"Rate limited: {src_ip} exceeded bandwidth ({payload_size} bytes)",
                confidence=1.0,
                recommends_block=(self._mode == "enforce"),
                metadata={"src_ip": src_ip, "payload_bytes": payload_size},
            )
            result.findings.append(finding)

            if self._mode == "enforce":
                result.action = InspectionAction.BLOCK

        result.processing_time_ms = (time.time() - start) * 1000
        return result
