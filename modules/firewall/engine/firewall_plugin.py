"""
Enterprise NGFW — Firewall Inspector Plugin

Bridges the NGFW inspection pipeline to the full firewall policy engine:
  UnifiedEvaluator (GeoIP → ACL → App Control) + StateTracker

Priority: HIGHEST — the firewall is the first line of defence.
ESTABLISHED connections bypass the evaluator for performance.
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


class FirewallPlugin(InspectorPlugin):
    """
    Stateful Next-Gen Firewall plugin.

    Pipeline per packet:
    1. StateTracker — ESTABLISHED connections are allowed instantly.
    2. UnifiedEvaluator — GeoIP → ACL (L3/4) → AppControl (L7).
    3. StateTracker update — record new ALLOW'd connections.
    """

    PLUGIN_NAME = "firewall"

    def __init__(
        self,
        db_manager=None,
        config=None,
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.HIGHEST,
            logger=logger or logging.getLogger(__name__),
        )
        self.db_manager = db_manager
        self._state_tracker = None
        self._evaluator = None

        try:
            from modules.firewall.engine.state_tracker import StateTracker
            self._state_tracker = StateTracker(timeout_seconds=300)
            self.logger.info("FirewallPlugin: StateTracker initialized")
        except Exception as exc:
            self.logger.warning("FirewallPlugin: StateTracker init failed: %s", exc)

        # UnifiedEvaluator needs a DB session — lazy-initialized on first inspect()
        self._db_session = None

    def can_inspect(self, context: InspectionContext) -> bool:
        return context.protocol in ("TCP", "UDP", "ICMP")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes,
    ) -> InspectionResult:
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        src_ip   = context.src_ip or "0.0.0.0"
        dst_ip   = context.dst_ip or "0.0.0.0"
        src_port = context.src_port or 0
        dst_port = context.dst_port or 0
        proto    = context.protocol or "any"

        # 1. Stateful shortcut — established connections bypass deep evaluation
        if self._state_tracker:
            conn_state = self._state_tracker.get_or_update_state(
                src_ip, src_port, dst_ip, dst_port, proto
            )
            from modules.firewall.engine.state_tracker import ConnectionState
            if conn_state == ConnectionState.ESTABLISHED:
                result.processing_time_ms = (time.time() - start) * 1000
                return result   # fast path

        # 2. Full policy evaluation
        try:
            decision = self._evaluate(context, src_ip, dst_ip, src_port, dst_port, proto)
        except Exception as exc:
            self.logger.error("FirewallPlugin evaluation error: %s", exc, exc_info=True)
            # Fail-open (monitor mode) — do NOT silently block on errors
            result.processing_time_ms = (time.time() - start) * 1000
            return result

        action_str = decision.get("action", "ALLOW").upper()

        if action_str in ("DROP", "BLOCK", "REJECT"):
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="HIGH",
                category="Firewall",
                description=decision.get("reason", "Blocked by firewall policy"),
                confidence=decision.get("confidence", 1.0),
                recommends_block=True,
                metadata={
                    "rule":     decision.get("rule_name", ""),
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "dst_port": dst_port,
                    "proto":    proto,
                },
            ))
        elif action_str == "LOG":
            result.action = InspectionAction.LOG_ONLY

        # 3. Update state table for allowed connections only
        if result.action == InspectionAction.ALLOW and self._state_tracker:
            self._state_tracker.get_or_update_state(
                src_ip, src_port, dst_ip, dst_port, proto
            )

        result.metadata["firewall"] = {
            "action":    action_str,
            "rule_name": decision.get("rule_name", ""),
            "reason":    decision.get("reason", ""),
        }
        result.processing_time_ms = (time.time() - start) * 1000
        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _evaluate(self, context, src_ip, dst_ip, src_port, dst_port, proto) -> dict:
        """Run UnifiedEvaluator, lazy-initializing DB session if needed."""
        evaluator = self._get_evaluator()
        ctx_dict = {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  proto,
            "interface": getattr(context, "interface", "any"),
            "app_id":    (context.metadata or {}).get("app_id"),
            "domain":    (context.metadata or {}).get("domain"),
        }
        return evaluator.evaluate(ctx_dict)

    def _get_evaluator(self):
        """Lazy-load UnifiedEvaluator with a DB session from db_manager."""
        if self._evaluator is not None:
            return self._evaluator
        try:
            from modules.firewall.engine.evaluator import UnifiedEvaluator
            db_session = None
            if self.db_manager:
                db_session = self.db_manager.session()
            self._evaluator = UnifiedEvaluator(db_session)
            self.logger.info("FirewallPlugin: UnifiedEvaluator loaded with %d rules",
                             len(self._evaluator.acl_engine.rules))
        except Exception as exc:
            self.logger.error("FirewallPlugin: Failed to load UnifiedEvaluator: %s", exc)
            # Minimal fallback — allow all (fail-open)
            class _PassThrough:
                def evaluate(self, ctx):
                    return {"action": "ALLOW", "confidence": 0.5,
                            "reason": "Evaluator unavailable", "rule_name": ""}
            self._evaluator = _PassThrough()
        return self._evaluator

    def reload_rules(self):
        """Hot-reload rules from DB (call after rule changes via API)."""
        self._evaluator = None   # force re-init on next packet
        self.logger.info("FirewallPlugin: rules reload scheduled")

    def get_stats(self) -> dict:
        """Return live state table stats."""
        if self._state_tracker:
            return {
                "active_connections": len(self._state_tracker.state_table),
                "timeout_seconds": self._state_tracker.timeout_seconds,
            }
        return {"active_connections": 0}
