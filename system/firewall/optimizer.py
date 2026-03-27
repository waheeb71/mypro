"""
Enterprise CyberNexus NGFW — Smart Firewall Policy Optimizer
=============================================================
Production-grade, thread-safe, rule-based optimizer.

Design Principles:
  - Human-in-the-Loop: NEVER applies changes automatically.
  - Explainable: every suggestion includes a human-readable reason.
  - Extensible: abstracted interfaces for rule repo + telemetry source.
  - Thread-safe: safe to run as a background daemon.
  - Efficient: O(N²) shadow detection with early-exit + set-based merging.
"""

import ipaddress
import threading
import time
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────
# Data Contracts (Rule & TelemetryLog structure)
# ─────────────────────────────────────────────────

@dataclass
class FirewallRule:
    id: int
    action: str                  # "ALLOW" | "BLOCK"
    source_ip: str = "any"
    dest_ip: str = "any"
    protocol: str = "any"
    dest_port: str = "any"
    priority: int = 100
    hit_count: int = 0
    enabled: bool = True
    is_critical: bool = False    # True = default-deny, management rules etc.
    created_at: Optional[datetime] = None
    name: str = ""

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


@dataclass
class TelemetryLog:
    rule_id: int
    timestamp: datetime
    decision: str               # "allow" | "block"
    src_ip: str = ""
    dst_ip: str = ""


@dataclass
class OptimizationSuggestion:
    action: str                 # "delete" | "shadowed" | "merge" | "reorder"
    reason: str
    confidence: float           # 0.0 – 1.0
    rule_id: Optional[int] = None
    shadowed_by: Optional[int] = None
    rules: Optional[List[int]] = None
    new_order: Optional[List[int]] = None
    efficiency: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "action": self.action,
            "reason": self.reason,
            "confidence": round(self.confidence, 2),
        }
        if self.rule_id is not None:
            d["rule_id"] = self.rule_id
        if self.shadowed_by is not None:
            d["shadowed_by"] = self.shadowed_by
        if self.rules is not None:
            d["rules"] = self.rules
        if self.new_order is not None:
            d["new_order"] = self.new_order
        if self.efficiency is not None:
            d["efficiency"] = round(self.efficiency, 4)
        return d


# ─────────────────────────────────────────────────
# Abstract Data Source Interfaces
# ─────────────────────────────────────────────────

class RuleRepository(ABC):
    """Abstract interface for fetching active firewall rules."""

    @abstractmethod
    def get_all_rules(self) -> List[FirewallRule]:
        ...


class TelemetrySource(ABC):
    """Abstract interface for fetching historical telemetry logs."""

    @abstractmethod
    def get_logs_since(self, since: datetime) -> List[TelemetryLog]:
        ...


# ─────────────────────────────────────────────────
# Concrete adapter for plain-dict rules (existing base.yaml format)
# ─────────────────────────────────────────────────

class DictRuleRepository(RuleRepository):
    """Adapter: wraps a plain list[dict] (e.g. from base.yaml) as a RuleRepository."""

    def __init__(self, raw_rules: List[Dict[str, Any]]):
        self._rules = raw_rules

    def get_all_rules(self) -> List[FirewallRule]:
        rules = []
        for r in self._rules:
            rules.append(FirewallRule(
                id=r.get("id", 0),
                action=r.get("action", "ALLOW"),
                source_ip=r.get("source_ip", "any"),
                dest_ip=r.get("dest_ip", r.get("destination_ip", "any")),
                protocol=r.get("protocol", "any"),
                dest_port=str(r.get("dest_port", r.get("destination_port", "any"))),
                priority=r.get("priority", 100),
                hit_count=r.get("hit_count", 0),
                enabled=r.get("enabled", True),
                is_critical=r.get("is_critical", False),
                name=r.get("name", ""),
                created_at=datetime.now(timezone.utc),
            ))
        return rules


class NullTelemetrySource(TelemetrySource):
    """Fallback telemetry source when no telemetry integration is available."""

    def get_logs_since(self, since: datetime) -> List[TelemetryLog]:
        return []


# ─────────────────────────────────────────────────
# Core Optimizer Engine
# ─────────────────────────────────────────────────

class FirewallOptimizer:
    """
    Deterministic, heuristic-based firewall policy optimizer.

    This engine analyzes the active ruleset against live telemetry
    and generates HUMAN-REVIEWED optimization suggestions.

    ⚠️  This optimizer NEVER modifies rules automatically.
        All output is advisory (Human-in-the-Loop).

    Usage:
        repo = DictRuleRepository(raw_rules)
        optimizer = FirewallOptimizer(repo)
        report = optimizer.analyze()
    """

    # Rules that have NOT been hit in this many days are flagged as "dead"
    UNUSED_THRESHOLD_DAYS: int = 30

    def __init__(
        self,
        rule_repository: RuleRepository,
        telemetry_source: Optional[TelemetrySource] = None,
    ):
        self._repo = rule_repository
        self._telemetry = telemetry_source or NullTelemetrySource()
        self._lock = threading.Lock()               # Thread-safe analysis runs

    # ── Main Entry Point ──────────────────────────

    def analyze(self) -> Dict[str, Any]:
        """
        Run all heuristic analyses and compile the optimization report.
        Thread-safe: safe to call from a background daemon thread.

        Returns:
            A structured report dict with analysis metadata + suggestion list.
        """
        with self._lock:
            return self._run_analysis()

    def _run_analysis(self) -> Dict[str, Any]:
        logger.info("[Optimizer] Starting policy analysis...")
        start = time.perf_counter()

        rules = self._repo.get_all_rules()
        active_rules = [r for r in rules if r.enabled]

        # Build telemetry index: rule_id → last_seen timestamp
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.UNUSED_THRESHOLD_DAYS)
        logs = self._telemetry.get_logs_since(cutoff)
        recently_active_ids: set = {log.rule_id for log in logs}
        total_traffic = len(logs) or 1             # avoid division by zero

        suggestions: List[OptimizationSuggestion] = []
        suggestions.extend(self.detect_unused_rules(active_rules, recently_active_ids))
        suggestions.extend(self.detect_shadowed_rules(active_rules))
        suggestions.extend(self.detect_mergeable_rules(active_rules))
        suggestions.extend(self.optimize_order(active_rules, total_traffic))

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        report = {
            "status": "success",
            "calculation_time_ms": elapsed_ms,
            "total_rules_analyzed": len(active_rules),
            "total_suggestions": len(suggestions),
            "suggestions": [s.to_dict() for s in suggestions],
        }

        logger.info(
            f"[Optimizer] Done in {elapsed_ms}ms — "
            f"{len(suggestions)} suggestion(s) from {len(active_rules)} rules."
        )
        return report

    # ── Analysis Methods ──────────────────────────

    def detect_unused_rules(
        self,
        rules: List[FirewallRule],
        recently_active_ids: set,
    ) -> List[OptimizationSuggestion]:
        """
        Flag rules that have NEVER been triggered AND have not appeared in
        telemetry for the last 30 days.  Critical rules are excluded.

        Confidence = high (0.9) when both conditions are met.
        """
        suggestions = []
        for rule in rules:
            if rule.is_critical:
                continue   # SAFETY: never touch critical/default-deny rules
            if rule.hit_count == 0 and rule.id not in recently_active_ids:
                suggestions.append(OptimizationSuggestion(
                    action="delete",
                    rule_id=rule.id,
                    reason=(
                        f"Rule '{rule.name or rule.id}' has never been triggered "
                        f"(hit_count=0) and has not appeared in telemetry for the "
                        f"past {self.UNUSED_THRESHOLD_DAYS} days. "
                        "Safe to remove to reduce attack surface."
                    ),
                    confidence=0.9,
                ))
        return suggestions

    def detect_shadowed_rules(
        self,
        rules: List[FirewallRule],
    ) -> List[OptimizationSuggestion]:
        """
        Identify rules that will NEVER be reached because a higher-priority
        rule fully subsumes their traffic parameters.

        A rule B is shadowed by A when:
          - A has higher priority (lower priority number)
          - src(B) ⊆ src(A)  AND  dst(B) ⊆ dst(A)
          - protocol(A) == 'any' or protocol(A) == protocol(B)
          - port(A) == 'any' or port(A) == port(B)
        """
        sorted_rules = sorted(rules, key=lambda r: r.priority)
        suggestions = []

        for i, rule_b in enumerate(sorted_rules):
            if rule_b.is_critical:
                continue
            for rule_a in sorted_rules[:i]:     # only higher-priority rules
                if self._is_shadow(rule_a, rule_b):
                    action_a = rule_a.action.upper()
                    action_b = rule_b.action.upper()
                    if action_a == action_b:
                        reason = (
                            f"Rule {rule_b.id} is completely shadowed by Rule {rule_a.id}. "
                            f"Both have action '{action_a}' and rule {rule_a.id} matches "
                            "a superset of rule "
                            f"{rule_b.id}'s traffic — rule {rule_b.id} will never execute."
                        )
                        confidence = 0.95
                    else:
                        reason = (
                            f"CRITICAL CONFLICT: Rule {rule_b.id} ({action_b}) is "
                            f"shadowed by Rule {rule_a.id} ({action_a}). "
                            "The intended security effect of rule "
                            f"{rule_b.id} is completely negated."
                        )
                        confidence = 0.99   # Very certain — this is a definitive conflict

                    suggestions.append(OptimizationSuggestion(
                        action="shadowed",
                        rule_id=rule_b.id,
                        shadowed_by=rule_a.id,
                        reason=reason,
                        confidence=confidence,
                    ))
                    break   # One shadowing parent is enough to report
        return suggestions

    def detect_mergeable_rules(
        self,
        rules: List[FirewallRule],
    ) -> List[OptimizationSuggestion]:
        """
        Find rules sharing identical (dest_ip, dest_port, protocol, action)
        but differing only in source_ip → they can be grouped into an IP Group.
        """
        suggestions = []
        buckets: Dict[tuple, List[FirewallRule]] = {}
        for rule in rules:
            if rule.is_critical:
                continue
            key = (rule.dest_ip, rule.dest_port, rule.protocol.lower(), rule.action.upper())
            buckets.setdefault(key, []).append(rule)

        for key, group in buckets.items():
            if len(group) >= 2:
                rule_ids = [r.id for r in group]
                dest_ip, dest_port, proto, action = key
                suggestions.append(OptimizationSuggestion(
                    action="merge",
                    rules=rule_ids,
                    reason=(
                        f"Rules {rule_ids} share identical destination "
                        f"({dest_ip}:{dest_port} / {proto.upper()}) and action ({action}). "
                        "Merging them into a single IP Group rule will reduce the rule table "
                        "size and improve packet-matching throughput."
                    ),
                    confidence=0.80,
                ))
        return suggestions

    def optimize_order(
        self,
        rules: List[FirewallRule],
        total_traffic: int = 1,
    ) -> List[OptimizationSuggestion]:
        """
        Suggest reordering rules by descending hit_count.
        Placing frequently matched rules earlier reduces average lookup depth.

        Efficiency = hit_count / total_traffic (packet-matching ratio)
        Suggestion is only generated when current order differs from optimal.
        """
        current_order = [r.id for r in rules]
        optimal_order = [
            r.id for r in sorted(rules, key=lambda r: r.hit_count, reverse=True)
        ]

        if current_order == optimal_order:
            return []    # Already optimal — no suggestion needed

        # Attach efficiency scores to each rule in optimal order
        top_n = 5
        top_rules = sorted(rules, key=lambda r: r.hit_count, reverse=True)[:top_n]
        efficiency_notes = ", ".join(
            f"Rule {r.id} (efficiency={r.hit_count / total_traffic:.2%})"
            for r in top_rules
        )

        return [OptimizationSuggestion(
            action="reorder",
            new_order=optimal_order,
            reason=(
                "Reordering rules by hit_count (descending) reduces average "
                f"packet-matching depth. Top performers: {efficiency_notes}."
            ),
            confidence=0.75,
        )]

    # ── Internal Helpers ──────────────────────────

    def _is_shadow(self, rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
        """Return True if rule_a's traffic space fully contains rule_b's."""
        return (
            self._net_is_subset(rule_b.source_ip, rule_a.source_ip)
            and self._net_is_subset(rule_b.dest_ip, rule_a.dest_ip)
            and self._proto_covered(rule_a.protocol, rule_b.protocol)
            and self._port_covered(rule_a.dest_port, rule_b.dest_port)
        )

    @staticmethod
    def _net_is_subset(sub: str, sup: str) -> bool:
        """Mathematical: sub ⊆ sup using Python ipaddress CIDR arithmetic."""
        if sup.lower() == "any":
            return True
        if sub.lower() == "any":
            return False
        try:
            net_sub = ipaddress.ip_network(sub, strict=False)
            net_sup = ipaddress.ip_network(sup, strict=False)
            # Both must be same IP version for subnet_of() to work
            if type(net_sub) is not type(net_sup):
                return False
            if isinstance(net_sub, ipaddress.IPv4Network) and isinstance(net_sup, ipaddress.IPv4Network):
                return net_sub.subnet_of(net_sup)
            if isinstance(net_sub, ipaddress.IPv6Network) and isinstance(net_sup, ipaddress.IPv6Network):
                return net_sub.subnet_of(net_sup)
            return False
        except ValueError:
            return False   # FQDN / range format — skip

    @staticmethod
    def _proto_covered(proto_a: str, proto_b: str) -> bool:
        pa, pb = proto_a.lower(), proto_b.lower()
        return pa == "any" or pa == pb

    @staticmethod
    def _port_covered(port_a: str, port_b: str) -> bool:
        pa, pb = str(port_a).lower(), str(port_b).lower()
        return pa == "any" or pa == pb
