"""
Enterprise CyberNexus v2.0 - DNS Security Plugin (Unified, Cached)

Uses the centralized DNSEngine for zero-DB-access per-packet inspection.
All rule matching and config reads happen against in-memory caches.
"""

import time
import logging
import threading
from collections import defaultdict
from typing import Dict, List, Tuple

from system.inspection_core.framework.plugin_base import (
    InspectorPlugin,
    InspectionContext,
    InspectionFinding,
    InspectionResult,
    InspectionAction,
)
from modules.dns_security.engine.dns_engine import DNSEngine
from modules.dns_security.models import ActionEnum
from .dga_detector import DGADetector
from .tunneling_detector import DNSTunnelingDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedded threat-intel seed list (loaded at startup, extended by feed_url)
# ---------------------------------------------------------------------------
THREAT_INTEL_DOMAINS = frozenset({
    "malware-c2.example.com",
    "botnet-gate.xyz",
    "dnscat.evil.tk",
})


class DNSSecurityPlugin(InspectorPlugin):
    """
    Unified DNS Security Plugin — Priority 20 (runs early in pipeline).

    All per-packet decisions are made against in-memory caches via DNSEngine.
    No database connection is opened per packet.
    """

    def __init__(self, block_on_match: bool = True):
        super().__init__(name="dns_security", priority=20)
        self.block_on_match = block_on_match
        self.engine = DNSEngine()

        # Rate-limiting state: src_ip → list of timestamps (sliding window)
        self._query_counts: Dict[str, List[float]] = defaultdict(list)
        # Tunneling behavioural counter: (src_ip, domain) → query count
        self._domain_queries: Dict[Tuple[str, str], int] = defaultdict(int)
        self._state_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Plugin contract
    # ------------------------------------------------------------------

    def can_inspect(self, context: InspectionContext) -> bool:
        return (
            context.protocol == "dns"
            or context.metadata.get("is_dns", False)
            or (context.protocol == "UDP" and context.dst_port == 53)
        )

    # ------------------------------------------------------------------
    # Main inspection flow (no DB access here)
    # ------------------------------------------------------------------

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings: List[InspectionFinding] = []
        action = InspectionAction.ALLOW

        if not self.engine.is_active:
            return InspectionResult(action=action, findings=findings)

        domain: str = context.metadata.get("domain", "").lower().strip()
        qtype: str = context.metadata.get("query_type", "A")

        if not domain:
            return InspectionResult(action=action, findings=findings)

        # ── 1. Rate Limiting ────────────────────────────────────────
        if self.engine.enable_rate_limiting:
            rl_finding = self._check_rate_limit(context.src_ip)
            if rl_finding:
                findings.append(rl_finding)

        # ── 2. Custom Filter Rules (matched from in-memory cache) ───
        matched_rule = self.engine.match_filter_rules(domain)
        if matched_rule is not None:
            # Update stats asynchronously (brief DB write, not on hot path)
            threading.Thread(
                target=self.engine.update_rule_stats,
                args=(matched_rule.id,),
                daemon=True
            ).start()

            if matched_rule.action == ActionEnum.ALLOW:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[])

            return InspectionResult(
                action=InspectionAction.BLOCK,
                findings=[InspectionFinding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    category="DNS_FILTER",
                    description=f"Domain matched rule '{matched_rule.domain_pattern}': {domain}",
                    confidence=1.0,
                )]
            )

        # ── 3. Threat Intel ────────────────────────────────────────
        if self.engine.enable_threat_intel:
            ti_finding = self._check_threat_intel(domain)
            if ti_finding:
                findings.append(ti_finding)
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        # ── 4. Suspicious TLD ──────────────────────────────────────
        if self.engine.enable_tld_blocking:
            tld_finding = self._check_suspicious_tld(domain)
            if tld_finding:
                findings.append(tld_finding)
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        # ── 5. DGA Detection (Shannon Entropy) ─────────────────────
        if self.engine.enable_dga_detection and DGADetector.is_dga(
            domain, self.engine.dga_entropy_threshold
        ):
            findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="HIGH",
                category="DGA_DETECTED",
                description=f"High-entropy domain detected (possible DGA): {domain}",
                confidence=0.90,
            ))
            if self.block_on_match:
                action = InspectionAction.BLOCK

        # ── 6. DNS Tunneling ───────────────────────────────────────
        if self.engine.enable_tunneling_detection:
            # Structural heuristics (long labels, suspicious query types)
            if DNSTunnelingDetector.is_tunneling(domain, qtype):
                findings.append(InspectionFinding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    category="DNS_TUNNELING",
                    description=f"DNS tunneling characteristics detected: {domain}",
                    confidence=0.95,
                ))
                if self.block_on_match:
                    action = InspectionAction.BLOCK

            # Behavioural: repeated queries from same source
            key = (context.src_ip, domain)
            with self._state_lock:
                self._domain_queries[key] += 1
                count = self._domain_queries[key]

            if count > self.engine.tunneling_query_threshold:
                findings.append(InspectionFinding(
                    plugin_name=self.name,
                    severity="HIGH",
                    category="DNS_REPEATED_QUERIES",
                    description=(
                        f"Excessive queries to {domain}: "
                        f"{count} > {self.engine.tunneling_query_threshold}"
                    ),
                    confidence=0.85,
                ))
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        return InspectionResult(action=action, findings=findings)

    # ------------------------------------------------------------------
    # Internal helpers (stateful, no DB access)
    # ------------------------------------------------------------------

    def _check_rate_limit(self, src_ip: str):
        now = time.time()
        limit = self.engine.rate_limit_per_minute
        with self._state_lock:
            self._query_counts[src_ip] = [
                t for t in self._query_counts[src_ip] if now - t < 60.0
            ]
            self._query_counts[src_ip].append(now)
            count = len(self._query_counts[src_ip])

        if count > limit:
            return InspectionFinding(
                plugin_name=self.name,
                severity="MEDIUM",
                category="DNS_RATE_LIMIT",
                description=f"Excessive DNS queries from {src_ip}: {count} in 60 s (limit {limit})",
                confidence=0.90,
            )
        return None

    def _check_threat_intel(self, domain: str):
        if domain in THREAT_INTEL_DOMAINS:
            return InspectionFinding(
                plugin_name=self.name,
                severity="CRITICAL",
                category="THREAT_INTEL",
                description=f"Domain matches threat-intel feed: {domain}",
                confidence=0.98,
            )
        # Parent-domain suffix match
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in THREAT_INTEL_DOMAINS:
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="HIGH",
                    category="THREAT_INTEL",
                    description=f"Domain {domain} is a subdomain of threat-intel entry {parent}",
                    confidence=0.90,
                )
        return None

    def _check_suspicious_tld(self, domain: str):
        for tld in self.engine.suspicious_tlds:
            if domain.endswith(tld):
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    category="SUSPICIOUS_TLD",
                    description=f"Suspicious TLD '{tld}' in domain: {domain}",
                    confidence=0.75,
                )
        return None
