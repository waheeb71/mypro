"""
Enterprise NGFW v2.0 - DNS Security Plugin (Unified)

Consolidated DNS inspection engine:
  - Custom domain filter rules (EXACT / WILDCARD / REGEX)
  - DGA detection  (Shannon Entropy)
  - DNS Tunneling  (length / type heuristics)
  - Rate limiting  (per-source-IP, sliding window)
  - Suspicious TLD blocking
  - Threat-intel feed (local embedded list)

Author: Enterprise NGFW Team
License: Proprietary
"""

import re
import time
import logging
import fnmatch
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, cast

from sqlalchemy.orm import Session

from system.database.database import SessionLocal
from system.inspection_core.framework.plugin_base import (
    InspectorPlugin,
    InspectionContext,
    InspectionFinding,
    InspectionResult,
    InspectionAction,
)
from .dga_detector import DGADetector
from .tunneling_detector import DNSTunnelingDetector
from modules.dns_security.models import (
    DNSFilterRule,
    DNSModuleConfig,
    FilterType,
    ActionEnum,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedded threat-intel seed list (augmented at runtime from DB config)
# ---------------------------------------------------------------------------
THREAT_INTEL_DOMAINS = frozenset({
    # Known C2 / malware infrastructure
    "malware-c2.example.com",
    "botnet-gate.xyz",
    "dnscat.evil.tk",
    # Add real IOC feeds here (or load from file/API)
})


class DNSSecurityPlugin(InspectorPlugin):
    """
    Unified DNS Security Plugin.

    Priority 20 — runs before generic plugins.
    """

    def __init__(self, block_on_match: bool = True):
        super().__init__(name="dns_security", priority=20)
        self.block_on_match = block_on_match

        # Rate-limiting state (per source IP)
        self._query_counts: Dict[str, List[float]] = cast(
            Dict[str, List[float]], defaultdict(list)
        )

        # Tunneling counters: (src_ip, domain) -> count
        self._domain_queries: Dict[Tuple[str, str], int] = cast(
            Dict[Tuple[str, str], int], defaultdict(int)
        )

    # ------------------------------------------------------------------
    # Plugin contract
    # ------------------------------------------------------------------

    def can_inspect(self, context: InspectionContext) -> bool:
        return (
            context.protocol == "dns"
            or context.metadata.get("is_dns", False)
            or (context.protocol == "UDP" and context.dst_port == 53)
        )

    def get_db_session(self) -> Session:
        return SessionLocal()

    # ------------------------------------------------------------------
    # Main inspection flow
    # ------------------------------------------------------------------

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings: List[InspectionFinding] = []
        action = InspectionAction.ALLOW

        domain: str = context.metadata.get("domain", "").lower().strip()
        qtype: str  = context.metadata.get("query_type", "A")

        if not domain:
            return InspectionResult(action=action, findings=findings)

        db = self.get_db_session()
        try:
            config: Optional[DNSModuleConfig] = db.query(DNSModuleConfig).first()

            # Bootstrap default config
            if not config:
                config = DNSModuleConfig()
                db.add(config)
                db.commit()
                db.refresh(config)

            if not config.is_active:
                return InspectionResult(action=action, findings=findings)

            # ── 1. Rate Limiting ────────────────────────────────────────
            if config.enable_rate_limiting:
                rl_finding = self._check_rate_limit(
                    context.src_ip,
                    config.rate_limit_per_minute,
                )
                if rl_finding:
                    findings.append(rl_finding)
                    # Rate limit alone does not block; flag for monitoring

            # ── 2. Custom Domain Filter Rules ──────────────────────────
            filter_result = self._check_domain_filters(domain, db)
            if filter_result is not None:
                return filter_result   # Explicit allow or block — stop here

            # ── 3. Threat Intel ────────────────────────────────────────
            if config.enable_threat_intel:
                ti_finding = self._check_threat_intel(domain)
                if ti_finding:
                    findings.append(ti_finding)
                    if self.block_on_match:
                        action = InspectionAction.BLOCK

            # ── 4. Suspicious TLD ──────────────────────────────────────
            if config.enable_tld_blocking:
                tld_set = {
                    t.strip()
                    for t in (config.suspicious_tlds or "").split(",")
                    if t.strip()
                }
                tld_finding = self._check_suspicious_tld(domain, tld_set)
                if tld_finding:
                    findings.append(tld_finding)
                    if self.block_on_match:
                        action = InspectionAction.BLOCK

            # ── 5. DGA Detection ───────────────────────────────────────
            if config.enable_dga_detection and DGADetector.is_dga(
                domain, config.dga_entropy_threshold
            ):
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity="HIGH",
                        category="DGA_DETECTED",
                        description=(
                            f"High-entropy domain detected (possible DGA): {domain}"
                        ),
                        confidence=0.90,
                    )
                )
                if self.block_on_match:
                    action = InspectionAction.BLOCK

            # ── 6. DNS Tunneling ───────────────────────────────────────
            if config.enable_tunneling_detection:
                # Structural heuristics
                if DNSTunnelingDetector.is_tunneling(domain, qtype):
                    findings.append(
                        InspectionFinding(
                            plugin_name=self.name,
                            severity="CRITICAL",
                            category="DNS_TUNNELING",
                            description=(
                                f"DNS tunneling characteristics detected: {domain}"
                            ),
                            confidence=0.95,
                        )
                    )
                    if self.block_on_match:
                        action = InspectionAction.BLOCK

                # Behavioural: repeated queries from same source
                key = (context.src_ip, domain)
                self._domain_queries[key] += 1
                count = self._domain_queries[key]
                if count > config.tunneling_query_threshold:
                    findings.append(
                        InspectionFinding(
                            plugin_name=self.name,
                            severity="HIGH",
                            category="DNS_REPEATED_QUERIES",
                            description=(
                                f"Excessive queries to {domain}: "
                                f"{count} > {config.tunneling_query_threshold}"
                            ),
                            confidence=0.85,
                        )
                    )
                    if self.block_on_match:
                        action = InspectionAction.BLOCK

        except Exception as exc:
            logger.error(f"DNS plugin inspection error: {exc}", exc_info=True)
        finally:
            db.close()

        return InspectionResult(action=action, findings=findings)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_rate_limit(
        self,
        src_ip: str,
        limit_per_minute: int,
    ) -> Optional[InspectionFinding]:
        """Sliding-window rate limiter per source IP."""
        now = time.time()
        window = 60.0
        self._query_counts[src_ip] = [
            t for t in self._query_counts[src_ip] if now - t < window
        ]
        self._query_counts[src_ip].append(now)
        count = len(self._query_counts[src_ip])
        if count > limit_per_minute:
            return InspectionFinding(
                plugin_name=self.name,
                severity="MEDIUM",
                category="DNS_RATE_LIMIT",
                description=(
                    f"Excessive DNS queries from {src_ip}: "
                    f"{count} in 60 s (limit {limit_per_minute})"
                ),
                confidence=0.90,
            )
        return None

    def _check_domain_filters(
        self,
        domain: str,
        db: Session,
    ) -> Optional[InspectionResult]:
        """
        Match domain against DB filter rules.
        Returns InspectionResult on a definitive match, otherwise None.
        """
        rules: List[DNSFilterRule] = (
            db.query(DNSFilterRule)
            .filter(DNSFilterRule.enabled == True)
            .all()
        )

        for rule in rules:
            pattern = rule.domain_pattern.lower()
            matched = False

            if rule.filter_type == FilterType.EXACT:
                matched = domain == pattern

            elif rule.filter_type == FilterType.WILDCARD:
                matched = fnmatch.fnmatchcase(domain, pattern)

            elif rule.filter_type == FilterType.REGEX:
                try:
                    matched = bool(re.search(pattern, domain))
                except re.error:
                    logger.warning(f"Invalid regex in DNS rule #{rule.id}: {pattern}")
                    matched = False

            if matched:
                # Update hit statistics
                try:
                    rule.blocked_count = (rule.blocked_count or 0) + 1
                    rule.last_triggered = datetime.utcnow()
                    db.commit()
                except Exception:
                    db.rollback()

                if rule.action == ActionEnum.ALLOW:
                    return InspectionResult(
                        action=InspectionAction.ALLOW, findings=[]
                    )

                return InspectionResult(
                    action=InspectionAction.BLOCK,
                    findings=[
                        InspectionFinding(
                            plugin_name=self.name,
                            severity="CRITICAL",
                            category="DNS_FILTER",
                            description=(
                                f"Domain matched rule '{rule.domain_pattern}': "
                                f"{domain}"
                            ),
                            confidence=1.0,
                        )
                    ],
                )

        return None  # No match

    def _check_threat_intel(self, domain: str) -> Optional[InspectionFinding]:
        """Check against embedded threat-intel domain set."""
        # Full match
        if domain in THREAT_INTEL_DOMAINS:
            return InspectionFinding(
                plugin_name=self.name,
                severity="CRITICAL",
                category="THREAT_INTEL",
                description=f"Domain matches threat-intel feed: {domain}",
                confidence=0.98,
            )
        # Parent-domain match (e.g. sub.evil.com → evil.com)
        parts: List[str] = domain.split(".")
        num_parts = len(parts)
        for i in range(1, num_parts - 1):
            suffix_parts: List[str] = [parts[j] for j in range(i, num_parts)]
            parent = ".".join(suffix_parts)
            if parent in THREAT_INTEL_DOMAINS:
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="HIGH",
                    category="THREAT_INTEL",
                    description=(
                        f"Domain {domain} is a subdomain of threat-intel entry "
                        f"{parent}"
                    ),
                    confidence=0.90,
                )
        return None

    def _check_suspicious_tld(
        self,
        domain: str,
        tld_set: Set[str],
    ) -> Optional[InspectionFinding]:
        """Check whether the domain ends with a known-suspicious TLD."""
        for tld in tld_set:
            if domain.endswith(tld):
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    category="SUSPICIOUS_TLD",
                    description=f"Suspicious TLD '{tld}' in domain: {domain}",
                    confidence=0.75,
                )
        return None
