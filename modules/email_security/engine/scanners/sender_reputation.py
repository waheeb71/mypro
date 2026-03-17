"""
Enterprise NGFW — Sender Reputation Checker

Verifies sender legitimacy through:
  1. SPF  — Is the sender IP authorized by the domain?
  2. DKIM — Is the email signature valid? (header-based check)
  3. DMARC — Does the domain enforce an anti-spoofing policy?
  4. Disposable email domain detection
  5. IP reputation via Threat Intelligence cache
"""

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── Known disposable email providers ─────────────────
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "spam4.me", "trashmail.com", "dispostable.com",
    "maildrop.cc", "fakeinbox.com", "jetable.fr", "spamgourmet.com",
    "discard.email", "spamex.com", "mailnull.com", "spamspot.com",
}


@dataclass
class SenderReputationResult:
    spf_status:       str   = "unknown"   # pass | fail | softfail | neutral | unknown
    dkim_present:     bool  = False        # True if DKIM-Signature header found
    dmarc_policy:     str   = "unknown"   # none | quarantine | reject | unknown
    is_disposable:    bool  = False
    ip_reputation:    float = 0.0          # from ThreatIntel (0.0=clean, 1.0=bad)
    score:            float = 0.0
    flags:            List[str] = field(default_factory=list)


class SenderReputation:
    """
    Analyse sender reputation from email headers + IP.

    Args:
        spf_check:                 Perform SPF DNS lookup
        dkim_check:                Check for DKIM-Signature header
        dmarc_check:               Check DMARC policy via DNS
        block_disposable_domains:  Treat disposable email services as suspicious
        custom_suspicious_domains: Extra domain list to flag
        threat_intel:              Optional ThreatIntelCache for IP reputation
    """

    def __init__(
        self,
        spf_check:                bool = True,
        dkim_check:               bool = True,
        dmarc_check:              bool = True,
        block_disposable_domains: bool = True,
        custom_suspicious_domains: Optional[List[str]] = None,
        threat_intel=None,
    ):
        self.spf_check    = spf_check
        self.dkim_check   = dkim_check
        self.dmarc_check  = dmarc_check
        self.block_disposable = block_disposable_domains
        self.threat_intel = threat_intel

        self._suspicious_domains = set(custom_suspicious_domains or [])

    def check(self, parsed_email) -> SenderReputationResult:
        """
        Check sender reputation.

        Args:
            parsed_email: ParsedEmail from EmailPreprocessor
        """
        result = SenderReputationResult()
        headers = parsed_email.headers or {}
        raw_from = parsed_email.raw_from or ""
        sender_ip = parsed_email.sender_ip or ""

        # Extract sender domain
        domain = self._extract_domain(raw_from)

        # 1. SPF check (from Authentication-Results header — already computed by MTA)
        if self.spf_check:
            result.spf_status = self._read_spf_from_headers(headers)
            if result.spf_status in ("fail", "hardfail"):
                result.score += 0.4
                result.flags.append(f"spf_fail:{result.spf_status}")
            elif result.spf_status == "softfail":
                result.score += 0.2
                result.flags.append("spf_softfail")

        # 2. DKIM — look for DKIM-Signature header
        if self.dkim_check:
            result.dkim_present = any(
                k.lower() == "dkim-signature" for k in headers
            )
            if not result.dkim_present:
                result.score += 0.15
                result.flags.append("no_dkim_signature")

        # 3. DMARC — check DNS TXT record for _dmarc.<domain>
        if self.dmarc_check and domain:
            result.dmarc_policy = self._lookup_dmarc(domain)
            if result.dmarc_policy == "none":
                result.score += 0.1
                result.flags.append("dmarc_policy_none")
            elif result.dmarc_policy == "unknown":
                result.score += 0.05
                result.flags.append("dmarc_not_configured")

        # 4. Disposable email domain
        if self.block_disposable and domain:
            if domain in _DISPOSABLE_DOMAINS or domain in self._suspicious_domains:
                result.is_disposable = True
                result.score += 0.5
                result.flags.append(f"disposable_domain:{domain}")

        # 5. IP reputation (sync from cache)
        if sender_ip and self.threat_intel:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    result.ip_reputation = loop.run_until_complete(
                        self.threat_intel.get_ip_score(sender_ip)
                    )
                else:
                    result.ip_reputation = 0.0  # async env — use cached value
            except Exception as e:
                logger.debug("Sender IP reputation lookup failed: %s", e)

        if result.ip_reputation > 0.5:
            result.score += result.ip_reputation * 0.4
            result.flags.append(f"bad_sender_ip:{sender_ip} score={result.ip_reputation:.2f}")

        result.score = min(result.score, 1.0)
        return result

    # ── Helpers ──────────────────────────────────────

    @staticmethod
    def _extract_domain(raw_from: str) -> str:
        """Extract domain from 'Name <user@domain.com>' or 'user@domain.com'."""
        match = re.search(r'@([\w.\-]+)', raw_from)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _read_spf_from_headers(headers: dict) -> str:
        """
        Read SPF result from Authentication-Results or Received-SPF header.
        Modern MTAs (Postfix, Exchange) stamp this during delivery.
        """
        for key in ("Authentication-Results", "Received-SPF"):
            value = headers.get(key, "").lower()
            if not value:
                # Try case-insensitive search
                value = next(
                    (v.lower() for k, v in headers.items() if k.lower() == key.lower()),
                    ""
                )
            if "spf=pass" in value:
                return "pass"
            if "spf=fail" in value:
                return "fail"
            if "spf=softfail" in value:
                return "softfail"
            if "spf=neutral" in value:
                return "neutral"
        return "unknown"

    @staticmethod
    def _lookup_dmarc(domain: str) -> str:
        """
        DNS TXT lookup for _dmarc.<domain>.
        Returns: none | quarantine | reject | unknown
        """
        try:
            import dns.resolver
            txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in txt_records:
                record = r.to_text().strip('"').lower()
                if "v=dmarc1" in record:
                    if "p=reject" in record:   return "reject"
                    if "p=quarantine" in record: return "quarantine"
                    if "p=none" in record:      return "none"
        except Exception:
            pass
        return "unknown"
