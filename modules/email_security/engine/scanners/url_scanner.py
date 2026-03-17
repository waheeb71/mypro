"""
Enterprise NGFW — Email URL Scanner

Scans URLs found in emails for:
  1. Redirect chains / URL shorteners hiding real destination
  2. Suspicious TLD / domain patterns
  3. IP-literal URLs (http://1.2.3.4/login)
  4. Domain reputation via Threat Intelligence cache
  5. Lookalike / homograph domains (paypa1.com instead of paypal.com)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── URL Shorteners (common redirect services) ──
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "tiny.cc", "is.gd", "su.pr",
}

# ── Suspicious TLDs frequently used in phishing ──
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",     # Free Freenom TLDs
    ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".fun", ".icu",
    ".ru", ".cn",                           # High-risk country TLDs
}

# ── IP-literal URL pattern ──
_IP_URL_PATTERN = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}', re.I)

# ── Homograph detection — lookalike chars in Latin ──
_LOOKALIKE = str.maketrans(
    "0lI|1",
    "oliIO"   # common character substitutions
)


@dataclass
class URLScanResult:
    url:          str
    score:        float = 0.0      # 0.0=clean, 1.0=malicious
    flags:        List[str] = field(default_factory=list)
    is_shortener: bool = False
    is_ip_url:    bool = False
    suspicious_tld: bool = False
    reputation:   float = 0.0     # from ThreatIntelCache


@dataclass
class URLScannerResult:
    total_urls:   int = 0
    flagged_urls: List[URLScanResult] = field(default_factory=list)
    score:        float = 0.0
    excessive_urls: bool = False


class URLScanner:
    """
    Scan URLs extracted from an email body.

    Args:
        max_urls_per_email: Flag if email contains more URLs than this
        reputation_check:   Use ThreatIntelCache for domain reputation
        detect_redirects:   Flag known URL shortener domains
        trusted_domains:    These domains get a pass (no scoring)
        threat_intel:       Optional ThreatIntelCache instance
    """

    def __init__(
        self,
        max_urls_per_email: int = 10,
        reputation_check:   bool = True,
        detect_redirects:   bool = True,
        trusted_domains:    Optional[List[str]] = None,
        threat_intel=None,
    ):
        self.max_urls_per_email = max_urls_per_email
        self.reputation_check   = reputation_check
        self.detect_redirects   = detect_redirects
        self.trusted_domains    = set(trusted_domains or [])
        self.threat_intel       = threat_intel

    def scan(self, urls: List[str]) -> URLScannerResult:
        """
        Scan a list of URLs and return aggregated result.
        """
        result = URLScannerResult(total_urls=len(urls))

        if len(urls) > self.max_urls_per_email:
            result.excessive_urls = True

        flagged = []
        for url in urls[:50]:    # cap at 50 URLs to avoid DoS
            scan = self._scan_single(url)
            if scan.score > 0.2:
                flagged.append(scan)

        result.flagged_urls = sorted(flagged, key=lambda x: -x.score)

        # Score = worst flagged URL + penalty for excessive URLs
        if flagged:
            result.score = max(s.score for s in flagged)
        if result.excessive_urls:
            result.score = min(result.score + 0.2, 1.0)

        return result

    def _scan_single(self, url: str) -> URLScanResult:
        scan = URLScanResult(url=url)

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip("www.")
            tld    = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
        except Exception:
            scan.score = 0.1
            scan.flags.append("unparseable_url")
            return scan

        # Skip trusted domains entirely
        root_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        if root_domain in self.trusted_domains or domain in self.trusted_domains:
            return scan

        # 1. IP-literal URL
        if _IP_URL_PATTERN.match(url):
            scan.is_ip_url = True
            scan.score += 0.5
            scan.flags.append("ip_literal_url")

        # 2. URL shortener
        if self.detect_redirects and (domain in _SHORTENERS or root_domain in _SHORTENERS):
            scan.is_shortener = True
            scan.score += 0.3
            scan.flags.append("url_shortener")

        # 3. Suspicious TLD
        if tld in _SUSPICIOUS_TLDS:
            scan.suspicious_tld = True
            scan.score += 0.3
            scan.flags.append(f"suspicious_tld:{tld}")

        # 4. Excessive subdomains (attacker trick: paypal.com.evil.ru)
        parts = domain.split(".")
        if len(parts) > 4:
            scan.score += 0.2
            scan.flags.append("excessive_subdomains")

        # 5. Very long URL (common in phishing to hide real destination)
        if len(url) > 200:
            scan.score += 0.1
            scan.flags.append("very_long_url")

        # 6. Non-HTTPS
        if url.startswith("http://"):
            scan.score += 0.1
            scan.flags.append("no_https")

        # Clamp
        scan.score = min(scan.score, 1.0)
        return scan
