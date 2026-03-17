"""
Enterprise NGFW — WAF Honeypot Guard

Detects attackers probing well-known "secret" paths that no legitimate
user would ever access (admin panels, .env files, debug consoles, etc.).

When a honeypot path is accessed:
  1. Immediately elevates the source IP risk by +HONEYPOT_SCORE_BOOST
  2. Records the event in an in-memory blacklist (TTL configurable)
  3. Returns a fake 404 response (attacker doesn't know it's a honeypot)

Integration
-----------
Call HoneypotGuard.check(src_ip, request_path) at the start of WAF inspection.
The returned HoneypotResult.triggered flag tells the Risk Engine to apply
the score boost. If tarpit_enabled is true, returning payload may be delayed
drastically.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Honeypot path definitions
# ──────────────────────────────────────────────

HONEYPOT_PATHS: frozenset = frozenset([
    # Admin panels
    '/admin_backup',
    '/admin_backup/',
    '/.admin',
    '/wp-admin',
    '/wp-login.php',
    # Debug / dev tools
    '/debug_console',
    '/phpmyadmin',
    '/phpMyAdmin',
    '/pma',
    '/adminer.php',
    # Exposed config / secrets
    '/.env',
    '/.env.production',
    '/.env.local',
    '/.git/config',
    '/.git/HEAD',
    '/config.php',
    '/config.yml',
    '/database.yml',
    '/settings.py',
    # API internals
    '/private_api',
    '/api/v0/internal',
    '/api/admin',
    '/internal',
    # Old / backup files
    '/backup.sql',
    '/backup.zip',
    '/site.tar.gz',
    'index.php.bak',
    # Exploit kits & scanner bait
    '/shell.php',
    '/c99.php',
    '/r57.php',
    '/webshell.php',
    '/xmlrpc.php',
    '/eval-stdin.php',
    # Cloud metadata (SSRF bait)
    '/latest/meta-data/',
    '/computeMetadata/v1/',
])


# ──────────────────────────────────────────────
#  Data structures
# ──────────────────────────────────────────────

@dataclass
class HoneypotEvent:
    """Records a single honeypot access."""
    src_ip:    str
    path:      str
    timestamp: float = field(default_factory=time.time)


@dataclass
class HoneypotResult:
    """Result of a honeypot check."""
    triggered:   bool  = False
    path:        str   = ""
    score_boost: float = 0.0   # amount to add to Risk Score
    tarpit_delay_sec: float = 0.0 # Active deception delay


# ──────────────────────────────────────────────
#  HoneypotGuard
# ──────────────────────────────────────────────

class HoneypotGuard:
    """
    Honeypot access guard.

    Args:
        score_boost: Risk score boost applied when a honeypot is triggered (0–1.0)
        blacklist_ttl_seconds: How long to remember a triggering IP
    """

    def __init__(
        self,
        score_boost: float = 0.5,
        blacklist_ttl_seconds: int = 86_400,   # 24 hours
        tarpit_enabled: bool = True,           # Enable active deception
    ):
        self.score_boost = score_boost
        self.blacklist_ttl = blacklist_ttl_seconds
        self.tarpit_enabled = tarpit_enabled

        # ip → expiry timestamp
        self._blacklist: dict[str, float] = {}
        # full event log
        self._events: list[HoneypotEvent] = []

    # ── Public API ──────────────────────────────

    def check(self, src_ip: str, request_path: str) -> HoneypotResult:
        """
        Check whether the request path is a honeypot.

        Returns HoneypotResult with triggered=True and score_boost if it is.
        """
        # Clean path: strip query string and normalize case
        path = request_path.split('?')[0].rstrip('/')
        if not path:
            path = '/'

        # Check against honeypot paths (case-insensitive)
        matched = path in HONEYPOT_PATHS or path.lower() in HONEYPOT_PATHS

        if not matched:
            # Also check if the IP is already blacklisted from a previous honeypot hit
            if self.is_blacklisted(src_ip):
                logger.warning(
                    "🍯 Honeypot: blacklisted IP %s accessed %s", src_ip, path
                )
                return HoneypotResult(
                    triggered=True,
                    path=path,
                    score_boost=self.score_boost * 0.5,  # half boost for follow-up
                    tarpit_delay_sec=10.0 if self.tarpit_enabled else 0.0, # Active Deception on repeated probes
                )
            return HoneypotResult(triggered=False)

        # ── Honeypot triggered ──
        event = HoneypotEvent(src_ip=src_ip, path=path)
        self._events.append(event)
        self._blacklist[src_ip] = time.time() + self.blacklist_ttl

        logger.warning(
            "🍯 Honeypot TRIGGERED: IP=%s Path=%s — blacklisted for %ds",
            src_ip, path, self.blacklist_ttl
        )

        return HoneypotResult(
            triggered=True,
            path=path,
            score_boost=self.score_boost,
            tarpit_delay_sec=5.0 if self.tarpit_enabled else 0.0, # Initial trap
        )

    def is_blacklisted(self, src_ip: str) -> bool:
        """Return True if this IP triggered a honeypot and is still within TTL."""
        expiry = self._blacklist.get(src_ip)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._blacklist[src_ip]
            return False
        return True

    def get_event_log(self) -> list:
        """Return full list of HoneypotEvents for audit/reporting."""
        return list(self._events)

    def get_blacklist_snapshot(self) -> dict:
        """Return current blacklist {ip: remaining_seconds}."""
        now = time.time()
        return {
            ip: round(expiry - now)
            for ip, expiry in self._blacklist.items()
            if expiry > now
        }

    def clear_expired(self) -> int:
        """Remove expired entries from the blacklist. Returns count removed."""
        now = time.time()
        expired = [ip for ip, exp in self._blacklist.items() if exp <= now]
        for ip in expired:
            del self._blacklist[ip]
        return len(expired)
