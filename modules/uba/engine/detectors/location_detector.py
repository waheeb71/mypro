"""
Enterprise NGFW — UBA Location / IP Anomaly Detector

Detects access from an unknown source IP compared to the user's known-IP list.
Escalates score if the IP subnet (first 2 octets) has also never been seen.

Score: 0.0 – 0.45
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


def _subnet(ip: str, prefix: int = 2) -> str:
    """Return X.Y prefix of an IPv4 address for rough geo comparison."""
    try:
        return ".".join(ip.split(".")[:prefix])
    except Exception:
        return ip


class LocationAnomalyDetector:
    """
    Detect anomalous source IP / network location.

    Strategy:
    1. Known IP → 0 score
    2. Unknown IP but known subnet (/16) → medium score
    3. Unknown IP and unknown subnet → high score (possible new geo-location)
    """

    MAX_SCORE = 0.45

    def analyze(self, profile, source_ip: str) -> tuple[float, list[str]]:
        """
        Returns (score, flags).

        profile: UBAUserProfile DB row
        source_ip: source IP of the activity
        """
        flags: list[str] = []
        score = 0.0

        if not source_ip:
            return score, flags

        known_ips: list = profile.known_ips or []

        if source_ip in known_ips:
            return 0.0, []   # normal

        # Unknown IP — check subnet
        new_subnet = _subnet(source_ip)
        known_subnets = {_subnet(ip) for ip in known_ips}

        if not known_ips:
            # No baseline yet → small alert only
            score = self.MAX_SCORE * 0.3
            flags.append(f"location:first_seen_ip:{source_ip}")
        elif new_subnet in known_subnets:
            score = self.MAX_SCORE * 0.5
            flags.append(f"location:new_ip_known_subnet:{source_ip}")
        else:
            score = self.MAX_SCORE
            flags.append(f"location:unknown_subnet:{source_ip} (new /16: {new_subnet})")

        return score, flags

    def update_known_ips(self, known_ips: list, source_ip: str, max_ips: int = 30) -> list:
        """Add IP to known list (LRU-style: drop oldest if full)."""
        if not source_ip:
            return known_ips
        known_ips = list(known_ips or [])
        if source_ip not in known_ips:
            known_ips.append(source_ip)
        if len(known_ips) > max_ips:
            known_ips = known_ips[-max_ips:]   # keep most recent
        return known_ips
