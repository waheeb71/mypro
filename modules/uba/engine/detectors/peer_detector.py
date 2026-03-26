"""
Enterprise CyberNexus — UBA Peer Group Comparator

Compares a user's current behavior to the average of their peer group
(users sharing the same role / department).

Score: 0.0 – 0.20

The score is intentionally lower than the other detectors — peer deviation
is a supporting signal, not a primary one; it reduces false positives.
"""

import logging
import math
from typing import Dict, List

logger = logging.getLogger(__name__)


def _z_score(value: float, mean: float, stddev: float) -> float:
    if stddev < 1e-9:
        return 0.0
    return abs(value - mean) / stddev


class PeerGroupDetector:
    """
    Compare the current event's key metrics to the peer-group averages
    stored in a lightweight peer_stats dictionary.

    peer_stats format (provided externally, computed by UserProfiler):
    {
        "avg_daily_bytes": 500_000.0,
        "daily_bytes_stddev": 200_000.0,
        "avg_session_duration": 3600.0,
        "session_duration_stddev": 1800.0,
        "count": 12,   # number of peers
    }
    """

    MAX_SCORE = 0.20

    def analyze(
        self,
        bytes_transferred: float,
        session_duration: float,
        peer_stats: Dict,
    ) -> tuple[float, list[str]]:
        """
        Returns (score, flags).
        """
        flags: list[str] = []

        if not peer_stats or peer_stats.get("count", 0) < 3:
            return 0.0, []   # not enough peers to compare

        score = 0.0

        # ── Bytes z-score ──────────────────────────────────────────────────────
        bz = _z_score(
            bytes_transferred,
            peer_stats.get("avg_daily_bytes", 0),
            peer_stats.get("daily_bytes_stddev", 1),
        )
        if bz > 3.5:
            score += self.MAX_SCORE * 0.6
            flags.append(f"peer:bytes_outlier_z{bz:.1f}")
        elif bz > 2.5:
            score += self.MAX_SCORE * 0.3
            flags.append(f"peer:bytes_deviation_z{bz:.1f}")

        # ── Session duration z-score ───────────────────────────────────────────
        sz = _z_score(
            session_duration,
            peer_stats.get("avg_session_duration", 0),
            peer_stats.get("session_duration_stddev", 1),
        )
        if sz > 3.5:
            score += self.MAX_SCORE * 0.4
            flags.append(f"peer:session_outlier_z{sz:.1f}")

        return min(score, self.MAX_SCORE), flags
