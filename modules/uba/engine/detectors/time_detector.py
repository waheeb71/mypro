"""
Enterprise CyberNexus — UBA Time Anomaly Detector

Detects access at unusual hours compared to the user's established work-hour
baseline using a 3-sigma rule applied to the per-user hour histogram.

Score: 0.0 – 0.35
"""

import math
import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)


def _histogram_mean_stddev(histogram: Dict[str, int]) -> tuple[float, float]:
    """Compute weighted mean and std-dev of hours from a count histogram."""
    total = sum(histogram.values())
    if total == 0:
        return 12.0, 6.0   # unknown → centre of day, wide spread

    mean = sum(int(h) * c for h, c in histogram.items()) / total
    variance = sum(c * (int(h) - mean) ** 2 for h, c in histogram.items()) / total
    return mean, math.sqrt(max(variance, 1.0))   # floor stddev at 1h


class TimeAnomalyDetector:
    """
    Analyse whether the event's current hour falls within the user's
    typical work-hour window.

    Strategy:
    1. If histogram has enough data (≥ baseline_min_events on profile):
       Use 3-sigma Gaussian test relative to the hour distribution.
    2. Otherwise: fall back to simple start/end window check.
    """

    MAX_SCORE = 0.35

    def analyze(self, profile, current_time: float | None = None) -> tuple[float, list[str]]:
        """
        Returns (score, flags).

        profile: UBAUserProfile DB row (or any object with the expected attrs)
        current_time: unix timestamp — defaults to now
        """
        ts = current_time or time.time()
        hour = time.localtime(ts).tm_hour
        flags: list[str] = []
        score = 0.0

        histogram: dict = profile.hour_histogram or {}

        if profile.baseline_locked and histogram:
            mean, stddev = _histogram_mean_stddev(histogram)
            # Handle wrap-around midnight (simplistic: use modular distance)
            delta = min(abs(hour - mean), 24 - abs(hour - mean))
            sigma = delta / max(stddev, 0.5)

            if sigma > 3.0:
                score = self.MAX_SCORE
                flags.append(f"time:extreme_outlier_{hour}h ({sigma:.1f}σ)")
            elif sigma > 2.0:
                score = self.MAX_SCORE * 0.6
                flags.append(f"time:unusual_hour_{hour}h ({sigma:.1f}σ)")
        else:
            # Fallback: simple window check
            start = getattr(profile, 'typical_hours_start', 8)
            end = getattr(profile, 'typical_hours_end', 18)
            if not (start <= hour <= end):
                score = self.MAX_SCORE * 0.7
                flags.append(f"time:outside_window_{hour}h (expected {start}-{end})")

        return score, flags

    def update_histogram(self, histogram: dict, current_time: float | None = None) -> dict:
        """Increment the hour bucket for the current time."""
        ts = current_time or time.time()
        hour = str(time.localtime(ts).tm_hour)
        histogram = dict(histogram or {})
        histogram[hour] = histogram.get(hour, 0) + 1
        return histogram
