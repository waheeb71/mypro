"""
Enterprise CyberNexus — UBA Data Exfiltration Detector

Flags abnormally large data transfers compared to the user's rolling baseline.
Uses the 2-sigma rule: bytes > avg + 2*stddev → suspicious.

Score: 0.0 – 0.40
"""

import math
import logging

logger = logging.getLogger(__name__)


class ExfilDetector:
    """
    Detect potential data exfiltration by comparing bytes_transferred
    against the user's historical volume baseline.

    Baseline learning: updated with exponential moving average (EMA).
    """

    MAX_SCORE = 0.40

    def analyze(
        self,
        profile,
        bytes_transferred: float,
        target_service: str = "",
    ) -> tuple[float, list[str]]:
        """
        Returns (score, flags).
        """
        flags: list[str] = []
        score = 0.0

        if bytes_transferred <= 0:
            return 0.0, []

        avg = profile.avg_daily_bytes or 0.0
        stddev = profile.daily_bytes_stddev or 0.0

        if avg == 0.0 and not profile.baseline_locked:
            # No baseline yet → no score, just learn
            return 0.0, []

        threshold_2sigma = avg + 2 * max(stddev, avg * 0.2)   # floor stddev at 20% of avg
        threshold_3sigma = avg + 3 * max(stddev, avg * 0.2)

        if bytes_transferred > threshold_3sigma and bytes_transferred > 1_000_000:
            score = self.MAX_SCORE
            flags.append(
                f"exfil:extreme_volume:{bytes_transferred/1e6:.1f}MB "
                f"(threshold {threshold_3sigma/1e6:.1f}MB, 3σ)"
            )
        elif bytes_transferred > threshold_2sigma and bytes_transferred > 500_000:
            score = self.MAX_SCORE * 0.55
            flags.append(
                f"exfil:high_volume:{bytes_transferred/1e6:.1f}MB "
                f"(threshold {threshold_2sigma/1e6:.1f}MB, 2σ)"
            )

        return score, flags

    def update_baseline(
        self,
        profile,
        bytes_transferred: float,
        alpha: float = 0.1,
    ) -> tuple[float, float]:
        """
        Return updated (avg_daily_bytes, daily_bytes_stddev) via EMA.

        alpha: smoothing factor (0=very slow, 1=instant).
        """
        prev_avg = profile.avg_daily_bytes or bytes_transferred
        prev_var = (profile.daily_bytes_stddev or 0.0) ** 2

        new_avg = alpha * bytes_transferred + (1 - alpha) * prev_avg
        new_var = alpha * (bytes_transferred - new_avg) ** 2 + (1 - alpha) * prev_var
        new_stddev = math.sqrt(max(new_var, 0.0))

        max_obs = max(profile.max_observed_bytes or 0.0, bytes_transferred)
        return new_avg, new_stddev, max_obs
