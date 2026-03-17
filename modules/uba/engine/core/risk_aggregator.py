"""
Enterprise NGFW — UBA Risk Score Aggregator

Collects detector scores, applies configurable weights, maps the result
to a risk tier, and updates the user profile's running risk score using
an Exponential Moving Average (EMA) — so a single extreme event raises
the score fast, while sustained normalcy gradually reduces it.

Risk Tiers (from UBAConfig.thresholds):
  low      0 – 25
  medium  25 – 55
  high    55 – 80
  critical 80 – 100
"""

from __future__ import annotations

import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS: Dict[str, float] = {
    "time":      0.20,
    "location":  0.30,
    "exfil":     0.25,
    "privilege": 0.15,
    "peer":      0.10,
}

DEFAULT_THRESHOLDS = {
    "medium": 25.0,
    "high":   55.0,
    "critical": 80.0,
}


class RiskAggregator:

    def __init__(
        self,
        weights: Dict[str, float] | None = None,
        thresholds: Dict[str, float] | None = None,
        ema_alpha: float = 0.15,
    ):
        self.weights = weights or DEFAULT_WEIGHTS
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        # Use slightly higher alpha on risk score so threats surface quickly
        self.ema_alpha = ema_alpha

    def aggregate(
        self,
        detector_scores: Dict[str, float],
    ) -> Tuple[float, float]:
        """
        Compute weighted anomaly score (0.0–1.0) from detector sub-scores.

        Returns:
            (raw_score_0_to_1, weighted_risk_0_to_100)
        """
        raw = 0.0
        for name, weight in self.weights.items():
            raw += detector_scores.get(name, 0.0) * weight
        raw = min(raw, 1.0)
        risk_contribution = raw * 100.0
        return raw, risk_contribution

    def update_profile_risk(
        self,
        current_risk_score: float,
        risk_contribution: float,
    ) -> Tuple[float, str]:
        """
        Apply EMA to the profile's running risk score.

        If the event is more severe than current score → fast rise.
        If the event is less severe → slow decay (event_alpha * 0.5).
        Returns (new_risk_score, risk_level_str).
        """
        if risk_contribution >= current_risk_score:
            alpha = self.ema_alpha
        else:
            alpha = self.ema_alpha * 0.5   # slow decay

        new_score = alpha * risk_contribution + (1 - alpha) * current_risk_score
        new_score = max(0.0, min(100.0, new_score))
        level = self._classify(new_score)
        return new_score, level

    def _classify(self, score: float) -> str:
        if score >= self.thresholds.get("critical", 80.0):
            return "critical"
        if score >= self.thresholds.get("high", 55.0):
            return "high"
        if score >= self.thresholds.get("medium", 25.0):
            return "medium"
        return "low"
