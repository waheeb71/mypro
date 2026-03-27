"""
Email Security — Policy Evaluator

Provides a clean, centralized policy layer that maps risk scores to final
enforcement decisions. Separates policy logic from detection logic.
"""

from enum import Enum
from typing import List


class EmailPolicyAction(str, Enum):
    ALLOW      = "allow"
    QUARANTINE = "quarantine"
    BLOCK      = "block"


class EmailPolicyEvaluator:
    """
    Maps a risk breakdown into a final EmailPolicyAction.

    Keeps policy logic (thresholds, overrides, mode) separate from
    the detection/scoring layer (EmailRiskEngine).

    Args:
        mode:                  'enforce' | 'monitor' | 'learning'
        threshold_quarantine:  Score at or above this → quarantine
        threshold_block:       Score at or above this → block
        always_block_brands:   Block on brand-spoof regardless of score
    """

    def __init__(
        self,
        mode: str = "enforce",
        threshold_quarantine: float = 0.55,
        threshold_block: float = 0.80,
        always_block_brands: bool = True,
    ):
        self.mode                = mode
        self.threshold_quarantine = threshold_quarantine
        self.threshold_block     = threshold_block
        self.always_block_brands = always_block_brands

    def evaluate(
        self,
        risk_score: float,
        brand_spoof: str = "",
        force_block: bool = False,
        finding_categories: List[str] = None,
    ) -> EmailPolicyAction:
        """
        Determine policy action for an email.

        In 'monitor' or 'learning' mode every email is ALLOWED regardless
        of score (detections are logged only).

        Args:
            risk_score:          Final weighted score from EmailRiskEngine (0–1)
            brand_spoof:         Detected brand impersonation (e.g. "paypal")
            force_block:         Hard-block flag raised by AttachmentGuard
            finding_categories:  List of detection category strings
        """
        # Monitor / learning mode: never change delivery, just log.
        if self.mode in ("monitor", "learning"):
            return EmailPolicyAction.ALLOW

        # Hard force-block (dangerous executable attachment etc.)
        if force_block:
            return EmailPolicyAction.BLOCK

        # Brand spoofing with confirmed link mismatch → immediate block
        if brand_spoof and self.always_block_brands:
            return EmailPolicyAction.BLOCK

        # Score-based decision
        if risk_score >= self.threshold_block:
            return EmailPolicyAction.BLOCK
        elif risk_score >= self.threshold_quarantine:
            return EmailPolicyAction.QUARANTINE

        return EmailPolicyAction.ALLOW
