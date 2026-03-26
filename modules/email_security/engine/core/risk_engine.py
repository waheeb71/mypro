"""
Enterprise CyberNexus — Email Risk Scoring Engine

Aggregates scores from all email detection modules into a
single risk score and maps it to a policy decision.

Weights (default — configurable via waf.yaml):
  phishing       : 35%
  url_scanner    : 25%
  attachment_guard: 20%
  sender_reputation: 15%
  spam_filter    : 5%
  smtp_commands  : (bonus penalty, not weighted)

Policy decisions:
  ALLOW      : < threshold.allow
  QUARANTINE : threshold.allow - threshold.block  (move to spam folder)
  BLOCK      : >= threshold.block                 (SMTP REJECT)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class EmailPolicyDecision(str, Enum):
    ALLOW      = "allow"
    QUARANTINE = "quarantine"    # Deliver to Spam / Junk folder
    BLOCK      = "block"         # SMTP 550 REJECT — do not deliver


@dataclass
class EmailRiskBreakdown:
    phishing_score:    float = 0.0
    url_score:         float = 0.0
    attachment_score:  float = 0.0
    sender_score:      float = 0.0
    spam_score:        float = 0.0
    command_penalty:   float = 0.0
    final_score:       float = 0.0
    decision:          EmailPolicyDecision = EmailPolicyDecision.ALLOW

    def to_dict(self) -> dict:
        return {
            "phishing_score":   round(self.phishing_score, 3),
            "url_score":        round(self.url_score, 3),
            "attachment_score": round(self.attachment_score, 3),
            "sender_score":     round(self.sender_score, 3),
            "spam_score":       round(self.spam_score, 3),
            "command_penalty":  round(self.command_penalty, 3),
            "final_score":      round(self.final_score, 3),
            "decision":         self.decision.value,
        }


class EmailRiskEngine:
    """
    Calculate final email risk score from all detection layers.

    Weights should sum to 1.0.

    Args:
        w_phishing:    Weight for phishing detection score
        w_url:         Weight for URL scan score
        w_attachment:  Weight for attachment guard score
        w_sender:      Weight for sender reputation score
        w_spam:        Weight for spam filter score
        threshold_allow:      Score below this → ALLOW
        threshold_block:      Score at or above this → BLOCK
    """

    def __init__(
        self,
        w_phishing:       float = 0.35,
        w_url:            float = 0.25,
        w_attachment:     float = 0.20,
        w_sender:         float = 0.15,
        w_spam:           float = 0.05,
        threshold_allow:  float = 0.25,
        threshold_quarantine: float = 0.55,
        threshold_block:  float = 0.80,
    ):
        # Normalize weights
        total = w_phishing + w_url + w_attachment + w_sender + w_spam
        if total > 0:
            self.w_phishing   = w_phishing   / total
            self.w_url        = w_url        / total
            self.w_attachment = w_attachment / total
            self.w_sender     = w_sender     / total
            self.w_spam       = w_spam       / total
        else:
            self.w_phishing = self.w_url = self.w_attachment = 0.20
            self.w_sender = self.w_spam = 0.20

        self.threshold_allow      = threshold_allow
        self.threshold_quarantine = threshold_quarantine
        self.threshold_block      = threshold_block

    def calculate(
        self,
        phishing_score:    float = 0.0,
        url_score:         float = 0.0,
        attachment_score:  float = 0.0,
        sender_score:      float = 0.0,
        spam_score:        float = 0.0,
        command_penalty:   float = 0.0,
        force_block:       bool  = False,
    ) -> EmailRiskBreakdown:
        """
        Calculate the final risk score.

        Args:
            phishing_score:   From PhishingDetector.detect()
            url_score:        From URLScanner.scan()
            attachment_score: From AttachmentGuard.scan()
            sender_score:     From SenderReputation.check()
            spam_score:       From SpamFilter.score()
            command_penalty:  Extra penalty for suspicious SMTP commands
            force_block:      Force BLOCK regardless of score (e.g., dangerous attachment)

        Returns:
            EmailRiskBreakdown with final_score and decision
        """
        breakdown = EmailRiskBreakdown(
            phishing_score   = phishing_score,
            url_score        = url_score,
            attachment_score = attachment_score,
            sender_score     = sender_score,
            spam_score       = spam_score,
            command_penalty  = command_penalty,
        )

        # Weighted sum
        raw = (
            (phishing_score   * self.w_phishing) +
            (url_score        * self.w_url) +
            (attachment_score * self.w_attachment) +
            (sender_score     * self.w_sender) +
            (spam_score       * self.w_spam) +
            command_penalty
        )

        breakdown.final_score = min(raw, 1.0)

        # Determine decision
        if force_block:
            breakdown.decision = EmailPolicyDecision.BLOCK
        elif breakdown.final_score >= self.threshold_block:
            breakdown.decision = EmailPolicyDecision.BLOCK
        elif breakdown.final_score >= self.threshold_quarantine:
            breakdown.decision = EmailPolicyDecision.QUARANTINE
        else:
            breakdown.decision = EmailPolicyDecision.ALLOW

        logger.debug(
            "EmailRisk score=%.3f → %s (phish=%.2f url=%.2f attach=%.2f sender=%.2f spam=%.2f)",
            breakdown.final_score, breakdown.decision.value,
            phishing_score, url_score, attachment_score, sender_score, spam_score
        )

        return breakdown
