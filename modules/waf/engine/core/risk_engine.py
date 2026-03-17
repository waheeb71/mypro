"""
Enterprise NGFW — WAF Risk Scoring Engine

Combines scores from multiple AI models into a single Risk Score [0.0, 1.0]
and maps it to a policy decision: ALLOW / CHALLENGE / BLOCK.

Scoring formula
---------------
    risk = (
        nlp_score        * W_NLP        +   # NLP attack detection
        anomaly_score    * W_ANOMALY    +   # behavioral anomaly
        bot_score        * W_BOT        +   # bot detection
        reputation_score * W_REPUTATION +   # threat intelligence IP reputation
        honeypot_boost   * W_HONEYPOT       # honeypot trigger bonus
    )

All weights sum to 1.0.  Resulting risk is clamped to [0.0, 1.0].

Policy thresholds (default)
---------------------------
    risk < 0.30  → ALLOW
    risk < 0.60  → CHALLENGE (rate-limit / CAPTCHA)
    risk < 0.80  → SOFT_BLOCK (HTTP 429)
    risk ≥ 0.80  → BLOCK (HTTP 403 + session terminate)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Default weights  (sum = 1.0)
# ──────────────────────────────────────────────

W_NLP        = 0.35
W_ANOMALY    = 0.25
W_BOT        = 0.20
W_REPUTATION = 0.15
W_HONEYPOT   = 0.05


# ──────────────────────────────────────────────
#  Policy thresholds
# ──────────────────────────────────────────────

THRESHOLD_ALLOW     = 0.30
THRESHOLD_CHALLENGE = 0.60
THRESHOLD_SOFT_BLOCK = 0.80


# ──────────────────────────────────────────────
#  Data structures
# ──────────────────────────────────────────────

class PolicyDecision(str, Enum):
    ALLOW       = "allow"
    CHALLENGE   = "challenge"     # CAPTCHA / rate-limit
    SOFT_BLOCK  = "soft_block"   # HTTP 429
    BLOCK       = "block"        # HTTP 403 + blacklist


@dataclass
class RiskBreakdown:
    """Detailed breakdown of how the risk score was computed."""
    nlp_score:        float = 0.0
    anomaly_score:    float = 0.0
    bot_score:        float = 0.0
    reputation_score: float = 0.0
    honeypot_boost:   float = 0.0
    final_score:      float = 0.0
    decision:         PolicyDecision = PolicyDecision.ALLOW

    def to_dict(self) -> dict:
        return {
            "nlp":        round(self.nlp_score,        4),
            "anomaly":    round(self.anomaly_score,    4),
            "bot":        round(self.bot_score,        4),
            "reputation": round(self.reputation_score, 4),
            "honeypot":   round(self.honeypot_boost,   4),
            "final_score":round(self.final_score,      4),
            "decision":   self.decision.value,
        }


# ──────────────────────────────────────────────
#  RiskScoringEngine
# ──────────────────────────────────────────────

class RiskScoringEngine:
    """
    Weighted risk aggregator for the AI-WAF.

    All input scores must be in [0.0, 1.0] where:
      0.0 = completely safe
      1.0 = definite attack / malicious

    Args:
        w_nlp, w_anomaly, w_bot, w_reputation, w_honeypot:
            Custom weights (must sum to ≤ 1.0).
        threshold_allow, threshold_challenge, threshold_soft_block:
            Custom policy thresholds.
    """

    def __init__(
        self,
        w_nlp:          float = W_NLP,
        w_anomaly:      float = W_ANOMALY,
        w_bot:          float = W_BOT,
        w_reputation:   float = W_REPUTATION,
        w_honeypot:     float = W_HONEYPOT,
        threshold_allow:       float = THRESHOLD_ALLOW,
        threshold_challenge:   float = THRESHOLD_CHALLENGE,
        threshold_soft_block:  float = THRESHOLD_SOFT_BLOCK,
    ):
        self.w_nlp         = w_nlp
        self.w_anomaly     = w_anomaly
        self.w_bot         = w_bot
        self.w_reputation  = w_reputation
        self.w_honeypot    = w_honeypot

        self.threshold_allow      = threshold_allow
        self.threshold_challenge  = threshold_challenge
        self.threshold_soft_block = threshold_soft_block

    # ── Public API ──────────────────────────────

    def calculate(
        self,
        nlp_score:        float = 0.0,
        anomaly_score:    float = 0.0,
        bot_score:        float = 0.0,
        reputation_score: float = 0.0,
        honeypot_boost:   float = 0.0,
    ) -> RiskBreakdown:
        """
        Calculate the aggregated risk score and policy decision.

        Args:
            nlp_score:        0–1, from NLP attack detection model
            anomaly_score:    0–1, from behavioral anomaly detector
            bot_score:        0–1, from bot detection model
            reputation_score: 0–1, from threat intelligence (1 = known bad IP)
            honeypot_boost:   0–1, additional boost if honeypot was triggered

        Returns:
            RiskBreakdown with final_score and decision
        """
        # Clamp all inputs to [0, 1]
        nlp         = self._clamp(nlp_score)
        anomaly     = self._clamp(anomaly_score)
        bot         = self._clamp(bot_score)
        reputation  = self._clamp(reputation_score)
        honeypot    = self._clamp(honeypot_boost)

        score = (
            nlp        * self.w_nlp        +
            anomaly    * self.w_anomaly    +
            bot        * self.w_bot        +
            reputation * self.w_reputation +
            honeypot   * self.w_honeypot
        )

        # Normalize — in case weights don't exactly sum to 1.0
        weight_sum = (
            self.w_nlp + self.w_anomaly + self.w_bot +
            self.w_reputation + self.w_honeypot
        )
        if weight_sum > 0:
            score /= weight_sum

        score = self._clamp(score)

        decision = self._decide(score)

        breakdown = RiskBreakdown(
            nlp_score        = nlp,
            anomaly_score    = anomaly,
            bot_score        = bot,
            reputation_score = reputation,
            honeypot_boost   = honeypot,
            final_score      = score,
            decision         = decision,
        )

        logger.info(
            "RiskEngine: score=%.3f decision=%s [nlp=%.2f anom=%.2f bot=%.2f rep=%.2f hp=%.2f]",
            score, decision.value, nlp, anomaly, bot, reputation, honeypot
        )

        return breakdown

    def decide(self, risk_score: float) -> PolicyDecision:
        """Map a raw risk score to a PolicyDecision (standalone helper)."""
        return self._decide(self._clamp(risk_score))

    # ── Internals ──────────────────────────────

    def _decide(self, score: float) -> PolicyDecision:
        if score < self.threshold_allow:
            return PolicyDecision.ALLOW
        elif score < self.threshold_challenge:
            return PolicyDecision.CHALLENGE
        elif score < self.threshold_soft_block:
            return PolicyDecision.SOFT_BLOCK
        else:
            return PolicyDecision.BLOCK

    @staticmethod
    def _clamp(v: float) -> float:
        return max(0.0, min(1.0, float(v)))
