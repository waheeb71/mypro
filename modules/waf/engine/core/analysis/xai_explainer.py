"""
Enterprise CyberNexus — WAF Explainable AI (XAI)

Generates human-readable, SIEM-friendly explanations for Risk Scoring Engine decisions.
Simulates SHAP (SHapley Additive exPlanations) or LIME logic globally across the WAF.
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class WAFExplainer:
    """
    Transparent breakdown of why a request was blocked or challenged.
    """
    def __init__(self, explainer_type: str = "shap"):
        self.explainer_type = explainer_type

    def explain(self, breakdown) -> str:
        """
        Takes a RiskBreakdown object (or a dictionary representation) from the RiskScoringEngine
        and calculates the proportional contribution of each AI feature.
        """
        # Handle dict or dataclass seamlessly
        if hasattr(breakdown, "to_dict"):
            data = breakdown.to_dict()
        else:
            data = breakdown

        final_score = data.get("final_score", 0.0)
        
        if final_score == 0.0:
            return "Request appears completely benign."

        # Raw scores
        nlp   = data.get("nlp", 0.0)
        anom  = data.get("anomaly", 0.0)
        bot   = data.get("bot", 0.0)
        rep   = data.get("reputation", 0.0)
        hp    = data.get("honeypot", 0.0)

        # In a real model, we would extract the exact SHAP base values from xgboost here.
        # Since we use an ensemble weighting engine, the "explanation" is the proportional 
        # weight of each feature relative to the sum of triggers.
        factors = {
            "NLP Payload Attack": nlp,
            "Behavioral Anomaly": anom,
            "Bot Signature": bot,
            "IP Reputation": rep,
            "Deception/Honeypot": hp
        }

        # Filter out 0 impact vectors
        active_factors = {k: v for k, v in factors.items() if v > 0}
        
        if not active_factors:
            return f"Blocked via fallback mechanism (Risk={final_score:.2f})."
            
        total_active_weight = sum(active_factors.values())
        
        explanations = []
        for name, value in sorted(active_factors.items(), key=lambda item: item[1], reverse=True):
            if total_active_weight > 0:
                percentage = (value / total_active_weight) * 100
                if percentage >= 5.0: # Only list significant contributing factors
                    explanations.append(f"{percentage:.0f}% {name}")

        explanation_str = "XAI Attribution: " + " | ".join(explanations)
        return explanation_str
