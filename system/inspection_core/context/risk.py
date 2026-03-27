from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class RiskContext:
    """Contains anomaly scores and threat intelligence context."""
    uba_score: float = 0.0          # 0.0 to 1.0
    threat_intel_score: float = 0.0 # 0.0 to 1.0
    is_compromised: bool = False
    risk_factors: list = field(default_factory=list)
    recent_anomalies: Dict[str, Any] = field(default_factory=dict)
