"""
Router Types
Data classes and Enums for traffic routing.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional

class ProxyMode(Enum):
    """Proxy operation modes"""
    FORWARD = "forward"           # Explicit proxy
    TRANSPARENT = "transparent"   # Gateway mode
    REVERSE = "reverse"           # Web server protection
    HYBRID = "hybrid"             # Mixed mode

@dataclass
class RoutingDecision:
    """Routing decision for a connection"""
    mode: ProxyMode
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    ssl_inspection: bool = True
    policy_id: Optional[str] = None
    metadata: dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def __repr__(self):
        return (f"RoutingDecision(mode={self.mode.value}, "
                f"target={self.target_host}:{self.target_port}, "
                f"ssl_inspection={self.ssl_inspection})")
