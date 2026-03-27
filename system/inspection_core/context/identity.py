from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class IdentityContext:
    """Contains user identity information for Zero Trust enforcement."""
    type: str = "anonymous"  # user, device, anonymous
    source: str = "none"     # jwt, api_key, ip_mapping, device_fingerprint
    confidence: float = 0.0  # 0.0 to 1.0

    username: Optional[str] = None
    user_id: Optional[int] = None
    device_id: Optional[str] = None
    
    department: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    
    is_authenticated: bool = False
    auth_method: Optional[str] = None  # VPN, AD, JWT, Local
