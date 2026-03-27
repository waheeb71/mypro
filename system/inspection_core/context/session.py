from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SessionContext:
    """Contains environmental routing and session states."""
    geo_location: Optional[str] = None
    app_id: Optional[str] = None
    is_decrypted: bool = False      # True if handled by SSL Inspection
    original_sni: Optional[str] = None
    byte_count: int = 0
