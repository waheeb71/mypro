"""
Application Signatures
Database of application signatures for DPI.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import re

@dataclass
class AppSignature:
    app_id: str
    name: str
    category: str
    patterns: List[str]  # Regex or Byte patterns
    ports: List[int]

class EncryptedAppSignatures:
    """Signatures for encrypted traffic (SNI/Cert based)"""
    SIGNATURES = {
        "facebook": ["facebook.com", "fbcdn.net"],
        "whatsapp": ["whatsapp.com", "whatsapp.net"],
        "youtube": ["youtube.com", "googlevideo.com"],
        "netflix": ["netflix.com", "nflxvideo.net"],
        "tiktok": ["tiktok.com", "tiktokv.com", "byteoversea.com"],
        "zoom": ["zoom.us", "zoom.com"],
    }
    
    @staticmethod
    def identify_by_sni(sni: str) -> Optional[str]:
        for app, domains in EncryptedAppSignatures.SIGNATURES.items():
            for domain in domains:
                if sni.endswith(domain):
                    return app
        return None
