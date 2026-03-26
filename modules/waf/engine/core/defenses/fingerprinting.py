import logging
import hashlib
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class FingerprintResult:
    is_suspicious: bool
    risk_score: float = 0.0
    client_type: str = "unknown"
    ja3_hash: Optional[str] = None
    reason: Optional[str] = None

class AdvancedFingerprinting:
    """
    Client Fingerprinting Engine (JA3 / Header Order / Canvas mimicking).
    Detects bots that try to spoof User-Agents by analyzing deeper connection attributes.
    """

    # Known bad JA3 hashes for popular scripting tools (Requests, cURL, Go-http, etc) masquerading as browsers.
    # In a real system, this would be loaded from a Threat Intelligence feed or DB.
    SUSPICIOUS_JA3_HASHES = {
        "cd08e31494f9531f560d64c695473da9": "python-requests",
        "3b5074b1b5d032e5620f69f9f700ff0e": "curl", 
        "ca9be6e205ab04cbebe777f98fb6957a": "go-http-client",
        # ... massive DB of common script tools ...
    }

    # Common Browser Header Orders (Browsers almost always send headers in specific sorted orders)
    BROWSER_HEADER_ORDERS = {
        "chrome":  ["host", "connection", "sec-ch-ua", "sec-ch-ua-mobile"],
        "firefox": ["host", "user-agent", "accept", "accept-language"],
        "safari":  ["host", "accept", "user-agent", "accept-language"]
    }

    def __init__(self, check_ja3: bool = True, check_headers: bool = True):
        self.check_ja3 = check_ja3
        self.check_headers = check_headers
        logger.info("AdvancedFingerprinting initialized | JA3=%s, Headers=%s", self.check_ja3, self.check_headers)

    def analyze(self, 
                user_agent: str, 
                headers: Dict[str, str], 
                ja3_hash: Optional[str] = None, 
                ja4_hash: Optional[str] = None) -> FingerprintResult:
        """Analyze a client connection for spoofing and fingerprint anomalies."""
        
        score = 0.0
        reasons = []
        is_suspicious = False
        client_type = "unknown"
        
        ua_lower = user_agent.lower()
        if "chrome" in ua_lower:
            client_type = "chrome"
        elif "firefox" in ua_lower:
            client_type = "firefox"
        elif "safari" in ua_lower:
            client_type = "safari"

        # 1. Check TLS/SSL Fingerprints (JA3)
        if self.check_ja3 and ja3_hash:
            if ja3_hash in self.SUSPICIOUS_JA3_HASHES:
                tool_name = self.SUSPICIOUS_JA3_HASHES[ja3_hash]
                
                # If they are using Python Requests but claiming to be Chrome = MASSIVE RED FLAG
                if client_type in ["chrome", "firefox", "safari"]:
                     score += 0.90
                     reasons.append(f"JA3 indicates '{tool_name}' but User-Agent claims '{client_type}'")
                     is_suspicious = True
                else:
                     score += 0.40
                     reasons.append(f"JA3 indicates known script/bot tool '{tool_name}'")

        # 2. Check Header Ordering Anomalies
        if self.check_headers and client_type in self.BROWSER_HEADER_ORDERS:
             expected_order = self.BROWSER_HEADER_ORDERS[client_type]
             
             # Very naive order check: do the top N headers match the browser's typical structure?
             # Real implementation would use full sequence alignment.
             actual_ordered_keys = list(headers.keys())
             
             matching_top_headers = 0
             for expected in expected_order:
                 if expected in actual_ordered_keys[:10]: # Look in top 10 headers
                      matching_top_headers += 1
                      
             if matching_top_headers < len(expected_order) / 2:
                 # It claims to be Safari, but sends headers like a Python script
                 score += 0.60
                 reasons.append(f"Header order significantly deviates from claimed '{client_type}' browser profile")
                 is_suspicious = True

        # 3. Micro-anomalies
        if "accept-encoding" not in [k.lower() for k in headers.keys()] and client_type != "unknown":
            score += 0.30
            reasons.append("Real browsers always send Accept-Encoding, but it is missing")

        return FingerprintResult(
            is_suspicious=is_suspicious or (score >= 0.5),
            risk_score=min(1.0, score),
            client_type=client_type,
            ja3_hash=ja3_hash,
            reason=" | ".join(reasons) if reasons else None
        )
