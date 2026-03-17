import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class HTTPAnalyzer:
    """ High-speed HTTP request anomaly detection and deep header parsing """
    
    @staticmethod
    def parse_request_line(request_line: str) -> Dict[str, str]:
        parts = request_line.split()
        if len(parts) >= 3:
            return {
                "method": parts[0],
                "uri": parts[1],
                "version": parts[2]
            }
        return {"method": "", "uri": "", "version": ""}
        
    @staticmethod
    def extract_headers(header_lines: List[str]) -> Dict[str, str]:
        headers = {}
        for line in header_lines:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers
        
    @classmethod
    def analyze_request(cls, request_data: bytes) -> Dict[str, Any]:
        """ Analyzes standard HTTP request bytes for generic anomalies """
        result = {
            "is_anomalous": False,
            "risk_score": 0,
            "reasons": [],
            "method": "",
            "uri": "",
            "host": ""
        }
        
        try:
            req_str = request_data.decode('utf-8', errors='ignore')
            lines = req_str.split("\r\n")
            if not lines:
                return result
                
            req_line = cls.parse_request_line(lines[0])
            result["method"] = req_line["method"]
            result["uri"] = req_line["uri"]
            
            headers = cls.extract_headers(lines[1:])
            result["host"] = headers.get("host", "")
            
            # Anomaly checks
            # 1. Unusual User-Agent
            ua = headers.get("user-agent", "").lower()
            suspicious_uas = ["curl", "python", "nmap", "sqlmap", "nikto", "dirb"]
            if not ua or any(s in ua for s in suspicious_uas):
                result["is_anomalous"] = True
                result["risk_score"] += 30
                result["reasons"].append(f"Suspicious User-Agent: {ua[:20]}...")
                
            # 2. Huge URI
            if len(result["uri"]) > 1024:
                result["is_anomalous"] = True
                result["risk_score"] += 40
                result["reasons"].append("Extremely long URI (possible buffer overflow attempt)")
                
            # 3. Missing Host Header in HTTP/1.1
            if req_line["version"] == "HTTP/1.1" and not result["host"]:
                result["is_anomalous"] = True
                result["risk_score"] += 20
                result["reasons"].append("Missing required Host header")
                
            return result
            
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
            return result
