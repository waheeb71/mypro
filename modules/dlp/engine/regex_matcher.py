import re
from typing import List, Dict

class RegexMatcher:
    PATTERNS = {
        "CREDIT_CARD": r"\b(?:\d{4}[ -]?){3}(?:\d{4}|\d{3})\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "PHONE_US": r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b",
        "IBAN": r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9a-zA-Z]{4}){3,7}(?:[ ]?[0-9a-zA-Z]{1,3})?\b"
    }
    
    PATTERNS_COMPILED = {k: re.compile(v) for k, v in PATTERNS.items()}
    
    @classmethod
    def scan_text(cls, text: str) -> List[Dict[str, str]]:
        findings = []
        for p_name, p_regex in cls.PATTERNS_COMPILED.items():
            matches = p_regex.findall(text)
            for match in matches:
                # If tuple (contains groups), join them or use string representation
                match_str = "".join(match) if isinstance(match, tuple) else str(match)
                
                # Basic masking for reporting
                masked = match_str[:4] + "****" + match_str[-4:] if len(match_str) > 8 else "***"
                
                findings.append({
                    "type": p_name,
                    "value_masked": masked
                })
        return findings
