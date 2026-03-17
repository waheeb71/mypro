import logging
from typing import Dict, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class URLCategory(BaseModel):
    domain: str
    category: str
    risk_score: int # 0-100

class URLChecker:
    """ Evaluates URLs against categorized lists and risk databases """
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self._domain_cache: Dict[str, URLCategory] = {}
        self._load_categories()
        
    def _load_categories(self):
        """ Basic cache pre-warm. In production, this uses an external service or redis. """
        self._domain_cache["malicious.com"] = URLCategory(domain="malicious.com", category="MALWARE", risk_score=95)
        self._domain_cache["gambling.net"] = URLCategory(domain="gambling.net", category="GAMBLING", risk_score=70)
        self._domain_cache["social.com"] = URLCategory(domain="social.com", category="SOCIAL", risk_score=20)
        self._domain_cache["news.org"] = URLCategory(domain="news.org", category="NEWS", risk_score=5)
        logger.debug(f"Loaded {len(self._domain_cache)} categorized domains.")

    def _extract_domain(self, url: str) -> str:
        if not url.startswith('http'):
            url = f"http://{url}"
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""

    def check_url(self, url: str) -> Tuple[str, str, int]:
        """
        Returns (action, category, risk_score)
        Action: ALLOW, BLOCK, WARN
        """
        domain = self._extract_domain(url)
        if not domain:
            return ("ALLOW", "UNKNOWN", 0)
            
        # Exact match
        if domain in self._domain_cache:
            cat = self._domain_cache[domain]
            action = "BLOCK" if cat.risk_score >= 70 else "ALLOW"
            return (action, cat.category, cat.risk_score)
            
        # Suffix matching
        parts = domain.split(".")
        for i in range(len(parts)-1):
            sub_domain = ".".join(parts[i:])
            if sub_domain in self._domain_cache:
                cat = self._domain_cache[sub_domain]
                action = "BLOCK" if cat.risk_score >= 70 else "ALLOW"
                return (action, cat.category, cat.risk_score)
                
        return ("ALLOW", "UNCATEGORIZED", 0)
