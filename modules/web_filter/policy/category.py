"""
Enterprise CyberNexus v2.0 - Category Engine
Content category-based blocking using database backend.
"""

import logging
import fnmatch
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import threading
from system.database.database import SessionLocal
from modules.web_filter.models import WebFilterCategory, WebFilterDomain

logger = logging.getLogger(__name__)

@dataclass
class CategoryMatch:
    domain: str
    categories: List[str]
    confidence: float = 1.0

class CategoryEngine:
    """Content category-based blocking system (DB backed, in-memory cache)"""
    
    def __init__(self):
        self._exact_domains: Dict[str, str] = {} # domain -> category_name
        self._wildcard_domains: Dict[str, str] = {} # pattern -> category_name
        self._category_actions: Dict[str, str] = {} # category_name -> action
        self._category_risks: Dict[str, int] = {}
        
        self._domain_cache: Dict[str, CategoryMatch] = {}
        self._lock = threading.RLock()
        self.reload()
        
    def reload(self):
        """Reload categories and domains from the database"""
        with self._lock:
            with SessionLocal() as db:
                cats = db.query(WebFilterCategory).all()
                self._category_actions = {c.name: c.action for c in cats}
                self._category_risks = {c.name: c.risk_score for c in cats}
                
                domains = db.query(WebFilterDomain).all()
                self._exact_domains.clear()
                self._wildcard_domains.clear()
                self._domain_cache.clear()
                
                for d in domains:
                    if '*' in d.domain_pattern or '?' in d.domain_pattern:
                        self._wildcard_domains[d.domain_pattern] = d.category_name
                    else:
                        self._exact_domains[d.domain_pattern] = d.category_name
            
            logger.info(f"CategoryEngine reloaded: {len(self._exact_domains)} exact domains, {len(self._wildcard_domains)} wildcards.")

    def categorize(self, domain: str) -> CategoryMatch:
        if domain in self._domain_cache:
            return self._domain_cache[domain]
            
        with self._lock:
            # 1. Exact match
            if domain in self._exact_domains:
                cat = self._exact_domains[domain]
                match = CategoryMatch(domain, [cat] if cat else ["UNRATED"])
                self._domain_cache[domain] = match
                return match
                
            # 2. Suffix exact match (e.g. www.example.com -> example.com)
            parts = domain.split(".")
            for i in range(len(parts)-1):
                sub_domain = ".".join(parts[i:])
                if sub_domain in self._exact_domains:
                    cat = self._exact_domains[sub_domain]
                    match = CategoryMatch(domain, [cat] if cat else ["UNRATED"])
                    self._domain_cache[domain] = match
                    return match
            
            # 3. Wildcard match
            for pattern, cat in self._wildcard_domains.items():
                if fnmatch.fnmatch(domain, pattern):
                    match = CategoryMatch(domain, [cat] if cat else ["UNRATED"])
                    self._domain_cache[domain] = match
                    return match
                    
            match = CategoryMatch(domain, ["UNRATED"])
            self._domain_cache[domain] = match
            return match

    def get_category_action(self, category_name: str) -> str:
        return self._category_actions.get(category_name, "ALLOW")
        
    def get_category_risk(self, category_name: str) -> int:
        return self._category_risks.get(category_name, 0)
