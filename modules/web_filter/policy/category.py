"""
Enterprise NGFW v2.0 - Category Engine
Content category-based blocking.
"""

import logging
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import IntEnum
import threading
from collections import defaultdict

logger = logging.getLogger(__name__)

class ContentCategory(IntEnum):
    # Security
    MALWARE = 1
    PHISHING = 2
    # Adult
    ADULT_EXPLICIT = 20
    # Social
    SOCIAL_NETWORKING = 70
    # Streaming
    VIDEO_STREAMING = 60
    # Unrated
    UNRATED = 190

@dataclass
class CategoryMatch:
    domain: str
    categories: List[ContentCategory]
    confidence: float = 1.0

class CategoryEngine:
    """Content category-based blocking system"""
    
    def __init__(self):
        self._category_patterns: Dict[ContentCategory, List[re.Pattern]] = {}
        self._blocked_categories: Set[ContentCategory] = set()
        self._domain_cache: Dict[str, CategoryMatch] = {}
        self._lock = threading.RLock()
        self._init_default_patterns()
        
    def _init_default_patterns(self):
        # Simplified default patterns
        self._add_patterns(ContentCategory.MALWARE, [r'.*malware.*', r'.*virus.*'])
        self._add_patterns(ContentCategory.PHISHING, [r'.*-verify\..*', r'.*paypal-.*'])
        self._add_patterns(ContentCategory.ADULT_EXPLICIT, [r'.*porn.*', r'.*xxx.*'])
        self._add_patterns(ContentCategory.SOCIAL_NETWORKING, [r'.*facebook.*', r'.*twitter.*'])
        self._add_patterns(ContentCategory.VIDEO_STREAMING, [r'.*youtube.*', r'.*netflix.*'])

    def _add_patterns(self, category: ContentCategory, patterns: List[str]):
        if category not in self._category_patterns:
            self._category_patterns[category] = []
        for p in patterns:
            self._category_patterns[category].append(re.compile(p, re.IGNORECASE))

    def categorize(self, domain: str) -> CategoryMatch:
        if domain in self._domain_cache:
            return self._domain_cache[domain]
            
        categories = []
        for cat, patterns in self._category_patterns.items():
            for p in patterns:
                if p.search(domain):
                    categories.append(cat)
                    break
        
        match = CategoryMatch(domain, categories if categories else [ContentCategory.UNRATED])
        self._domain_cache[domain] = match
        return match

    def is_blocked(self, domain: str) -> bool:
        match = self.categorize(domain)
        with self._lock:
            for cat in match.categories:
                if cat in self._blocked_categories:
                    return True
        return False
        
    def block_category(self, category: ContentCategory):
        self._blocked_categories.add(category)
