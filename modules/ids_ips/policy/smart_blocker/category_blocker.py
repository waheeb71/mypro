"""
Enterprise NGFW v2.0 - Category Blocker

Content category-based blocking with 90+ predefined categories.

Features:
- 90+ content categories (adult, gambling, malware, etc.)
- Domain categorization with caching
- Category-based policies
- Custom category definitions
- Multi-category matching

Author: Enterprise NGFW Team
License: Proprietary
"""

import logging
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import IntEnum
import threading
from collections import defaultdict


class ContentCategory(IntEnum):
    """
    Content categories (90+ categories).
    
    Organized by risk level and content type.
    """
    # High Risk - Security Threats
    MALWARE = 1
    PHISHING = 2
    SPYWARE = 3
    BOTNETS = 4
    RANSOMWARE = 5
    CRYPTOJACKING = 6
    COMMAND_CONTROL = 7
    EXPLOIT_KITS = 8
    
    # High Risk - Illegal Content
    CHILD_ABUSE = 10
    ILLEGAL_DRUGS = 11
    ILLEGAL_WEAPONS = 12
    TERRORISM = 13
    HATE_SPEECH = 14
    FRAUD = 15
    
    # Adult Content
    ADULT_EXPLICIT = 20
    ADULT_LINGERIE = 21
    ADULT_DATING = 22
    ADULT_SWIMWEAR = 23
    
    # Gambling
    GAMBLING_CASINO = 30
    GAMBLING_SPORTS = 31
    GAMBLING_LOTTERY = 32
    GAMBLING_POKER = 33
    
    # Suspicious/Anonymous
    ANONYMIZERS = 40
    VPN_SERVICES = 41
    TOR_NODES = 42
    PROXY_SERVICES = 43
    DYNAMIC_DNS = 44
    URL_SHORTENERS = 45
    
    # File Sharing
    P2P_FILESHARING = 50
    TORRENT_SITES = 51
    FILE_STORAGE = 52
    
    # Streaming/Entertainment
    VIDEO_STREAMING = 60
    MUSIC_STREAMING = 61
    GAMING_ONLINE = 62
    GAMING_DOWNLOADS = 63
    
    # Social Media
    SOCIAL_NETWORKING = 70
    INSTANT_MESSAGING = 71
    FORUMS_BOARDS = 72
    BLOGS = 73
    MICROBLOGGING = 74
    DATING_SITES = 75
    
    # Productivity Drains
    WEBMAIL = 80
    WEB_CHAT = 81
    MEME_SITES = 82
    ENTERTAINMENT_NEWS = 83
    CELEBRITY_GOSSIP = 84
    
    # Shopping
    ECOMMERCE = 90
    AUCTIONS = 91
    CLASSIFIEDS = 92
    REAL_ESTATE = 93
    
    # News/Information
    NEWS_GENERAL = 100
    NEWS_BUSINESS = 101
    NEWS_SPORTS = 102
    NEWS_POLITICS = 103
    REFERENCE_SITES = 104
    SEARCH_ENGINES = 105
    
    # Business/Professional
    BUSINESS_SERVICES = 110
    FINANCIAL_SERVICES = 111
    BANKING = 112
    STOCK_TRADING = 113
    INSURANCE = 114
    
    # Education
    EDUCATION_GENERAL = 120
    UNIVERSITIES = 121
    K12_SCHOOLS = 122
    ONLINE_LEARNING = 123
    EDUCATIONAL_GAMES = 124
    
    # Technology
    SOFTWARE_DOWNLOADS = 130
    TECH_NEWS = 131
    DEVELOPER_TOOLS = 132
    HOSTING_SERVICES = 133
    CLOUD_SERVICES = 134
    
    # Government/Legal
    GOVERNMENT = 140
    MILITARY = 141
    LEGAL_SERVICES = 142
    
    # Health
    HEALTH_MEDICAL = 150
    PHARMACEUTICALS = 151
    ALTERNATIVE_MEDICINE = 152
    HEALTHCARE_PROVIDERS = 153
    
    # Lifestyle
    TRAVEL = 160
    RESTAURANTS = 161
    FASHION = 162
    HOME_GARDEN = 163
    AUTOMOTIVE = 164
    SPORTS_RECREATION = 165
    
    # Religion/Ideology
    RELIGION = 170
    POLITICAL_ADVOCACY = 171
    
    # Advertising
    ADVERTISING = 180
    AD_NETWORKS = 181
    ANALYTICS_TRACKING = 182
    
    # Unrated/Unknown
    UNRATED = 190
    NEWLY_REGISTERED = 191
    PARKED_DOMAINS = 192
    SUSPICIOUS_NEW = 193
    
    # Infrastructure
    CDN_SERVICES = 200
    DNS_SERVICES = 201
    WEB_INFRASTRUCTURE = 202


# Category risk levels
CATEGORY_RISK_LEVELS = {
    # Critical Risk
    ContentCategory.MALWARE: 'CRITICAL',
    ContentCategory.PHISHING: 'CRITICAL',
    ContentCategory.RANSOMWARE: 'CRITICAL',
    ContentCategory.CHILD_ABUSE: 'CRITICAL',
    ContentCategory.TERRORISM: 'CRITICAL',
    
    # High Risk
    ContentCategory.SPYWARE: 'HIGH',
    ContentCategory.BOTNETS: 'HIGH',
    ContentCategory.COMMAND_CONTROL: 'HIGH',
    ContentCategory.EXPLOIT_KITS: 'HIGH',
    ContentCategory.ILLEGAL_DRUGS: 'HIGH',
    ContentCategory.ILLEGAL_WEAPONS: 'HIGH',
    ContentCategory.FRAUD: 'HIGH',
    ContentCategory.CRYPTOJACKING: 'HIGH',
    
    # Medium Risk
    ContentCategory.ADULT_EXPLICIT: 'MEDIUM',
    ContentCategory.GAMBLING_CASINO: 'MEDIUM',
    ContentCategory.ANONYMIZERS: 'MEDIUM',
    ContentCategory.TOR_NODES: 'MEDIUM',
    ContentCategory.P2P_FILESHARING: 'MEDIUM',
    ContentCategory.TORRENT_SITES: 'MEDIUM',
    
    # Low Risk (productivity concerns)
    ContentCategory.SOCIAL_NETWORKING: 'LOW',
    ContentCategory.VIDEO_STREAMING: 'LOW',
    ContentCategory.GAMING_ONLINE: 'LOW',
    ContentCategory.WEBMAIL: 'LOW',
}


@dataclass
class CategoryMatch:
    """Result of category matching"""
    domain: str
    categories: List[ContentCategory]
    risk_level: str  # CRITICAL/HIGH/MEDIUM/LOW/SAFE
    matched_patterns: List[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0-1.0


class CategoryBlocker:
    """
    Content category-based blocking system.
    
    Features:
    - 90+ predefined categories
    - Pattern-based categorization
    - Category blocking policies
    - Multi-category domains
    - Risk-based decisions
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Category patterns (domain regex patterns)
        self._category_patterns: Dict[ContentCategory, List[re.Pattern]] = {}
        
        # Blocked categories
        self._blocked_categories: Set[ContentCategory] = set()
        
        # Domain cache
        self._domain_cache: Dict[str, CategoryMatch] = {}
        
        # Statistics
        self._categorization_count = 0
        self._blocked_count = 0
        self._category_hits: Dict[ContentCategory, int] = defaultdict(int)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize default patterns
        self._init_default_patterns()
        
    def _init_default_patterns(self):
        """Initialize default category patterns"""
        # Malware/Security Threats
        self._add_patterns(ContentCategory.MALWARE, [
            r'.*malware.*', r'.*virus.*', r'.*trojan.*', r'.*worm\d*\..*'
        ])
        
        self._add_patterns(ContentCategory.PHISHING, [
            r'.*-verify\..*', r'.*-secure\..*', r'.*-account\..*',
            r'.*paypal-.*', r'.*amazon-.*', r'.*bank-.*'
        ])
        
        self._add_patterns(ContentCategory.RANSOMWARE, [
            r'.*ransom.*', r'.*crypt\d+\..*', r'.*locker.*'
        ])
        
        self._add_patterns(ContentCategory.BOTNETS, [
            r'.*botnet.*', r'.*c2-.*', r'.*cnc\..*'
        ])
        
        # Adult Content
        self._add_patterns(ContentCategory.ADULT_EXPLICIT, [
            r'.*porn.*', r'.*xxx.*', r'.*sex.*', r'.*adult.*',
            r'.*nude.*', r'.*erotic.*'
        ])
        
        # Gambling
        self._add_patterns(ContentCategory.GAMBLING_CASINO, [
            r'.*casino.*', r'.*slots.*', r'.*gambling.*', r'.*bet.*'
        ])
        
        self._add_patterns(ContentCategory.GAMBLING_POKER, [
            r'.*poker.*', r'.*blackjack.*'
        ])
        
        # Anonymizers
        self._add_patterns(ContentCategory.ANONYMIZERS, [
            r'.*anonymizer.*', r'.*hide(my)?ip.*', r'.*proxy.*'
        ])
        
        self._add_patterns(ContentCategory.VPN_SERVICES, [
            r'.*vpn.*', r'.*nordvpn.*', r'.*expressvpn.*'
        ])
        
        self._add_patterns(ContentCategory.TOR_NODES, [
            r'.*\.onion$', r'.*tor-.*', r'.*torproject.*'
        ])
        
        # File Sharing
        self._add_patterns(ContentCategory.TORRENT_SITES, [
            r'.*torrent.*', r'.*thepiratebay.*', r'.*1337x.*'
        ])
        
        self._add_patterns(ContentCategory.P2P_FILESHARING, [
            r'.*p2p.*', r'.*filesharing.*'
        ])
        
        # Social Media
        self._add_patterns(ContentCategory.SOCIAL_NETWORKING, [
            r'.*facebook.*', r'.*twitter.*', r'.*instagram.*',
            r'.*linkedin.*', r'.*tiktok.*', r'.*snapchat.*'
        ])
        
        self._add_patterns(ContentCategory.INSTANT_MESSAGING, [
            r'.*whatsapp.*', r'.*telegram.*', r'.*discord.*',
            r'.*slack.*', r'.*messenger.*'
        ])
        
        # Streaming
        self._add_patterns(ContentCategory.VIDEO_STREAMING, [
            r'.*youtube.*', r'.*netflix.*', r'.*hulu.*',
            r'.*twitch.*', r'.*vimeo.*'
        ])
        
        self._add_patterns(ContentCategory.MUSIC_STREAMING, [
            r'.*spotify.*', r'.*soundcloud.*', r'.*pandora.*'
        ])
        
        # Gaming
        self._add_patterns(ContentCategory.GAMING_ONLINE, [
            r'.*steam.*', r'.*epicgames.*', r'.*battlenet.*',
            r'.*origin\..*', r'.*roblox.*'
        ])
        
        # URL Shorteners
        self._add_patterns(ContentCategory.URL_SHORTENERS, [
            r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',
            r'ow\.ly', r'is\.gd'
        ])
        
        # Dynamic DNS
        self._add_patterns(ContentCategory.DYNAMIC_DNS, [
            r'.*\.dyndns\..*', r'.*\.no-ip\..*', r'.*\.ddns\..*'
        ])
        
        # Cloud Services
        self._add_patterns(ContentCategory.CLOUD_SERVICES, [
            r'.*\.s3\.amazonaws\.com', r'.*\.blob\.core\.windows\.net',
            r'.*drive\.google\.com', r'.*dropbox.*'
        ])
        
        # Ad Networks
        self._add_patterns(ContentCategory.AD_NETWORKS, [
            r'.*doubleclick.*', r'.*adsense.*', r'.*adserver.*',
            r'.*ads\..*'
        ])
        
        self._add_patterns(ContentCategory.ANALYTICS_TRACKING, [
            r'.*analytics.*', r'.*tracking.*', r'.*pixel.*'
        ])
        
        self.logger.info(f"Initialized {len(self._category_patterns)} category patterns")
        
    def _add_patterns(self, category: ContentCategory, patterns: List[str]):
        """Add regex patterns for a category"""
        if category not in self._category_patterns:
            self._category_patterns[category] = []
            
        for pattern in patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._category_patterns[category].append(compiled)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                
    def categorize_domain(self, domain: str) -> CategoryMatch:
        """
        Categorize a domain into content categories.
        
        Args:
            domain: Domain name
            
        Returns:
            CategoryMatch with matched categories
        """
        domain = domain.lower()
        
        # Check cache
        with self._lock:
            if domain in self._domain_cache:
                return self._domain_cache[domain]
                
            self._categorization_count += 1
            
        # Match against patterns
        matched_categories = []
        matched_patterns = []
        
        for category, patterns in self._category_patterns.items():
            for pattern in patterns:
                if pattern.search(domain):
                    matched_categories.append(category)
                    matched_patterns.append(pattern.pattern)
                    with self._lock:
                        self._category_hits[category] += 1
                    break  # One match per category
                    
        # Determine risk level
        if matched_categories:
            risk_level = self._get_highest_risk(matched_categories)
        else:
            matched_categories = [ContentCategory.UNRATED]
            risk_level = 'UNKNOWN'
            
        result = CategoryMatch(
            domain=domain,
            categories=matched_categories,
            risk_level=risk_level,
            matched_patterns=matched_patterns,
            confidence=1.0 if matched_categories else 0.5
        )
        
        # Cache result
        with self._lock:
            self._domain_cache[domain] = result
            
        return result
        
    def _get_highest_risk(self, categories: List[ContentCategory]) -> str:
        """Get highest risk level from categories"""
        risk_priority = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']
        
        for risk in risk_priority:
            for cat in categories:
                if CATEGORY_RISK_LEVELS.get(cat) == risk:
                    return risk
                    
        return 'UNKNOWN'
        
    def is_blocked(self, domain: str) -> tuple[bool, Optional[str]]:
        """
        Check if domain should be blocked based on categories.
        
        Args:
            domain: Domain name
            
        Returns:
            (is_blocked, reason) tuple
        """
        match = self.categorize_domain(domain)
        
        with self._lock:
            for category in match.categories:
                if category in self._blocked_categories:
                    self._blocked_count += 1
                    reason = f"Category {category.name} blocked"
                    self.logger.info(f"Blocked {domain}: {reason}")
                    return True, reason
                    
        return False, None
        
    def block_category(self, category: ContentCategory) -> None:
        """Add category to block list"""
        with self._lock:
            self._blocked_categories.add(category)
            self.logger.info(f"Blocking category: {category.name}")
            
    def unblock_category(self, category: ContentCategory) -> None:
        """Remove category from block list"""
        with self._lock:
            self._blocked_categories.discard(category)
            self.logger.info(f"Unblocked category: {category.name}")
            
    def block_risk_level(self, risk_level: str) -> None:
        """Block all categories of a risk level"""
        risk_level = risk_level.upper()
        
        with self._lock:
            for category, level in CATEGORY_RISK_LEVELS.items():
                if level == risk_level:
                    self._blocked_categories.add(category)
                    
        self.logger.info(f"Blocked all {risk_level} risk categories")
        
    def add_custom_pattern(
        self,
        category: ContentCategory,
        pattern: str
    ) -> bool:
        """Add custom pattern for a category"""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            
            with self._lock:
                if category not in self._category_patterns:
                    self._category_patterns[category] = []
                self._category_patterns[category].append(compiled)
                
                # Clear cache to re-categorize
                self._domain_cache.clear()
                
            self.logger.info(f"Added custom pattern to {category.name}: {pattern}")
            return True
            
        except re.error as e:
            self.logger.error(f"Invalid pattern '{pattern}': {e}")
            return False
            
    def get_top_categories(self, n: int = 10) -> List[tuple[ContentCategory, int]]:
        """Get top N categories by hits"""
        with self._lock:
            sorted_categories = sorted(
                self._category_hits.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_categories[:n]
            
    def get_statistics(self) -> Dict:
        """Get category blocker statistics"""
        with self._lock:
            return {
                'total_categorizations': self._categorization_count,
                'total_blocked': self._blocked_count,
                'blocked_categories_count': len(self._blocked_categories),
                'cached_domains': len(self._domain_cache),
                'total_patterns': sum(len(p) for p in self._category_patterns.values()),
                'unique_categories_hit': len(self._category_hits)
            }
            
    def get_blocked_categories(self) -> List[str]:
        """Get list of currently blocked categories"""
        with self._lock:
            return [cat.name for cat in self._blocked_categories]
            
    def clear_cache(self) -> None:
        """Clear domain categorization cache"""
        with self._lock:
            self._domain_cache.clear()
            self.logger.info("Cleared category cache")