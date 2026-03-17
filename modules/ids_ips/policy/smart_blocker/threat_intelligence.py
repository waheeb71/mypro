"""
Enterprise NGFW v2.0 - Threat Intelligence

Integration with threat intelligence feeds for real-time threat detection.

Features:
- Multiple threat feed sources
- IP/domain/URL threat lookups
- Threat severity scoring
- Feed aggregation and deduplication
- Automatic feed updates
- IOC (Indicators of Compromise) matching

Author: Enterprise NGFW Team
License: Proprietary
"""

import logging
import time
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
import threading
from datetime import datetime, timedelta


class ThreatLevel(IntEnum):
    """Threat severity levels"""
    CRITICAL = 5   # Active threat, immediate action
    HIGH = 4       # Known malicious, block
    MEDIUM = 3     # Suspicious, monitor
    LOW = 2        # Potentially unwanted
    INFO = 1       # Informational
    SAFE = 0       # Known safe


class ThreatType(IntEnum):
    """Types of threats"""
    MALWARE = 1
    PHISHING = 2
    BOTNET = 3
    C2_SERVER = 4
    EXPLOIT = 5
    RANSOMWARE = 6
    CRYPTOMINER = 7
    SPAM_SOURCE = 8
    SCANNER = 9
    BRUTE_FORCE = 10
    DDoS_SOURCE = 11
    TOR_EXIT = 12
    SUSPICIOUS = 13


@dataclass
class ThreatIndicator:
    """Threat indicator (IOC)"""
    indicator: str  # IP, domain, or URL
    indicator_type: str  # 'ip', 'domain', 'url', 'hash'
    threat_level: ThreatLevel
    threat_types: List[ThreatType]
    source: str  # Feed source name
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 1.0  # 0.0-1.0
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    @property
    def age_hours(self) -> float:
        """Get age of indicator in hours"""
        return (time.time() - self.first_seen) / 3600
        
    @property
    def is_fresh(self, max_age_hours: int = 24) -> bool:
        """Check if indicator is fresh"""
        return self.age_hours < max_age_hours


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration"""
    name: str
    url: str
    feed_type: str  # 'ip', 'domain', 'url', 'mixed'
    update_interval: int = 3600  # seconds
    enabled: bool = True
    last_update: float = 0.0
    indicator_count: int = 0
    error_count: int = 0


class ThreatIntelligence:
    """
    Threat intelligence feed aggregator and query engine.
    
    Features:
    - Multiple feed source support
    - Real-time threat lookups
    - Automatic feed updates
    - Deduplication and aggregation
    - Confidence scoring
    """
    
    def __init__(
        self,
        max_indicators: int = 1000000,
        max_age_hours: int = 168,  # 7 days
        logger: Optional[logging.Logger] = None
    ):
        self.max_indicators = max_indicators
        self.max_age_hours = max_age_hours
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Threat indicators
        self._ip_indicators: Dict[str, ThreatIndicator] = {}
        self._domain_indicators: Dict[str, ThreatIndicator] = {}
        self._url_indicators: Dict[str, ThreatIndicator] = {}
        self._hash_indicators: Dict[str, ThreatIndicator] = {}
        
        # Feed configuration
        self._feeds: Dict[str, ThreatFeed] = {}
        
        # Statistics
        self._lookups = 0
        self._hits = 0
        self._misses = 0
        self._threat_type_hits: Dict[ThreatType, int] = defaultdict(int)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize default feeds
        self._init_default_feeds()
        
    def _init_default_feeds(self):
        """Initialize default threat intelligence feeds"""
        default_feeds = [
            ThreatFeed(
                name="abuse.ch_urlhaus",
                url="https://urlhaus.abuse.ch/downloads/csv_recent/",
                feed_type="url",
                update_interval=3600
            ),
            ThreatFeed(
                name="abuse.ch_feodotracker",
                url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                feed_type="ip",
                update_interval=3600
            ),
            ThreatFeed(
                name="blocklist.de",
                url="https://lists.blocklist.de/lists/all.txt",
                feed_type="ip",
                update_interval=3600
            ),
            ThreatFeed(
                name="tor_exit_nodes",
                url="https://check.torproject.org/exit-addresses",
                feed_type="ip",
                update_interval=7200
            ),
            ThreatFeed(
                name="phishtank",
                url="https://data.phishtank.com/data/online-valid.csv",
                feed_type="url",
                update_interval=3600
            )
        ]
        
        for feed in default_feeds:
            self._feeds[feed.name] = feed
            
        self.logger.info(f"Initialized {len(self._feeds)} default threat feeds")
        
    def add_indicator(
        self,
        indicator: str,
        indicator_type: str,
        threat_level: ThreatLevel,
        threat_types: List[ThreatType],
        source: str,
        confidence: float = 1.0,
        description: str = "",
        tags: Optional[List[str]] = None
    ) -> bool:
        """
        Add threat indicator to database.
        
        Args:
            indicator: IP, domain, URL, or hash
            indicator_type: Type of indicator
            threat_level: Severity level
            threat_types: List of threat types
            source: Source feed name
            confidence: Confidence score (0.0-1.0)
            description: Optional description
            tags: Optional tags
            
        Returns:
            True if added successfully
        """
        try:
            with self._lock:
                # Select storage based on type
                if indicator_type == 'ip':
                    storage = self._ip_indicators
                elif indicator_type == 'domain':
                    storage = self._domain_indicators
                    indicator = indicator.lower()
                elif indicator_type == 'url':
                    storage = self._url_indicators
                elif indicator_type == 'hash':
                    storage = self._hash_indicators
                else:
                    self.logger.error(f"Unknown indicator type: {indicator_type}")
                    return False
                    
                # Check if indicator exists
                if indicator in storage:
                    # Update existing
                    existing = storage[indicator]
                    existing.last_seen = time.time()
                    existing.confidence = max(existing.confidence, confidence)
                    
                    # Merge threat types
                    for tt in threat_types:
                        if tt not in existing.threat_types:
                            existing.threat_types.append(tt)
                            
                    # Update threat level if higher
                    if threat_level > existing.threat_level:
                        existing.threat_level = threat_level
                        
                else:
                    # Add new indicator
                    storage[indicator] = ThreatIndicator(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        threat_level=threat_level,
                        threat_types=threat_types,
                        source=source,
                        confidence=confidence,
                        description=description,
                        tags=tags or []
                    )
                    
                # Enforce max indicators limit
                if len(storage) > self.max_indicators:
                    self._evict_old_indicators(storage)
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add indicator: {e}")
            return False
            
    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Lookup threat information for IP"""
        with self._lock:
            self._lookups += 1
            
            indicator = self._ip_indicators.get(ip)
            
            if indicator:
                self._hits += 1
                for tt in indicator.threat_types:
                    self._threat_type_hits[tt] += 1
            else:
                self._misses += 1
                
            return indicator
            
    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Lookup threat information for domain"""
        domain = domain.lower()
        
        with self._lock:
            self._lookups += 1
            
            # Check exact match
            indicator = self._domain_indicators.get(domain)
            
            if not indicator:
                # Check parent domains
                indicator = self._lookup_parent_domain(domain)
                
            if indicator:
                self._hits += 1
                for tt in indicator.threat_types:
                    self._threat_type_hits[tt] += 1
            else:
                self._misses += 1
                
            return indicator
            
    def _lookup_parent_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check if parent domain is in threat database"""
        parts = domain.split('.')
        
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self._domain_indicators:
                return self._domain_indicators[parent]
                
        return None
        
    def lookup_url(self, url: str) -> Optional[ThreatIndicator]:
        """Lookup threat information for URL"""
        with self._lock:
            self._lookups += 1
            
            # Check exact match
            indicator = self._url_indicators.get(url)
            
            # Check URL hash
            if not indicator:
                url_hash = hashlib.sha256(url.encode()).hexdigest()
                indicator = self._hash_indicators.get(url_hash)
                
            if indicator:
                self._hits += 1
                for tt in indicator.threat_types:
                    self._threat_type_hits[tt] += 1
            else:
                self._misses += 1
                
            return indicator
            
    def is_threat(
        self,
        indicator: str,
        indicator_type: str,
        min_level: ThreatLevel = ThreatLevel.MEDIUM
    ) -> Tuple[bool, Optional[ThreatIndicator]]:
        """
        Check if indicator is a threat.
        
        Args:
            indicator: IP, domain, or URL
            indicator_type: Type of indicator
            min_level: Minimum threat level to consider
            
        Returns:
            (is_threat, threat_info) tuple
        """
        # Lookup based on type
        if indicator_type == 'ip':
            info = self.lookup_ip(indicator)
        elif indicator_type == 'domain':
            info = self.lookup_domain(indicator)
        elif indicator_type == 'url':
            info = self.lookup_url(indicator)
        else:
            return False, None
            
        if info and info.threat_level >= min_level:
            return True, info
            
        return False, info
        
    def add_feed(self, feed: ThreatFeed) -> None:
        """Add threat intelligence feed"""
        with self._lock:
            self._feeds[feed.name] = feed
            self.logger.info(f"Added threat feed: {feed.name}")
            
    def remove_feed(self, feed_name: str) -> None:
        """Remove threat intelligence feed"""
        with self._lock:
            if feed_name in self._feeds:
                del self._feeds[feed_name]
                self.logger.info(f"Removed threat feed: {feed_name}")
                
    def update_feed(self, feed_name: str) -> bool:
        """
        Update indicators from a feed (placeholder).
        
        In production, this would fetch data from the feed URL
        and parse it into indicators.
        """
        if feed_name not in self._feeds:
            return False
            
        feed = self._feeds[feed_name]
        
        if not feed.enabled:
            return False
            
        try:
            # Placeholder: In real implementation, fetch and parse feed
            # For now, just update timestamp
            feed.last_update = time.time()
            feed.error_count = 0
            
            self.logger.info(f"Updated threat feed: {feed_name}")
            return True
            
        except Exception as e:
            feed.error_count += 1
            self.logger.error(f"Failed to update feed {feed_name}: {e}")
            return False
            
    def _evict_old_indicators(self, storage: Dict[str, ThreatIndicator]) -> int:
        """Remove oldest indicators to maintain size limit"""
        # Sort by last_seen
        sorted_indicators = sorted(
            storage.items(),
            key=lambda x: x[1].last_seen
        )
        
        # Remove oldest 10%
        to_remove = len(storage) // 10
        removed = 0
        
        for indicator, _ in sorted_indicators[:to_remove]:
            del storage[indicator]
            removed += 1
            
        self.logger.info(f"Evicted {removed} old indicators")
        return removed
        
    def cleanup_old_indicators(self) -> int:
        """Remove indicators older than max_age_hours"""
        cutoff_time = time.time() - (self.max_age_hours * 3600)
        removed = 0
        
        with self._lock:
            # Clean IPs
            to_remove = [
                ip for ip, ind in self._ip_indicators.items()
                if ind.last_seen < cutoff_time
            ]
            for ip in to_remove:
                del self._ip_indicators[ip]
                removed += 1
                
            # Clean domains
            to_remove = [
                domain for domain, ind in self._domain_indicators.items()
                if ind.last_seen < cutoff_time
            ]
            for domain in to_remove:
                del self._domain_indicators[domain]
                removed += 1
                
            # Clean URLs
            to_remove = [
                url for url, ind in self._url_indicators.items()
                if ind.last_seen < cutoff_time
            ]
            for url in to_remove:
                del self._url_indicators[url]
                removed += 1
                
        self.logger.info(f"Cleaned up {removed} old indicators")
        return removed
        
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        with self._lock:
            return {
                'total_lookups': self._lookups,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': self._hits / max(self._lookups, 1) * 100,
                'ip_indicators': len(self._ip_indicators),
                'domain_indicators': len(self._domain_indicators),
                'url_indicators': len(self._url_indicators),
                'hash_indicators': len(self._hash_indicators),
                'total_indicators': (
                    len(self._ip_indicators) +
                    len(self._domain_indicators) +
                    len(self._url_indicators) +
                    len(self._hash_indicators)
                ),
                'active_feeds': sum(1 for f in self._feeds.values() if f.enabled),
                'total_feeds': len(self._feeds)
            }
            
    def get_top_threats(self, n: int = 10) -> List[ThreatIndicator]:
        """Get top N threats by severity"""
        with self._lock:
            all_indicators = []
            all_indicators.extend(self._ip_indicators.values())
            all_indicators.extend(self._domain_indicators.values())
            all_indicators.extend(self._url_indicators.values())
            
            # Sort by threat level and confidence
            sorted_threats = sorted(
                all_indicators,
                key=lambda x: (x.threat_level, x.confidence),
                reverse=True
            )
            
            return sorted_threats[:n]