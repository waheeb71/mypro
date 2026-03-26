"""
Enterprise CyberNexus v2.0 - Threat Intelligence
Integration with threat intelligence feeds for real-time threat detection.
"""

import logging
import time
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

class ThreatLevel(IntEnum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    SAFE = 0

class ThreatType(IntEnum):
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
    indicator: str
    indicator_type: str
    threat_level: ThreatLevel
    threat_types: List[ThreatType]
    source: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 1.0

class ThreatIntelligence:
    """Threat intelligence feed aggregator and query engine"""
    
    def __init__(self):
        self._ip_indicators: Dict[str, ThreatIndicator] = {}
        self._domain_indicators: Dict[str, ThreatIndicator] = {}
        self._url_indicators: Dict[str, ThreatIndicator] = {}
        self._lock = threading.RLock()
        
    def add_indicator(self, indicator: str, type: str, level: ThreatLevel, types: List[ThreatType], source: str):
        with self._lock:
            ti = ThreatIndicator(indicator, type, level, types, source)
            if type == 'ip':
                self._ip_indicators[indicator] = ti
            elif type == 'domain':
                self._domain_indicators[indicator] = ti
            elif type == 'url':
                self._url_indicators[indicator] = ti
                
    def is_threat(self, indicator: str, type: str) -> Tuple[bool, Optional[ThreatIndicator]]:
        with self._lock:
            if type == 'ip':
                info = self._ip_indicators.get(indicator)
            elif type == 'domain':
                info = self._domain_indicators.get(indicator)
            elif type == 'url':
                info = self._url_indicators.get(indicator)
            else:
                return False, None
                
            if info:
                return True, info
            return False, None
