"""
Enterprise NGFW v2.0 - Reputation Engine
IP and domain reputation scoring system.
"""

import logging
import time
from typing import Dict, Optional, Set
from dataclasses import dataclass, field
from enum import IntEnum
import threading
logger = logging.getLogger(__name__)
class ReputationLevel(IntEnum):
    TRUSTED = 90
    GOOD = 70
    NEUTRAL = 50
    SUSPICIOUS = 30
    MALICIOUS = 10

@dataclass
class ReputationScore:
    entity: str
    score: float = 50.0
    last_updated: float = field(default_factory=time.time)

class ReputationEngine:
    """IP and domain reputation scoring engine"""
    
    def __init__(self):
        self._ip_reputation: Dict[str, ReputationScore] = {}
        self._lock = threading.RLock()
        
    def get_ip_reputation(self, ip: str) -> ReputationScore:
        with self._lock:
            if ip not in self._ip_reputation:
                self._ip_reputation[ip] = ReputationScore(ip)
            return self._ip_reputation[ip]
            
    def update_score(self, ip: str, delta: float):
        with self._lock:
            rep = self.get_ip_reputation(ip)
            rep.score = max(0.0, min(100.0, rep.score + delta))
            rep.last_updated = time.time()
