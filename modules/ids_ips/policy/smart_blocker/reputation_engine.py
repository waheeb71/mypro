"""
Enterprise CyberNexus v2.0 - Reputation Engine

IP and domain reputation scoring system with dynamic scoring,
historical tracking, and decay mechanisms.

Features:
- IP reputation scoring (0-100)
- Domain reputation with subdomain support
- Automatic score decay over time
- Incident tracking and aggregation
- Reputation categories (trusted/suspicious/malicious)
- Whitelist/blacklist overrides

Author: Enterprise CyberNexus Team
License: Proprietary
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
import threading


class ReputationLevel(IntEnum):
    """Reputation levels"""
    TRUSTED = 90      # Highly trusted (90-100)
    GOOD = 70         # Good reputation (70-89)
    NEUTRAL = 50      # Neutral/unknown (40-69)
    SUSPICIOUS = 30   # Suspicious (20-39)
    MALICIOUS = 10    # Known malicious (0-19)


class IncidentType(IntEnum):
    """Types of security incidents"""
    MALWARE = -30         # Malware detected
    PHISHING = -25        # Phishing attempt
    SPAM = -15            # Spam/bulk traffic
    BRUTE_FORCE = -20     # Brute force attempt
    DDoS = -25            # DDoS participation
    PORT_SCAN = -10       # Port scanning
    SUSPICIOUS_DNS = -15  # Suspicious DNS queries
    PROTOCOL_VIOLATION = -10  # Protocol violations
    TLS_ANOMALY = -12     # TLS/SSL anomalies
    
    # Positive events
    LEGITIMATE_TRAFFIC = 5    # Verified legitimate
    PAYMENT_SUCCESS = 10      # Successful transaction
    LONG_SESSION = 3          # Long-lived session


@dataclass
class ReputationScore:
    """Reputation score for an entity (IP/domain)"""
    entity: str
    score: float = 50.0  # Default neutral
    last_updated: float = field(default_factory=time.time)
    incident_count: int = 0
    incident_types: Dict[str, int] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_incident: float = 0.0
    
    @property
    def level(self) -> ReputationLevel:
        """Get reputation level based on score"""
        if self.score >= 90:
            return ReputationLevel.TRUSTED
        elif self.score >= 70:
            return ReputationLevel.GOOD
        elif self.score >= 40:
            return ReputationLevel.NEUTRAL
        elif self.score >= 20:
            return ReputationLevel.SUSPICIOUS
        else:
            return ReputationLevel.MALICIOUS
            
    @property
    def age_days(self) -> float:
        """Get age of reputation in days"""
        return (time.time() - self.first_seen) / 86400
        
    @property
    def is_trusted(self) -> bool:
        """Check if entity is trusted"""
        return self.score >= ReputationLevel.TRUSTED
        
    @property
    def is_malicious(self) -> bool:
        """Check if entity is malicious"""
        return self.score < ReputationLevel.SUSPICIOUS


class ReputationEngine:
    """
    IP and domain reputation scoring engine.
    
    Manages reputation scores with:
    - Dynamic scoring based on incidents
    - Time-based score decay
    - Whitelist/blacklist overrides
    - Historical incident tracking
    """
    
    def __init__(
        self,
        decay_rate: float = 0.1,  # Score decay per day
        decay_interval: int = 86400,  # 24 hours
        max_score: float = 100.0,
        min_score: float = 0.0,
        logger: Optional[logging.Logger] = None
    ):
        self.decay_rate = decay_rate
        self.decay_interval = decay_interval
        self.max_score = max_score
        self.min_score = min_score
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Reputation storage
        self._ip_reputation: Dict[str, ReputationScore] = {}
        self._domain_reputation: Dict[str, ReputationScore] = {}
        
        # Override lists
        self._ip_whitelist: Set[str] = set()
        self._ip_blacklist: Set[str] = set()
        self._domain_whitelist: Set[str] = set()
        self._domain_blacklist: Set[str] = set()
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._total_incidents = 0
        self._blocked_count = 0
        
    def get_ip_reputation(self, ip: str) -> ReputationScore:
        """
        Get reputation score for IP address.
        
        Args:
            ip: IP address
            
        Returns:
            ReputationScore object
        """
        with self._lock:
            # Check whitelist
            if ip in self._ip_whitelist:
                return ReputationScore(
                    entity=ip,
                    score=self.max_score,
                    last_updated=time.time()
                )
                
            # Check blacklist
            if ip in self._ip_blacklist:
                return ReputationScore(
                    entity=ip,
                    score=self.min_score,
                    last_updated=time.time()
                )
                
            # Get or create reputation
            if ip not in self._ip_reputation:
                self._ip_reputation[ip] = ReputationScore(entity=ip)
            else:
                # Apply decay
                self._apply_decay(self._ip_reputation[ip])
                
            return self._ip_reputation[ip]
            
    def get_domain_reputation(self, domain: str) -> ReputationScore:
        """
        Get reputation score for domain.
        
        Supports subdomain inheritance (e.g., www.example.com inherits from example.com)
        
        Args:
            domain: Domain name
            
        Returns:
            ReputationScore object
        """
        with self._lock:
            domain = domain.lower()
            
            # Check whitelist
            if self._is_domain_whitelisted(domain):
                return ReputationScore(
                    entity=domain,
                    score=self.max_score,
                    last_updated=time.time()
                )
                
            # Check blacklist
            if self._is_domain_blacklisted(domain):
                return ReputationScore(
                    entity=domain,
                    score=self.min_score,
                    last_updated=time.time()
                )
                
            # Check exact match
            if domain in self._domain_reputation:
                self._apply_decay(self._domain_reputation[domain])
                return self._domain_reputation[domain]
                
            # Check parent domains
            parent_score = self._get_parent_domain_score(domain)
            if parent_score:
                return parent_score
                
            # Create new entry
            self._domain_reputation[domain] = ReputationScore(entity=domain)
            return self._domain_reputation[domain]
            
    def _get_parent_domain_score(self, domain: str) -> Optional[ReputationScore]:
        """Get reputation from parent domain"""
        parts = domain.split('.')
        
        # Try progressively higher-level domains
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self._domain_reputation:
                # Inherit parent score but create separate entry
                parent_score = self._domain_reputation[parent]
                self._apply_decay(parent_score)
                return ReputationScore(
                    entity=domain,
                    score=parent_score.score,
                    first_seen=time.time()
                )
                
        return None
        
    def record_incident(
        self,
        entity: str,
        incident_type: IncidentType,
        entity_type: str = 'ip',  # 'ip' or 'domain'
        details: Optional[str] = None
    ) -> float:
        """
        Record security incident and update reputation.
        
        Args:
            entity: IP or domain
            incident_type: Type of incident
            entity_type: 'ip' or 'domain'
            details: Optional incident details
            
        Returns:
            New reputation score
        """
        with self._lock:
            # Get current reputation
            if entity_type == 'ip':
                rep = self.get_ip_reputation(entity)
                self._ip_reputation[entity] = rep
            else:
                rep = self.get_domain_reputation(entity)
                self._domain_reputation[entity.lower()] = rep
                
            # Update score
            old_score = rep.score
            rep.score = max(
                self.min_score,
                min(self.max_score, rep.score + incident_type.value)
            )
            
            # Update incident tracking
            rep.incident_count += 1
            rep.last_incident = time.time()
            rep.last_updated = time.time()
            
            incident_name = incident_type.name
            rep.incident_types[incident_name] = rep.incident_types.get(incident_name, 0) + 1
            
            # Statistics
            self._total_incidents += 1
            
            self.logger.info(
                f"Incident recorded: {entity} ({entity_type}) - {incident_type.name} "
                f"(score: {old_score:.1f} -> {rep.score:.1f})"
            )
            
            if details:
                self.logger.debug(f"Details: {details}")
                
            return rep.score
            
    def _apply_decay(self, rep: ReputationScore) -> None:
        """Apply time-based reputation decay (move toward neutral)"""
        elapsed = time.time() - rep.last_updated
        
        if elapsed < self.decay_interval:
            return
            
        # Calculate decay intervals passed
        intervals = elapsed / self.decay_interval
        
        # Decay toward neutral (50.0)
        neutral_score = 50.0
        if rep.score > neutral_score:
            # Good reputation decays down
            decay_amount = self.decay_rate * intervals
            rep.score = max(neutral_score, rep.score - decay_amount)
        elif rep.score < neutral_score:
            # Bad reputation recovers up
            recovery_amount = self.decay_rate * intervals
            rep.score = min(neutral_score, rep.score + recovery_amount)
            
        rep.last_updated = time.time()
        
    def whitelist_ip(self, ip: str) -> None:
        """Add IP to whitelist (always trusted)"""
        with self._lock:
            self._ip_whitelist.add(ip)
            self.logger.info(f"Added IP to whitelist: {ip}")
            
    def blacklist_ip(self, ip: str) -> None:
        """Add IP to blacklist (always blocked)"""
        with self._lock:
            self._ip_blacklist.add(ip)
            self.logger.info(f"Added IP to blacklist: {ip}")
            
    def whitelist_domain(self, domain: str) -> None:
        """Add domain to whitelist"""
        with self._lock:
            self._domain_whitelist.add(domain.lower())
            self.logger.info(f"Added domain to whitelist: {domain}")
            
    def blacklist_domain(self, domain: str) -> None:
        """Add domain to blacklist"""
        with self._lock:
            self._domain_blacklist.add(domain.lower())
            self.logger.info(f"Added domain to blacklist: {domain}")
            
    def _is_domain_whitelisted(self, domain: str) -> bool:
        """Check if domain or parent is whitelisted"""
        if domain in self._domain_whitelist:
            return True
            
        # Check parent domains
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self._domain_whitelist:
                return True
                
        return False
        
    def _is_domain_blacklisted(self, domain: str) -> bool:
        """Check if domain or parent is blacklisted"""
        if domain in self._domain_blacklist:
            return True
            
        # Check parent domains
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self._domain_blacklist:
                return True
                
        return False
        
    def get_top_malicious_ips(self, n: int = 10) -> List[ReputationScore]:
        """Get top N malicious IPs"""
        with self._lock:
            malicious = [
                rep for rep in self._ip_reputation.values()
                if rep.is_malicious
            ]
            return sorted(malicious, key=lambda r: r.score)[:n]
            
    def get_top_malicious_domains(self, n: int = 10) -> List[ReputationScore]:
        """Get top N malicious domains"""
        with self._lock:
            malicious = [
                rep for rep in self._domain_reputation.values()
                if rep.is_malicious
            ]
            return sorted(malicious, key=lambda r: r.score)[:n]
            
    def get_statistics(self) -> Dict:
        """Get reputation engine statistics"""
        with self._lock:
            return {
                'total_ips_tracked': len(self._ip_reputation),
                'total_domains_tracked': len(self._domain_reputation),
                'ip_whitelist_size': len(self._ip_whitelist),
                'ip_blacklist_size': len(self._ip_blacklist),
                'domain_whitelist_size': len(self._domain_whitelist),
                'domain_blacklist_size': len(self._domain_blacklist),
                'total_incidents': self._total_incidents,
                'malicious_ips': sum(1 for r in self._ip_reputation.values() if r.is_malicious),
                'malicious_domains': sum(1 for r in self._domain_reputation.values() if r.is_malicious),
                'trusted_ips': sum(1 for r in self._ip_reputation.values() if r.is_trusted),
                'trusted_domains': sum(1 for r in self._domain_reputation.values() if r.is_trusted)
            }
            
    def clear_old_entries(self, max_age_days: int = 30) -> int:
        """Clear reputation entries older than max_age_days"""
        with self._lock:
            current_time = time.time()
            max_age_seconds = max_age_days * 86400
            
            removed = 0
            
            # Clean IPs
            to_remove = [
                ip for ip, rep in self._ip_reputation.items()
                if current_time - rep.first_seen > max_age_seconds
                and rep.incident_count == 0  # Only remove if no incidents
            ]
            
            for ip in to_remove:
                del self._ip_reputation[ip]
                removed += 1
                
            # Clean domains
            to_remove = [
                domain for domain, rep in self._domain_reputation.items()
                if current_time - rep.first_seen > max_age_seconds
                and rep.incident_count == 0
            ]
            
            for domain in to_remove:
                del self._domain_reputation[domain]
                removed += 1
                
            self.logger.info(f"Cleared {removed} old reputation entries")
            return removed