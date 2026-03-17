"""
Enterprise NGFW v2.0 - Blocking Decision Engine

Orchestrates all smart blocking components to make final allow/block decisions.

Integrates:
- Reputation Engine
- GeoIP Filter
- Category Blocker
- Threat Intelligence

Provides unified decision-making with policy-based rules.

Author: Enterprise NGFW Team
License: Proprietary
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
import time
import threading

from .reputation_engine import ReputationEngine, ReputationLevel
from .geoip_filter import GeoIPFilter
from .category_blocker import CategoryBlocker, ContentCategory
from .threat_intelligence import ThreatIntelligence, ThreatLevel
from system.policy.decision_ttl import DecisionTTLManager  # ✨ NEW


class BlockingAction(IntEnum):
    """Final blocking decision"""
    ALLOW = 0
    BLOCK = 1
    MONITOR = 2  # Allow but log
    CHALLENGE = 3  # Request captcha/verification
    RATE_LIMIT= 4  # ✨ NEW: Apply rate limiting
    QUARANTINE = 5  # ✨ NEW: Isolate suspicious traffic
    LOG_ONLY = 6  # ✨ NEW: Only log, no action


@dataclass
class BlockingDecision:
    """Result of blocking decision"""
    action: BlockingAction
    reasons: List[str] = field(default_factory=list)
    confidence: float = 1.0
    sources: List[str] = field(default_factory=list)  # Which engines triggered
    metadata: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    @property
    def is_blocked(self) -> bool:
        """Check if decision is to block"""
        return self.action == BlockingAction.BLOCK
        
    @property
    def is_allowed(self) -> bool:
        """Check if decision is to allow"""
        return self.action == BlockingAction.ALLOW


class PolicyMode(IntEnum):
    """Policy enforcement modes"""
    PERMISSIVE = 0  # Log only, don't block
    BALANCED = 1    # Default enforcement
    STRICT = 2      # Aggressive blocking
    PARANOID = 3    # Maximum security


class FailMode(IntEnum):
    """Fail-safe modes for ML/Component failures"""
    FAIL_OPEN = 0   # ✨ NEW: Allow traffic when components fail
    FAIL_CLOSED = 1  # ✨ NEW: Block traffic when components fail


class BlockingDecisionEngine:
    """
    Orchestrates all blocking components for unified decisions.
    
    Decision flow:
    1. Check threat intelligence (highest priority)
    2. Check reputation scores
    3. Check GeoIP restrictions
    4. Check content categories
    5. Apply policy rules
    6. Make final decision
    """
    
    def __init__(
        self,
        reputation_engine: Optional[ReputationEngine] = None,
        geoip_filter: Optional[GeoIPFilter] = None,
        category_blocker: Optional[CategoryBlocker] = None,
        threat_intel: Optional[ThreatIntelligence] = None,
        policy_mode: PolicyMode = PolicyMode.BALANCED,
        fail_mode: FailMode = FailMode.FAIL_OPEN,  # ✨ NEW
        logger: Optional[logging.Logger] = None
    ):
        self.reputation_engine = reputation_engine or ReputationEngine()
        self.geoip_filter = geoip_filter or GeoIPFilter()
        self.category_blocker = category_blocker or CategoryBlocker()
        self.threat_intel = threat_intel or ThreatIntelligence()
        
        self.policy_mode = policy_mode
        self.fail_mode = fail_mode  # ✨ NEW
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # ✨ NEW: TTL Manager for temporary decisions
        self.ttl_manager = DecisionTTLManager(cleanup_interval=60)
        
        # Policy configuration
        self._reputation_threshold = 30  # Block if score < 30
        self._threat_level_threshold = ThreatLevel.MEDIUM
        
        # Statistics
        self._total_decisions = 0
        self._blocked_decisions = 0
        self._allowed_decisions = 0
        self._monitored_decisions = 0
        self._rate_limited_decisions = 0  # ✨ NEW
        self._quarantined_decisions = 0   # ✨ NEW
        
        self._block_reasons: Dict[str, int] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        self.logger.info(
            f"Initialized decision engine (mode: {policy_mode.name}, "
            f"fail_mode: {fail_mode.name})"
        )
        
    def evaluate_connection(
        self,
        src_ip: str,
        dst_ip: Optional[str] = None,
        domain: Optional[str] = None,
        url: Optional[str] = None
    ) -> BlockingDecision:
        """
        Evaluate connection and make blocking decision.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP (optional)
            domain: Destination domain (optional)
            url: Full URL (optional)
            
        Returns:
            BlockingDecision with final verdict
        """
        with self._lock:
            self._total_decisions += 1
            
        decision = BlockingDecision(action=BlockingAction.ALLOW)
        decision.metadata['src_ip'] = src_ip
        
        # 1. Check threat intelligence (highest priority)
        threat_decision = self._check_threat_intelligence(
            src_ip, dst_ip, domain, url
        )
        if threat_decision.is_blocked:
            self._record_decision(threat_decision)
            return threat_decision
            
        # Merge threat info
        decision.reasons.extend(threat_decision.reasons)
        decision.sources.extend(threat_decision.sources)
        
        # 2. Check IP reputation
        reputation_decision = self._check_reputation(src_ip, domain)
        if reputation_decision.is_blocked:
            self._record_decision(reputation_decision)
            return reputation_decision
            
        decision.reasons.extend(reputation_decision.reasons)
        decision.sources.extend(reputation_decision.sources)
        
        # 3. Check GeoIP restrictions
        geoip_decision = self._check_geoip(src_ip)
        if geoip_decision.is_blocked:
            self._record_decision(geoip_decision)
            return geoip_decision
            
        decision.reasons.extend(geoip_decision.reasons)
        decision.sources.extend(geoip_decision.sources)
        
        # 4. Check content categories
        if domain:
            category_decision = self._check_categories(domain)
            if category_decision.is_blocked:
                self._record_decision(category_decision)
                return category_decision
                
            decision.reasons.extend(category_decision.reasons)
            decision.sources.extend(category_decision.sources)
            
        # 5. Apply policy mode adjustments
        decision = self._apply_policy_mode(decision)
        
        # 6. Final decision
        if not decision.reasons:
            decision.reasons.append("No blocking criteria matched")
            
        self._record_decision(decision)
        return decision
        
    def _check_threat_intelligence(
        self,
        src_ip: str,
        dst_ip: Optional[str],
        domain: Optional[str],
        url: Optional[str]
    ) -> BlockingDecision:
        """Check threat intelligence feeds"""
        decision = BlockingDecision(action=BlockingAction.ALLOW)
        
        try:
            # Check source IP
            is_threat, threat_info = self.threat_intel.is_threat(
                src_ip, 'ip', self._threat_level_threshold
            )
            
            if is_threat and threat_info:
                decision.action = BlockingAction.BLOCK
                decision.reasons.append(
                    f"Source IP in threat feed: {threat_info.source} "
                    f"(level: {threat_info.threat_level.name})"
                )
                decision.sources.append('threat_intel')
                decision.metadata['threat_level'] = threat_info.threat_level.name
                decision.metadata['threat_types'] = [
                    tt.name for tt in threat_info.threat_types
                ]
                return decision
                
            # Check destination IP
            if dst_ip:
                is_threat, threat_info = self.threat_intel.is_threat(
                    dst_ip, 'ip', self._threat_level_threshold
                )
                
                if is_threat and threat_info:
                    decision.action = BlockingAction.BLOCK
                    decision.reasons.append(
                        f"Destination IP in threat feed: {threat_info.source}"
                    )
                    decision.sources.append('threat_intel')
                    return decision
                    
            # Check domain
            if domain:
                is_threat, threat_info = self.threat_intel.is_threat(
                    domain, 'domain', self._threat_level_threshold
                )
                
                if is_threat and threat_info:
                    decision.action = BlockingAction.BLOCK
                    decision.reasons.append(
                        f"Domain in threat feed: {threat_info.source}"
                    )
                    decision.sources.append('threat_intel')
                    return decision
                    
            # Check URL
            if url:
                is_threat, threat_info = self.threat_intel.is_threat(
                    url, 'url', self._threat_level_threshold
                )
                
                if is_threat and threat_info:
                    decision.action = BlockingAction.BLOCK
                    decision.reasons.append(
                        f"URL in threat feed: {threat_info.source}"
                    )
                    decision.sources.append('threat_intel')
                    return decision
                    
        except Exception as e:
            self.logger.error(f"Threat intelligence check failed: {e}")
            
        return decision
        
    def _check_reputation(
        self,
        src_ip: str,
        domain: Optional[str]
    ) -> BlockingDecision:
        """Check reputation scores"""
        decision = BlockingDecision(action=BlockingAction.ALLOW)
        
        try:
            # Check IP reputation
            ip_rep = self.reputation_engine.get_ip_reputation(src_ip)
            
            if ip_rep.score < self._reputation_threshold:
                decision.action = BlockingAction.BLOCK
                decision.reasons.append(
                    f"Low IP reputation: {ip_rep.score:.1f} "
                    f"(level: {ip_rep.level.name})"
                )
                decision.sources.append('reputation')
                decision.metadata['ip_reputation'] = ip_rep.score
                decision.metadata['ip_reputation_level'] = ip_rep.level.name
                return decision
                
            # Check domain reputation
            if domain:
                domain_rep = self.reputation_engine.get_domain_reputation(domain)
                
                if domain_rep.score < self._reputation_threshold:
                    decision.action = BlockingAction.BLOCK
                    decision.reasons.append(
                        f"Low domain reputation: {domain_rep.score:.1f}"
                    )
                    decision.sources.append('reputation')
                    decision.metadata['domain_reputation'] = domain_rep.score
                    return decision
                    
        except Exception as e:
            self.logger.error(f"Reputation check failed: {e}")
            
        return decision
        
    def _check_geoip(self, src_ip: str) -> BlockingDecision:
        """Check GeoIP restrictions"""
        decision = BlockingDecision(action=BlockingAction.ALLOW)
        
        try:
            is_blocked, reason = self.geoip_filter.is_blocked(src_ip)
            
            if is_blocked:
                decision.action = BlockingAction.BLOCK
                decision.reasons.append(f"GeoIP: {reason}")
                decision.sources.append('geoip')
                
                # Add geo metadata
                geo_info = self.geoip_filter.lookup(src_ip)
                if geo_info:
                    decision.metadata['country'] = geo_info.country_code
                    decision.metadata['continent'] = geo_info.continent_code
                    
        except Exception as e:
            self.logger.error(f"GeoIP check failed: {e}")
            
        return decision
        
    def _check_categories(self, domain: str) -> BlockingDecision:
        """Check content categories"""
        decision = BlockingDecision(action=BlockingAction.ALLOW)
        
        try:
            is_blocked, reason = self.category_blocker.is_blocked(domain)
            
            if is_blocked:
                decision.action = BlockingAction.BLOCK
                decision.reasons.append(f"Category: {reason}")
                decision.sources.append('category')
                
                # Add category metadata
                match = self.category_blocker.categorize_domain(domain)
                decision.metadata['categories'] = [
                    cat.name for cat in match.categories
                ]
                decision.metadata['risk_level'] = match.risk_level
                
        except Exception as e:
            self.logger.error(f"Category check failed: {e}")
            
        return decision
        
    def _apply_policy_mode(self, decision: BlockingDecision) -> BlockingDecision:
        """Apply policy mode adjustments"""
        if self.policy_mode == PolicyMode.PERMISSIVE:
            # In permissive mode, convert blocks to monitor
            if decision.is_blocked:
                decision.action = BlockingAction.MONITOR
                decision.reasons.append("(Permissive mode: monitoring only)")
                
        elif self.policy_mode == PolicyMode.STRICT:
            # In strict mode, be more aggressive
            # Monitor suspicious traffic
            if 'suspicious' in str(decision.metadata).lower():
                decision.action = BlockingAction.MONITOR
                decision.reasons.append("Strict mode: monitoring suspicious")
                
        elif self.policy_mode == PolicyMode.PARANOID:
            # In paranoid mode, block on any suspicion
            if decision.sources:  # Any engine triggered
                decision.action = BlockingAction.BLOCK
                decision.reasons.append("Paranoid mode: blocking on suspicion")
                
        return decision
        
    def _record_decision(self, decision: BlockingDecision) -> None:
        """Record decision statistics"""
        with self._lock:
            if decision.is_blocked:
                self._blocked_decisions += 1
            elif decision.action == BlockingAction.MONITOR:
                self._monitored_decisions += 1
            else:
                self._allowed_decisions += 1
                
            # Record block reasons
            for reason in decision.reasons:
                # Extract main reason (before colon)
                main_reason = reason.split(':')[0].strip()
                self._block_reasons[main_reason] = \
                    self._block_reasons.get(main_reason, 0) + 1
                    
    def set_policy_mode(self, mode: PolicyMode) -> None:
        """Change policy enforcement mode"""
        self.policy_mode = mode
        self.logger.info(f"Policy mode changed to: {mode.name}")
        
    def set_reputation_threshold(self, threshold: int) -> None:
        """Set reputation score threshold for blocking"""
        self._reputation_threshold = max(0, min(100, threshold))
        self.logger.info(f"Reputation threshold set to: {threshold}")
        
    def set_threat_level_threshold(self, level: ThreatLevel) -> None:
        """Set minimum threat level for blocking"""
        self._threat_level_threshold = level
        self.logger.info(f"Threat level threshold set to: {level.name}")
        
    def get_statistics(self) -> Dict:
        """Get decision engine statistics"""
        with self._lock:
            total = max(self._total_decisions, 1)
            
            return {
                'total_decisions': self._total_decisions,
                'blocked': self._blocked_decisions,
                'allowed': self._allowed_decisions,
                'monitored': self._monitored_decisions,
                'block_rate': (self._blocked_decisions / total) * 100,
                'policy_mode': self.policy_mode.name,
                'reputation_threshold': self._reputation_threshold,
                'threat_level_threshold': self._threat_level_threshold.name,
                'top_block_reasons': sorted(
                    self._block_reasons.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            }
            
    def get_status(self) -> Dict:
        """Get comprehensive status of all components"""
        return {
            'decision_engine': self.get_statistics(),
            'reputation': self.reputation_engine.get_statistics(),
            'geoip': self.geoip_filter.get_statistics(),
            'categories': self.category_blocker.get_statistics(),
            'threat_intel': self.threat_intel.get_statistics()
        }