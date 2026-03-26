#!/usr/bin/env python3
"""
Enterprise CyberNexus - Adaptive Policy Engine
ML-driven dynamic policy adjustment and optimization
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from threading import RLock

logger = logging.getLogger(__name__)


class PolicyAction(Enum):
    """Policy actions"""
    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    MONITOR = "monitor"
    CHALLENGE = "challenge"  # CAPTCHA, rate limit, etc.


class AdaptationType(Enum):
    """Types of policy adaptations"""
    THRESHOLD_INCREASE = "threshold_increase"
    THRESHOLD_DECREASE = "threshold_decrease"
    RULE_ADD = "rule_add"
    RULE_REMOVE = "rule_remove"
    RATE_LIMIT_ADJUST = "rate_limit_adjust"
    REPUTATION_UPDATE = "reputation_update"


@dataclass
class PolicyRule:
    """Dynamic policy rule"""
    rule_id: str
    condition: str  # e.g., "src_ip == x.x.x.x"
    action: PolicyAction
    priority: int = 100
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    confidence: float = 0.8
    source: str = "adaptive"  # adaptive, manual, etc.
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptationEvent:
    """Record of policy adaptation"""
    timestamp: datetime
    adaptation_type: AdaptationType
    description: str
    reason: str
    old_value: Any
    new_value: Any
    confidence: float
    applied: bool = True


@dataclass
class PolicyMetrics:
    """Metrics for policy effectiveness"""
    total_adaptations: int = 0
    successful_blocks: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    avg_response_time: float = 0.0
    threat_detection_rate: float = 0.0
    
    def calculate_accuracy(self) -> float:
        """Calculate policy accuracy"""
        total = self.successful_blocks + self.false_positives + self.false_negatives
        if total == 0:
            return 1.0
        return self.successful_blocks / total


class AdaptivePolicyEngine:
    """
    ML-driven adaptive policy engine
    
    Features:
    - Dynamic threshold adjustment
    - Automatic rule generation
    - Rate limit optimization
    - Reputation-based policies
    - Performance feedback loop
    """
    
    def __init__(
        self,
        learning_rate: float = 0.1,
        adaptation_interval: int = 300,  # 5 minutes
        min_confidence: float = 0.7,
        max_rules: int = 1000
    ):
        self.learning_rate = learning_rate
        self.adaptation_interval = adaptation_interval
        self.min_confidence = min_confidence
        self.max_rules = max_rules
        
        # Policy storage
        self.dynamic_rules: Dict[str, PolicyRule] = {}
        self.adaptation_history: List[AdaptationEvent] = []
        
        # Thresholds (can be adapted)
        self.thresholds = {
            'anomaly_score': 0.7,
            'reputation_score': 40.0,
            'connection_rate': 1000,
            'packet_rate': 10000,
            'bandwidth_limit': 100 * 1024 * 1024,  # 100 MB/s
        }
        
        # Rate limits (per IP)
        self.rate_limits = {
            'connections_per_second': 100,
            'packets_per_second': 1000,
            'bytes_per_second': 10 * 1024 * 1024,  # 10 MB/s
        }
        
        # Metrics
        self.metrics = PolicyMetrics()
        
        # Feedback data
        self.feedback_buffer: List[Dict] = []
        self.last_adaptation = datetime.now()
        
        self._lock = RLock()

        # RL Optimizer link (disabled by default — enable via config)
        self._rl_optimizer = None
        self._rl_sync_enabled = False
        
        logger.info(f"AdaptivePolicyEngine initialized (lr={learning_rate}, interval={adaptation_interval}s)")

    def set_rl_optimizer(self, rl_optimizer) -> None:
        """
        Link RLPolicyOptimizer to this engine.

        When linked, the RL optimizer's learned policy parameters
        (sensitivity, rate_limit) will override the static thresholds
        every adaptation cycle.

        Enable via config:
            ml:
              rl_policy_sync:
                enabled: true
        """
        self._rl_optimizer = rl_optimizer
        self._rl_sync_enabled = True
        logger.info(
            "🤖 RLPolicyOptimizer linked to AdaptivePolicyEngine "
            "— RL-driven threshold sync ENABLED"
        )

    def _apply_rl_params(self) -> None:
        """Pull current RL policy params and apply them as thresholds."""
        if not (self._rl_sync_enabled and self._rl_optimizer):
            return
        try:
            params = self._rl_optimizer.get_policy_params()
            # sensitivity (0.1–1.0) maps inversely to anomaly_score threshold
            # higher sensitivity → lower threshold → more strict
            sensitivity = params.get('sensitivity', 0.5)
            new_anomaly_threshold = round(1.0 - sensitivity, 3)
            old = self.thresholds['anomaly_score']
            if abs(new_anomaly_threshold - old) > 0.01:          # only update if meaningful change
                self.adjust_threshold(
                    'anomaly_score',
                    new_anomaly_threshold,
                    reason=f"RL sync: sensitivity={sensitivity:.2f}"
                )

            # rate_limit maps to packets_per_second
            new_pps = int(params.get('rate_limit', self.rate_limits['packets_per_second']))
            if new_pps != self.rate_limits['packets_per_second']:
                old_pps = self.rate_limits['packets_per_second']
                self.rate_limits['packets_per_second'] = new_pps
                logger.info(f"RL sync: packets_per_second {old_pps} → {new_pps}")

        except Exception as e:
            logger.error(f"RL sync error: {e}")
    
    def evaluate(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        anomaly_score: float = 0.0,
        reputation_score: float = 100.0,
        pattern: Optional[str] = None,
        **kwargs
    ) -> Tuple[PolicyAction, float, str]:
        """
        Evaluate traffic against adaptive policies
        
        Returns:
            (action, confidence, reason)
        """
        with self._lock:
            # Check dynamic rules first (highest priority)
            for rule in sorted(self.dynamic_rules.values(), key=lambda r: r.priority, reverse=True):
                if not rule.enabled:
                    continue
                
                if self._match_rule(rule, src_ip, dst_ip, dst_port, protocol, anomaly_score, reputation_score, pattern):
                    rule.last_triggered = datetime.now()
                    rule.trigger_count += 1
                    return rule.action, rule.confidence, f"Matched dynamic rule: {rule.rule_id}"
            
            # Apply threshold-based policies
            
            # High anomaly score
            if anomaly_score > self.thresholds['anomaly_score']:
                confidence = min(0.95, anomaly_score)
                return PolicyAction.BLOCK, confidence, f"Anomaly score {anomaly_score:.3f} exceeds threshold"
            
            # Low reputation
            if reputation_score < self.thresholds['reputation_score']:
                confidence = 1.0 - (reputation_score / 100.0)
                return PolicyAction.THROTTLE, confidence, f"Low reputation score {reputation_score:.1f}"
            
            # Pattern-based blocking
            if pattern in ['scanning', 'ddos', 'brute_force', 'c2_comm', 'data_exfiltration']:
                return PolicyAction.BLOCK, 0.9, f"Malicious pattern detected: {pattern}"
            
            # Suspicious pattern
            if pattern == 'suspicious':
                return PolicyAction.MONITOR, 0.7, "Suspicious pattern, monitoring"
            
            # Default allow
            return PolicyAction.ALLOW, 0.95, "No threats detected"
    
    def add_feedback(
        self,
        src_ip: str,
        action_taken: PolicyAction,
        was_threat: bool,
        threat_type: Optional[str] = None
    ):
        """
        Add feedback for policy learning
        
        Args:
            src_ip: Source IP
            action_taken: Action that was taken
            was_threat: Whether it was actually a threat
            threat_type: Type of threat if any
        """
        with self._lock:
            feedback = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'action_taken': action_taken,
                'was_threat': was_threat,
                'threat_type': threat_type
            }
            
            self.feedback_buffer.append(feedback)
            
            # Update metrics
            if was_threat and action_taken in [PolicyAction.BLOCK, PolicyAction.THROTTLE]:
                self.metrics.successful_blocks += 1
            elif was_threat and action_taken == PolicyAction.ALLOW:
                self.metrics.false_negatives += 1
            elif not was_threat and action_taken in [PolicyAction.BLOCK, PolicyAction.THROTTLE]:
                self.metrics.false_positives += 1
            
            # Trigger adaptation if interval passed
            if (datetime.now() - self.last_adaptation).total_seconds() > self.adaptation_interval:
                self._perform_adaptation()
    
    def create_dynamic_rule(
        self,
        condition: str,
        action: PolicyAction,
        priority: int = 100,
        confidence: float = 0.8,
        reason: str = "ML-generated"
    ) -> Optional[str]:
        """
        Create a new dynamic rule
        
        Returns:
            rule_id if created successfully
        """
        with self._lock:
            if len(self.dynamic_rules) >= self.max_rules:
                # Remove lowest priority rule
                lowest_rule = min(
                    self.dynamic_rules.values(),
                    key=lambda r: (r.priority, r.trigger_count)
                )
                del self.dynamic_rules[lowest_rule.rule_id]
            
            rule_id = f"adaptive_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.dynamic_rules)}"
            
            rule = PolicyRule(
                rule_id=rule_id,
                condition=condition,
                action=action,
                priority=priority,
                confidence=confidence,
                metadata={'reason': reason}
            )
            
            self.dynamic_rules[rule_id] = rule
            
            # Record adaptation
            event = AdaptationEvent(
                timestamp=datetime.now(),
                adaptation_type=AdaptationType.RULE_ADD,
                description=f"Added rule: {condition} -> {action.value}",
                reason=reason,
                old_value=None,
                new_value=rule_id,
                confidence=confidence
            )
            self.adaptation_history.append(event)
            self.metrics.total_adaptations += 1
            
            logger.info(f"Created dynamic rule {rule_id}: {condition} -> {action.value}")
            return rule_id
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a dynamic rule"""
        with self._lock:
            if rule_id in self.dynamic_rules:
                rule = self.dynamic_rules[rule_id]
                del self.dynamic_rules[rule_id]
                
                event = AdaptationEvent(
                    timestamp=datetime.now(),
                    adaptation_type=AdaptationType.RULE_REMOVE,
                    description=f"Removed rule: {rule.condition}",
                    reason="Manual removal or ineffective",
                    old_value=rule_id,
                    new_value=None,
                    confidence=1.0
                )
                self.adaptation_history.append(event)
                
                return True
            return False
    
    def adjust_threshold(
        self,
        threshold_name: str,
        new_value: float,
        reason: str = "Manual adjustment"
    ):
        """Adjust a threshold value"""
        with self._lock:
            if threshold_name not in self.thresholds:
                logger.warning(f"Unknown threshold: {threshold_name}")
                return
            
            old_value = self.thresholds[threshold_name]
            self.thresholds[threshold_name] = new_value
            
            adaptation_type = (
                AdaptationType.THRESHOLD_INCREASE if new_value > old_value
                else AdaptationType.THRESHOLD_DECREASE
            )
            
            event = AdaptationEvent(
                timestamp=datetime.now(),
                adaptation_type=adaptation_type,
                description=f"Adjusted {threshold_name}",
                reason=reason,
                old_value=old_value,
                new_value=new_value,
                confidence=0.9
            )
            self.adaptation_history.append(event)
            self.metrics.total_adaptations += 1
            
            logger.info(f"Adjusted threshold {threshold_name}: {old_value} -> {new_value}")
    
    def get_metrics(self) -> PolicyMetrics:
        """Get policy metrics"""
        with self._lock:
            self.metrics.threat_detection_rate = self.metrics.calculate_accuracy()
            return self.metrics
    
    def get_recent_adaptations(self, count: int = 10) -> List[AdaptationEvent]:
        """Get recent adaptation events"""
        with self._lock:
            return self.adaptation_history[-count:]
    
    def _perform_adaptation(self):
        """Perform adaptive learning based on feedback"""
        with self._lock:
            if not self.feedback_buffer:
                return
            
            logger.info(f"Performing adaptation based on {len(self.feedback_buffer)} feedback samples")
            
            # Analyze feedback
            false_positive_rate = self.metrics.false_positives / max(
                self.metrics.false_positives + self.metrics.successful_blocks, 1
            )
            false_negative_rate = self.metrics.false_negatives / max(
                self.metrics.false_negatives + self.metrics.successful_blocks, 1
            )
            
            # Adapt thresholds
            
            # High false positive rate -> increase anomaly threshold (be more lenient)
            if false_positive_rate > 0.1:
                new_threshold = min(0.95, self.thresholds['anomaly_score'] + self.learning_rate)
                self.adjust_threshold(
                    'anomaly_score',
                    new_threshold,
                    f"High FP rate {false_positive_rate:.2%}"
                )
            
            # High false negative rate -> decrease anomaly threshold (be more strict)
            elif false_negative_rate > 0.05:
                new_threshold = max(0.5, self.thresholds['anomaly_score'] - self.learning_rate)
                self.adjust_threshold(
                    'anomaly_score',
                    new_threshold,
                    f"High FN rate {false_negative_rate:.2%}"
                )
            
            # Create rules for repeat offenders
            ip_threat_count = {}
            for feedback in self.feedback_buffer:
                if feedback['was_threat']:
                    ip = feedback['src_ip']
                    ip_threat_count[ip] = ip_threat_count.get(ip, 0) + 1
            
            for ip, count in ip_threat_count.items():
                if count >= 5:  # 5+ threats from same IP
                    condition = f"src_ip == '{ip}'"
                    # Check if rule already exists
                    if not any(r.condition == condition for r in self.dynamic_rules.values()):
                        self.create_dynamic_rule(
                            condition=condition,
                            action=PolicyAction.BLOCK,
                            priority=200,
                            confidence=0.95,
                            reason=f"Repeat offender: {count} threats detected"
                        )
            
            # Remove ineffective rules
            for rule_id, rule in list(self.dynamic_rules.items()):
                age = (datetime.now() - rule.created_at).total_seconds()
                
                # Remove rules that haven't triggered in 1 hour
                if age > 3600 and rule.trigger_count == 0:
                    self.remove_rule(rule_id)
                
                # Remove low-confidence rules that trigger too often (likely false positives)
                elif rule.confidence < 0.6 and rule.trigger_count > 100:
                    self.remove_rule(rule_id)
            
            # Clear feedback buffer
            self.feedback_buffer.clear()
            self.last_adaptation = datetime.now()

            # Apply RL-driven parameter updates if sync is enabled
            self._apply_rl_params()
            
            logger.info(f"Adaptation complete: FP={false_positive_rate:.2%}, FN={false_negative_rate:.2%}")

    
    def _match_rule(
        self,
        rule: PolicyRule,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        anomaly_score: float,
        reputation_score: float,
        pattern: Optional[str]
    ) -> bool:
        """Check if traffic matches a rule condition"""
        try:
            # Simple condition parsing
            condition = rule.condition
            
            # Replace variables
            context = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol.upper(),
                'anomaly_score': anomaly_score,
                'reputation_score': reputation_score,
                'pattern': pattern or ''
            }
            
            # Evaluate condition
            return eval(condition, {"__builtins__": {}}, context)
        
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
            return False