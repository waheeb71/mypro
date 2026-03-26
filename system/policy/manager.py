"""
Enterprise CyberNexus Policy Manager
Central orchestrator for all policy decisions.
"""

import logging
from typing import Optional, List, Dict
from dataclasses import dataclass
from .schema import PolicyContext, Action
from modules.firewall.policy.access_control.acl_engine import ACLEngine
from modules.firewall.policy.app_control.engine import AppControlEngine
from modules.web_filter.policy.engine import WebFilterEngine
from modules.ids_ips.engine.core.engine import IPSEngine

logger = logging.getLogger(__name__)

class PolicyManager:
    """
    Central Policy Decision Point (PDP).
    Aggregates decisions from ACL, AppControl, IPS, WebFilter.
    """
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        
        # Initialize specialized engines
        self.acl_engine = ACLEngine()
        self.app_engine = AppControlEngine()
        self.web_engine = WebFilterEngine()
        self.ips_engine = IPSEngine()
        
        # 🧠 Layer 5: Adaptive Policy Engine Integration
        try:
            from system.ml_core.adaptive_policy import AdaptivePolicyEngine
            self.adaptive_engine = AdaptivePolicyEngine()
            logger.info("Adaptive Policy Engine (Layer 5) initialized")
        except ImportError as e:
            logger.error(f"Failed to load AdaptivePolicyEngine: {e}")
            self.adaptive_engine = None
        
        # Load policies (Mock)
        self.load_policies()
        
        logger.info("Policy Manager initialized with all engines")

    def load_policies(self):
        """Load policies from database/file"""
        logger.info("Loading policies...")
        # TODO: Load from JSON/DB and pass to engines
        # self.acl_engine.load_rules(...)
        # self.app_engine.load_rules(...)
        pass

    def evaluate(self, context: PolicyContext) -> Action:
        """
        Evaluate a flow against all active policies.
        Order of operations:
        0. Adaptive ML Policy (L7+) -> Dynamic Blocks
        1. Access Control (L3/L4) -> Fast path
        2. IPS Inspection (Threat Intel/Reputation)
        3. App Control & Web Filter (L7)
        """
        
        # 0. Adaptive Policy Evaluation (AI Layer 5)
        if self.adaptive_engine:
            from system.ml_core.adaptive_policy import PolicyAction as MLPolicyAction
            ml_action, confidence, reason = self.adaptive_engine.evaluate(
                src_ip=context.src_ip,
                dst_ip=context.dst_ip,
                dst_port=context.dst_port,
                protocol=context.protocol,
                anomaly_score=0.0, # Could be fetched from context metadata in the future
                reputation_score=100.0, 
                pattern=context.app_id or 'unknown'
            )
            
            # If the AI strongly believes it's a threat and decides to BLOCK
            if ml_action == MLPolicyAction.BLOCK and confidence > 0.8:
                logger.warning(f"🧠 ML Adaptive Policy Blocked: {context.src_ip} -> {reason}")
                self.adaptive_engine.add_feedback(context.src_ip, ml_action, was_threat=True, threat_type="ml_adaptive_block")
                return Action.BLOCK
        
        # 1. Access Control (L3/L4)
        acl_action = self.acl_engine.evaluate(context)
        if acl_action == Action.BLOCK:
            self._feed_adaptive_engine(context.src_ip, acl_action, was_threat=True, threat_type="acl_block")
            return Action.BLOCK
        
        # 2. Intrusion Prevention (L7/Reputation)
        ips_action = self.ips_engine.evaluate(context)
        if ips_action == Action.BLOCK:
            self._feed_adaptive_engine(context.src_ip, ips_action, was_threat=True, threat_type="ips_block")
            return Action.BLOCK
            
        # 3. Deep Inspection (L7)
        # Always call App Control - it might resolve App ID from SNI
        app_action = self.app_engine.evaluate(context)
        if app_action == Action.BLOCK:
            self._feed_adaptive_engine(context.src_ip, app_action, was_threat=True, threat_type="app_block")
            return Action.BLOCK
            
        # Web Filter
        if context.domain or context.url:
            web_action = self.web_engine.evaluate(context)
            if web_action == Action.BLOCK:
                self._feed_adaptive_engine(context.src_ip, web_action, was_threat=True, threat_type="web_block")
                return Action.BLOCK
                
        # Default action
        self._feed_adaptive_engine(context.src_ip, Action.ALLOW, was_threat=False)
        return Action.ALLOW

    def _feed_adaptive_engine(self, src_ip: str, action: Action, was_threat: bool, threat_type: str = None):
        """Helper to safely pass feedback loop to the ML engine to learn dynamically"""
        if self.adaptive_engine:
            from system.ml_core.adaptive_policy import PolicyAction as MLPolicyAction
            ml_action = MLPolicyAction.BLOCK if action == Action.BLOCK else MLPolicyAction.ALLOW
            self.adaptive_engine.add_feedback(src_ip, ml_action, was_threat, threat_type)

    def reload(self):
        """Reload all policies"""
        self.load_policies()
