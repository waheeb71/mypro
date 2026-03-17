"""
Policy Integration
Handles interaction with the global Policy Engine.
"""

import logging
import asyncio
from typing import Optional
from system.policy.manager import PolicyManager
from system.policy.schema import PolicyContext, Action
from system.response.orchestrator import ThreatContext, MitigationAction
from .types import RoutingDecision

logger = logging.getLogger(__name__)

class PolicyIntegrator:
    """Wrapper around PolicyManager for Router"""
    
    def __init__(self, config: dict):
        self.policy_manager = PolicyManager(config)
        self.orchestrator = None

        
    def enforce_policy(self, 
                      decision: RoutingDecision, 
                      client_ip: str, 
                      client_port: int, 
                      local_port: int) -> bool:
        """
        Enforce policy on the routing decision.
        Returns True if allowed, False if blocked.
        Modifies 'decision' in-place if blocked.
        """
        ctx = PolicyContext(
            src_ip=client_ip,
            dst_ip=decision.target_host or "0.0.0.0",
            src_port=client_port,
            dst_port=decision.target_port or 0,
            protocol="TCP", # Simplified
            interface="eth0", # Simplified
            domain=decision.target_host,
            app_id=None # Engine will try to resolve
        )
        
        action = self.policy_manager.evaluate(ctx)
        
        if action == Action.BLOCK:
            logger.warning(f"POLICY BLOCK: {client_ip} -> {decision.target_host}")
            
            # Trigger Autonomous Response if Orchestrator is hooked up
            if self.orchestrator:
                threat_context = ThreatContext(
                    target=client_ip,
                    action=MitigationAction.BLOCK_IP,
                    confidence=0.9,
                    reason=f"Blocked by Policy Engine: tried to access {decision.target_host}",
                    metadata={
                        "src_port": client_port,
                        "dst_ip": decision.target_host,
                        "dst_port": decision.target_port
                    }
                )
                asyncio.create_task(self.orchestrator.execute_mitigation(threat_context))
                
            decision.target_host = "0.0.0.0"
            decision.target_port = 0
            decision.metadata['blocked'] = True
            return False
            
        return True
