"""
Traffic Router Manager
Main entry point for the modular router package.
"""

import logging
from typing import Tuple, Optional
from .types import RoutingDecision, ProxyMode
from .dispatcher import ProxyDispatcher
from .policy_integration import PolicyIntegrator
from .utils import extract_target

logger = logging.getLogger(__name__)

class TrafficRouter:
    """
    Smart Traffic Router (Modular)
    
    Coordinates:
    - Dispatcher (Port -> Mode)
    - Protocol Analysis (Target Extraction)
    - Policy Enforcement
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.dispatcher = ProxyDispatcher(config)
        self.policy_integrator = PolicyIntegrator(config)
        
        self.stats = {
            'total_routes': 0,
            'by_mode': {mode: 0 for mode in ProxyMode}
        }
        
        logger.info(f"Traffic Router initialized (default_mode={self.dispatcher.default_mode.value})")
        
    def set_orchestrator(self, orchestrator):
        """Set the MitigationOrchestrator down to the policy integrator"""
        self.policy_integrator.orchestrator = orchestrator
        logger.info("MitigationOrchestrator linked to Traffic Router")
        
    async def route(self, 
                   client_addr: Tuple[str, int],
                   local_port: int,
                   initial_data: Optional[bytes] = None) -> RoutingDecision:
        """
        Route incoming connection
        """
        self.stats['total_routes'] += 1
        
        # 1. Dispatch Mode
        mode = self.dispatcher.get_mode(local_port)
        
        # 2. Extract Target
        target_host = None
        target_port = None
        
        if initial_data:
            target_host, target_port = await extract_target(initial_data, mode)
            
        # 3. Create Decision
        decision = RoutingDecision(
            mode=mode,
            target_host=target_host,
            target_port=target_port or (443 if local_port in [443, 8443] else 80),
            ssl_inspection=self._should_inspect_ssl(client_addr[0], target_host),
            metadata={
                'client_ip': client_addr[0],
                'client_port': client_addr[1],
                'local_port': local_port,
            }
        )
        
        # 4. Enforce Policy
        allowed = self.policy_integrator.enforce_policy(
            decision, 
            client_ip=client_addr[0],
            client_port=client_addr[1],
            local_port=local_port
        )
        
        if not allowed:
            logger.info(f"Connection blocked by policy: {client_addr} -> {target_host}")
            
        # Update stats
        self.stats['by_mode'][mode] = self.stats['by_mode'].get(mode, 0) + 1
        
        logger.debug(f"Routed: {client_addr[0]} -> {decision}")
        return decision

    def _should_inspect_ssl(self, client_ip: str, target_host: Optional[str]) -> bool:
        """Determine if SSL inspection is needed"""
        ssl_config = self.config.get('ssl_inspection', {})
        if not ssl_config.get('enabled', True):
            return False
            
        # Check IPs
        if client_ip in ssl_config.get('bypass_ips', []):
            return False
            
        # Check Domains
        if target_host:
            bypass_domains = ssl_config.get('bypass_domains', [])
            from .utils import match_domain
            for pattern in bypass_domains:
                if match_domain(target_host, pattern):
                    return False
                    
        return True

    def get_statistics(self) -> dict:
        return {
            'total_routes': self.stats['total_routes'],
            'by_mode': {m.value: c for m, c in self.stats['by_mode'].items()}
        }
