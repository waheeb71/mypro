"""
Intent-Proving Deceptive Object Graph WAAP Engine
This module generates contextual 'canary' objects (like fake user IDs or pagination tokens)
and stores them. If a client interacts with any generated canary, their intent is proven
to be malicious (e.g., automated scraping, BOLA/IDOR attempt).
"""

import logging
from typing import Tuple
from modules.waf.engine.core.settings import DeceptionEngineSettings
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

class DeceptionEngine:
    """
    WAAP Facade for the central Unified Causal Deception Engine.
    """
    def __init__(self, settings: DeceptionEngineSettings):
        self.settings = settings
        self.unified_engine = UnifiedDeceptionEngine(ttl_seconds=self.settings.ttl_seconds)
        logger.info("WAAP Deception Engine interface initialized (ttl=%ds)", self.settings.ttl_seconds)

    def generate_decoy(self, session_id: str, ip_address: str, attack_surface: str = "bola") -> dict:
        """
        Generates a contextual decoy by delegating to the unified engine.
        """
        # We pass session_id as the 'username' field for WAAP if no user is authenticated
        trap_id, decoy_obj = self.unified_engine.generate_trap(
            module="waap",
            username=session_id,
            source_ip=ip_address,
            target_service=attack_surface,
            anomaly_score=0.7 # Simulated high risk for WAAP decoys
        )
        return decoy_obj

    def analyze_request(self, payload_str: str, url_path: str) -> Tuple[bool, float, str]:
        """
        Checks if the incoming request touches any known unified canary.
        """
        content_to_check = payload_str + " " + url_path
        intent_proven, evidence, threat_score = self.unified_engine.verify_intent(
            payload_or_content=content_to_check, 
            reporting_module="waap"
        )
        
        if intent_proven:
            return True, threat_score, evidence
            
        return False, 0.0, ""
