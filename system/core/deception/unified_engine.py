"""
Enterprise CyberNexus - Unified Causal Deception Engine 
(The Core Innovation: Patent Claim 1)

This unified engine acts as the central hub for generating, tracking, and 
validating contextual deception elements (Honeytokens, Fake Banners, Decoy Paths)
across all CyberNexus modules (WAAP, UBA, IDS/IPS, DLP).
"""

import uuid
import time
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class DeceptionTrap:
    trap_id: str
    module: str          # 'waap', 'uba', 'ids_ips', 'dlp'
    trap_type: str       # e.g., 'fake_file', 'fake_admin_url', 'fake_ssh_banner'
    username: str        # The anomalous user (if authenticated)
    source_ip: str       # The attacker IP
    target_service: str  # The service they were probing
    timestamp: float
    context_data: Dict[str, Any] # Specific payload details

class UnifiedDeceptionEngine:
    """
    Singleton implementation of the Causal Deception Engine.
    Keeps track of all cross-module distributed traps to prove malicious intent.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(UnifiedDeceptionEngine, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, ttl_seconds: int = 3600):
        if getattr(self, '_initialized', False):
            return
            
        self.ttl_seconds = ttl_seconds
        self.active_traps: Dict[str, DeceptionTrap] = {}
        self._initialized = True
        logger.info("Unified Causal Deception Engine initialized (Central Hub) - TTL: %ds", ttl_seconds)

    def generate_trap(self, module: str, username: str, source_ip: str, target_service: str, anomaly_score: float) -> Tuple[str, dict]:
        """
        Dynamically generates a trap payload based on the reporting module and the anomalous context.
        Returns: (trap_id, payload_dict)
        """
        self._prune()
        trap_id = f"dtk_{uuid.uuid4().hex[:16]}"
        trap_type = "generic_trap"
        payload = {}
        context_data = {"anomaly_score": anomaly_score}
        
        target_lower = target_service.lower()

        # 1. UBA Embodiment (Insider Threats)
        if module == "uba":
            if "smb" in target_lower or "file" in target_lower:
                trap_type = "honeyfile"
                payload = {
                    "files": [
                        {"name": "Public_Policy.pdf", "type": "real"},
                        {"name": f"Confidential_M&A_{time.strftime('%Y')}.xlsx", "type": "honeytoken", "id": trap_id}
                    ],
                    "message": "SMB Share Listing"
                }
            elif "sql" in target_lower or "db" in target_lower:
                trap_type = "fake_db_credentials"
                payload = {"hidden_credentials": {"admin_user": "sysadmin", "admin_pass_token": trap_id}}
            else:
                trap_type = "fake_admin_link"
                payload = {"admin_portal_url": f"/admin/v2/debug?auth_token={trap_id}"}
                
        # 2. WAAP Embodiment (API Abuse & Decoys)
        elif module == "waap":
            if "login" in target_lower or "auth" in target_lower:
                trap_type = "decoy_session"
                payload = {"session_id": trap_id, "role": "admin", "warning": "DO NOT USE"}
            else:
                trap_type = "fake_api_parameter"
                payload = {"debug_token": trap_id, "status": "development_mode"}
                
        # 3. IDS/IPS Embodiment (Network Banners)
        elif module == "ids_ips":
            if target_service == "22" or "ssh" in target_lower:
                trap_type = "fake_ssh_banner"
                payload = {"tcp_syn_ack": True, "banner": f"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1 (VULNERABLE)\r\ntrap_id={trap_id}\r\n"}
            elif target_service == "3306" or "mysql" in target_lower:
                trap_type = "fake_mysql_handshake"
                payload = {"tcp_syn_ack": True, "banner": f"5.5.99-MariaDB-log...trap_id={trap_id}"}
            else:
                trap_type = "generic_tarpit"
                payload = {"action": "tarpit", "delay_ms": 5000, "trap_id": trap_id}
                
        # 4. DLP Embodiment (Watermarked Data)
        elif module == "dlp":
            trap_type = "watermarked_pii"
            payload = {"fake_cc_record": f"4500-0000-0000-{trap_id[:4]}", "trap_id": trap_id}

        # Store the trap
        record = DeceptionTrap(
            trap_id=trap_id,
            module=module,
            trap_type=trap_type,
            username=username,
            source_ip=source_ip,
            target_service=target_service,
            timestamp=time.time(),
            context_data=context_data
        )
        self.active_traps[trap_id] = record
        
        logger.warning(f"[Central Deception] Generated {trap_type} for {module} (IP: {source_ip}, Score: {anomaly_score})")
        return trap_id, payload

    def verify_intent(self, payload_or_content: str, reporting_module: str) -> Tuple[bool, Optional[str], Optional[float]]:
        """
        Scans incoming payloads/requests for ANY active trap IDs.
        If found, returns 100% cryptographic proof of malicious intent.
        
        Returns: (is_intent_proven: bool, evidence_message: str, threat_score: float)
        """
        if not self.active_traps:
            return False, None, 0.0

        content_lower = payload_or_content.lower()
        
        # O(N) scan. N is usually small due to TTL and active culling.
        for trap_id, record in list(self.active_traps.items()):
            if trap_id.lower() in content_lower:
                evidence = (
                    f"INTENT PROVEN (Cross-Module): Subject '{record.username}' ({record.source_ip}) "
                    f"interacted with a highly sensitive Deception Trap ({record.trap_type}) "
                    f"originally generated by [{record.module}] for {record.target_service}. "
                    f"Detected by [{reporting_module}]."
                )
                logger.critical(evidence)
                
                # Intent proven. Burn the token so it can't be replayed safely.
                del self.active_traps[trap_id]
                return True, evidence, 1.0 # 1.0 = Max Threat Score

        return False, None, 0.0

    def _prune(self):
        """Removes expired traps to prevent memory bloat."""
        now = time.time()
        expired = [k for k, v in self.active_traps.items() if now - v.timestamp > self.ttl_seconds]
        for k in expired:
            del self.active_traps[k]
