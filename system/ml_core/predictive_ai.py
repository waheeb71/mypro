import logging
import time
import asyncio
from typing import Dict, List, Optional
from datetime import datetime

from system.telemetry.events.event_schema import EventSchema, EventVerdict
from system.response.orchestrator import MitigationOrchestrator, ThreatContext, MitigationAction

class PredictiveCorrelationEngine:
    """
    Predictive AI Correlation Engine
    
    Acts as the overarching 'Brain' connecting dots between isolated modules.
    Subscribes to the UnifiedEventSink. If an IP triggers multiple distinct
    security alerts within a time window (e.g., Malware Download followed by DGA),
    it orchestrates a system-wide isolation.
    """
    
    def __init__(self, orchestrator: MitigationOrchestrator, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.orchestrator = orchestrator
        
        # Temporal state: ip -> list of (timestamp, event_type/reason)
        # In a production distributed system, this would use Redis.
        self._state: Dict[str, List[EventSchema]] = {}
        self.time_window_sec = 300  # 5 minutes sliding window
        self._lock = asyncio.Lock()
        
        self.logger.info("Predictive Correlation Engine loaded. Zero Trust Multi-stage tracking active.")

    async def process_event(self, event: EventSchema):
        """Callback for real-time EventSink stream."""
        
        # We only care about blocked/quarantined anomalous events for correlation
        if event.verdict in (EventVerdict.ALLOW, EventVerdict.LOG_ONLY) and not event.ml_score:
            # If it's technically ALLOW but has an ML suspicion score > 0.6, we might track it,
            # but usually we track hard drops/quarantines.
            if not event.ml_score or event.ml_score < 0.6:
                return

        src_ip = event.src_ip
        if not src_ip or src_ip == "0.0.0.0":
            return
            
        now = time.time()
        
        async with self._lock:
            if src_ip not in self._state:
                self._state[src_ip] = []
                
            # Append current event
            self._state[src_ip].append(event)
            
            # Prune events older than our sliding window
            self._state[src_ip] = [
                e for e in self._state[src_ip]
                if now - e.timestamp.timestamp() <= self.time_window_sec
            ]
            
            # Run heuristic correlation rules
            await self._evaluate_killchain(src_ip, self._state[src_ip])

    async def _evaluate_killchain(self, ip: str, events: List[EventSchema]):
        """
        Evaluate if the recent events for this IP match a multi-stage killchain pattern.
        """
        if len(events) < 2:
            return  # Need at least 2 distinct anomalous events to correlate
            
        has_malware = False
        has_dga = False
        has_exfil = False
        has_waf_exploit = False
        
        for e in events:
            reason = e.reason.lower() if e.reason else ""
            threats = [t.lower() for t in e.metadata.threat_types] if e.metadata and e.metadata.threat_types else []
            combined_context = reason + " ".join(threats)
            
            if "malware" in combined_context or "virus" in combined_context or "dlp" in combined_context:
                has_malware = True
            if "dga" in combined_context or "tunneling" in combined_context:
                has_dga = True
            if "exfiltration" in combined_context or e.bytes > 50_000_000: # 50MB anomalous
                has_exfil = True
            if "sqli" in combined_context or "xss" in combined_context or "waf" in combined_context:
                has_waf_exploit = True
                
        # Rule 1: Compromised Host (Download -> C2 Beacon)
        if has_malware and has_dga:
            self.logger.critical(f"🧠 [CORRELATION DETECTED] Multi-stage Killchain on {ip} (Malware -> DGA C2)")
            await self.orchestrator.execute_mitigation(ThreatContext(
                target=ip,
                action=MitigationAction.ISOLATE_HOST,
                confidence=0.95,
                reason="Correlated Attack: Initial Infection followed by DGA Command & Control Beaconing",
                metadata={"trigger": "predictive_ai_rule_1"}
            ))
            # Clear state after mitigation to prevent spam
            self._state[ip] = []
            
        # Rule 2: Insider Threat / Data Breach (Exploit -> Exfil)
        elif has_waf_exploit and has_exfil:
            self.logger.critical(f"🧠 [CORRELATION DETECTED] Multi-stage Killchain on {ip} (WAF Exploit -> Exfil)")
            await self.orchestrator.execute_mitigation(ThreatContext(
                target=ip,
                action=MitigationAction.KILL_SESSIONS,
                confidence=0.90,
                reason="Correlated Attack: Server Exploitation followed by massive Data Exfiltration",
                metadata={"trigger": "predictive_ai_rule_2"}
            ))
            self._state[ip] = []
            
        # Rule 3: Highly Suspicious Lateral Movement
        elif len(events) >= 5:
            # 5 separate security block events within 5 minutes -> immediate quarantine
            self.logger.critical(f"🧠 [CORRELATION DETECTED] Hyper-active threat source {ip} (5+ Distinct Alerts)")
            await self.orchestrator.execute_mitigation(ThreatContext(
                target=ip,
                action=MitigationAction.BLOCK_IP,
                confidence=0.99,
                reason="Excessive Security Violations correlated across multiple NGFW modules",
                metadata={"trigger": "predictive_ai_rule_volumetric"}
            ))
            self._state[ip] = []

