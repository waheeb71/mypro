"""
Intrusion Prevention System (IPS) Engine
Coordinats Signature-based and Anomaly-based detection.
"""

import logging
from typing import List, Optional
from system.policy.schema import IPSRule, PolicyContext, Action
from modules.ids_ips.policy.smart_blocker.threat_intelligence import ThreatIntelligence, ThreatLevel
from .reputation import ReputationEngine, ReputationLevel
from .signatures import SignatureEngine
from modules.ids_ips.engine.anomaly_detector import AnomalyDetector, TrafficFeatures
from modules.ids_ips.models import IPSConfig, IPSSignature
from sqlalchemy.orm import Session
from system.database.database import SessionLocal
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

class IPSEngine:
    """
    Intrusion Prevention System.
    Layers:
    1. Threat Intelligence (Known Bad IPs/Domains)
    2. Reputation Check
    3. Signature Matching (Snort-like rules)
    4. AI Anomaly Detection (Behavioral)
    """
    
    def __init__(self):
        self.logger = logger
        self.threat_intel = ThreatIntelligence()
        self.reputation = ReputationEngine()
        self.signature_engine = SignatureEngine()
        self.unified_deception = UnifiedDeceptionEngine()
        
        # Paths to AI models (centralized in ml/models/)
        from ml.models import get_model_path
        try:
            l3_path = get_model_path('ids_ips', 'l3_anomaly_detector.pkl')
        except (FileNotFoundError, ValueError):
            l3_path = None
        try:
            l7_path = get_model_path('ids_ips', 'l7_dpi_classifier.pkl')
        except (FileNotFoundError, ValueError):
            l7_path = None
        
        # It's better to load the models once here rather than on every evaluate to save latency
        self.ai_detector = AnomalyDetector(model_path=l3_path, l7_model_path=l7_path)
        self.default_action = Action.ALLOW
        
    def get_db_session(self) -> Session:
        return SessionLocal()

    def sync_config(self):
        """Loads DB Config and Update Signatures Engine"""
        db = self.get_db_session()
        try:
            config = db.query(IPSConfig).first()
            if not config:
                config = IPSConfig()
                db.add(config)
                db.commit()
                db.refresh(config)
                
            self.config = config
            
            # Load signatures from DB
            db_sigs = db.query(IPSSignature).filter(IPSSignature.enabled == True).all()
            self.signature_engine.load_from_db(db_sigs)
        finally:
            db.close()

    def evaluate(self, context: PolicyContext, payload: bytes = b"") -> Action:
        self.sync_config()
        
        if not self.config.is_active:
            return Action.ALLOW
            
        # 1. Threat Intelligence Check
        is_threat, threat_info = self.threat_intel.is_threat(context.src_ip, 'ip')
        if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
            self.logger.warning(f"IPS Blocked Source IP Threat: {context.src_ip} ({threat_info.source})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        is_threat, threat_info = self.threat_intel.is_threat(context.dst_ip, 'ip')
        if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
            self.logger.warning(f"IPS Blocked Dest IP Threat: {context.dst_ip} ({threat_info.source})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        if context.domain:
            is_threat, threat_info = self.threat_intel.is_threat(context.domain, 'domain')
            if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
                self.logger.warning(f"IPS Blocked Malicious Domain: {context.domain} ({threat_info.source})")
                if self.config.mode == "blocking": return Action.BLOCK
            
        # 2. Reputation Check
        rep = self.reputation.get_ip_reputation(context.src_ip)
        if rep.score <= ReputationLevel.MALICIOUS:
            self.logger.warning(f"IPS Blocked Low Reputation: {context.src_ip} ({rep.score})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        # 3. Signature Matching
        if payload:
            alerts = self.signature_engine.scan(payload)
            if alerts:
                for alert in alerts:
                    self.logger.warning(f"IPS Signature Match: {alert}")
                if getattr(self.config, 'deception_enabled', True):
                    trap_id, fake_banner = self.unified_deception.generate_trap(
                        module="ids_ips",
                        username="unknown",
                        source_ip=context.src_ip,
                        target_service=str(context.dst_port),
                        anomaly_score=1.0 # Signatures are highly certain
                    )
                    context.metrics = context.metrics or {}
                    context.metrics["deception_trap"] = fake_banner
                    return Action.DECEIVE
                    
                if self.config.mode == "blocking": return Action.BLOCK
        
        # 4. AI Anomaly Detection (L3 & L7)
        # We need TrafficFeatures object, ideally built by a preprocessor. 
        # Here we mock it or extract it if context provides it.
        # Assuming context.metrics holds the 21 features required if available, otherwise we skip.
        if hasattr(context, 'metrics') and context.metrics:
            try:
                features = TrafficFeatures(**context.metrics)
                result = self.ai_detector.detect(features)
                
                # Check Configuration Toggles and Thresholds
                block_anomaly = False
                
                if self.config.enable_l3_anomaly and result.is_anomaly and result.anomaly_score >= self.config.anomaly_threshold:
                    self.logger.warning(f"IPS ML Anomaly Detected! Score: {result.anomaly_score:.2f}")
                    block_anomaly = True
                    
                if self.config.enable_l7_dpi and result.details.get("l7_classification") in ["web_attack", "brute_force"]:
                    self.logger.warning(f"IPS L7 DPI Classified Attack: {result.details['l7_classification']} (Conf: {result.details.get('l7_confidence', 0):.2f})")
                    block_anomaly = True
                    
                if block_anomaly:
                    if getattr(self.config, 'deception_enabled', True):
                        trap_id, fake_banner = self.unified_deception.generate_trap(
                            module="ids_ips",
                            username="unknown",
                            source_ip=context.src_ip,
                            target_service=str(context.dst_port),
                            anomaly_score=result.anomaly_score
                        )
                        context.metrics["deception_trap"] = fake_banner
                        return Action.DECEIVE
                        
                    if self.config.mode == "blocking":
                        return Action.BLOCK
                        
            except Exception as e:
                self.logger.error(f"Error executing AI Detector: {e}")
                
        return Action.ALLOW
