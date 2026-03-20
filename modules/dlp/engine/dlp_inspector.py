"""
Enterprise NGFW - Data Loss Prevention (DLP) Plugin

Scans payloads for sensitive information like Credit Cards, SSNs, and 
confidential keywords to prevent data exfiltration.
"""

import re
import logging
from dataclasses import dataclass
from typing import List
from sqlalchemy.orm import Session
from system.database.database import get_db, SessionLocal
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from modules.dlp.models import DLPRule, DLPConfig
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

@dataclass
class CompiledDLPRule:
    id: int
    name: str
    pattern: re.Pattern
    severity: str
    description: str

class DLPInspectorPlugin(InspectorPlugin):
    """Inspects traffic for sensitive data leaks using dynamic DB rules."""
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="dlp_inspector", priority=60)
        self.block_on_match = block_on_match
        self.unified_deception = UnifiedDeceptionEngine()
        
    def can_inspect(self, context: InspectionContext) -> bool:
        """DLP runs on all traffic, skip inbound unless configured"""
        return True

    def get_db_session(self) -> Session:
        return SessionLocal()
        
    def _load_rules(self, db: Session) -> List[CompiledDLPRule]:
        db_rules = db.query(DLPRule).filter(DLPRule.enabled == True).all()
        compiled = []
        for r in db_rules:
            try:
                # Use ignorecase wrapper by default for regex patterns
                pat = re.compile(r.pattern, re.IGNORECASE)
                compiled.append(CompiledDLPRule(
                    id=r.id,
                    name=r.name,
                    pattern=pat,
                    severity=r.severity,
                    description=r.description or f"DLP rule '{r.name}' triggered"
                ))
            except Exception as e:
                logger.error(f"Failed to compile DLP rule {r.name}: {e}")
        return compiled

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW
        
        # Only inspect outbound traffic if specified, or all traffic
        if context.direction == "inbound" and not context.metadata.get("inspect_inbound_dlp", False):
            return InspectionResult(action=action, findings=[])

        # Attempt decoding payload for text-based pattern matching
        # In real NGFW, file_parser.py handles binaries, but here we do simple decoding
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except Exception:
            text_data = ""
            
        if not text_data:
            return InspectionResult(action=action, findings=[])

        db = self.get_db_session()
        try:
            config = db.query(DLPConfig).first()
            if not config or not config.is_active:
                return InspectionResult(action=action, findings=[])
                
            block_policy = config.block_on_match
                
            rules = self._load_rules(db)
            
            for rule in rules:
                matches = rule.pattern.findall(text_data)
                if matches:
                    findings.append(
                        InspectionFinding(
                            plugin_name=self.name,
                            severity=rule.severity,
                            category="DLP",
                            description=f"{rule.description} (Matched {len(matches)} times)",
                            confidence=0.8,
                            recommends_block=block_policy,
                            metadata={"rule_id": rule.id, "rule_name": rule.name, "match_count": len(matches)}
                        )
                    )
            
            
            should_block = block_policy and bool(findings)
            action = InspectionAction.BLOCK if should_block else InspectionAction.ALLOW
            
            # Deception Flow: Inject Data Watermark Traps if enabled and there are findings
            if findings and getattr(config, 'deception_enabled', True):
                trap_id, watermark_payload = self.unified_deception.generate_trap(
                    module="dlp",
                    username=context.metadata.get("username", "unknown"),
                    source_ip=context.src_ip,
                    target_service="egress_dlp",
                    anomaly_score=1.0 # Exfiltration match is a definitive alert
                )
                action = InspectionAction.DECEIVE
                # Attach the watermark trap info for the core pipeline to handle 
                context.metrics = context.metrics or {}
                context.metrics["deception_trap"] = watermark_payload
                
        except Exception as e:
            logger.error(f"DLP inspection failed: {e}")
        finally:
            db.close()
            
        return InspectionResult(action=action, findings=findings)
