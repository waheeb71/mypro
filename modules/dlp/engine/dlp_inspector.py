"""
Enterprise CyberNexus - Data Loss Prevention (DLP) Plugin

Scans payloads for sensitive information like Credit Cards, SSNs, and 
confidential keywords to prevent data exfiltration.
"""

import logging
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from modules.dlp.engine.dlp_engine import DLPEngine
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

class DLPInspectorPlugin(InspectorPlugin):
    """Inspects traffic for sensitive data leaks using dynamic cached rules."""
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="dlp_inspector", priority=60)
        self.unified_deception = UnifiedDeceptionEngine()
        self.engine = DLPEngine()
        
    def can_inspect(self, context: InspectionContext) -> bool:
        """DLP runs on all traffic, skip inbound unless configured"""
        return True

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW
        
        # Only inspect outbound traffic if specified, or all traffic
        if context.direction == "inbound" and not context.metadata.get("inspect_inbound_dlp", False):
            return InspectionResult(action=action, findings=[])

        # Attempt decoding payload for text-based pattern matching
        # In real CyberNexus, file_parser.py handles binaries, but here we do simple decoding
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except Exception:
            text_data = ""
            
        if not text_data:
            return InspectionResult(action=action, findings=[])

        try:
            if not self.engine.is_active:
                return InspectionResult(action=action, findings=[])
                
            block_policy = self.engine.block_on_match
            engine_findings = self.engine.evaluate(text_data)
            
            for f in engine_findings:
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity=f["severity"],
                        category="DLP",
                        description=f["description"],
                        confidence=0.9,
                        recommends_block=block_policy,
                        metadata={
                            "rule_id": f.get("rule_id"), 
                            "rule_name": f["rule_name"], 
                            "match_count": f["match_count"]
                        }
                    )
                )
            
            should_block = block_policy and bool(findings)
            action = InspectionAction.BLOCK if should_block else InspectionAction.ALLOW
            
            # Deception Flow: Inject Data Watermark Traps if enabled and there are findings
            if findings and self.engine.deception_enabled:
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
            
        return InspectionResult(action=action, findings=findings)
