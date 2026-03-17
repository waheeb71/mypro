import logging
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from .http_analyzer import HTTPAnalyzer

logger = logging.getLogger(__name__)

class HTTPInspectorPlugin(InspectorPlugin):
    """ HTTP Inspection Plugin for detecting L7 anomalies. """
    
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="http_inspection", priority=30)
        self.block_on_match = block_on_match
        self.analyzer = HTTPAnalyzer()
        
    def can_inspect(self, context: InspectionContext) -> bool:
        # Only inspect HTTP traffic
        if context.protocol == "http" or context.metadata.get("is_http", False):
            return True
        return False
        
    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW
        
        result = self.analyzer.analyze_request(data)
        
        if result.get("is_anomalous"):
            reasons = result.get("reasons", [])
            score = result.get("risk_score", 0)
            
            findings.append(
                InspectionFinding(
                    plugin_name=self.name,
                    severity="HIGH" if score > 50 else "MEDIUM",
                    category="HTTP_ANOMALY",
                    description=f"HTTP Traffic Anomalies: {', '.join(reasons)}",
                    confidence=0.85,
                    metadata={"reasons": reasons, "score": score}
                )
            )
            
            # Decide action based on score
            if self.block_on_match and score >= 30:
                action = InspectionAction.BLOCK
                
        return InspectionResult(action=action, findings=findings)
