import logging
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from .url_checker import URLChecker

logger = logging.getLogger(__name__)

class WebFilterPlugin(InspectorPlugin):
    """ Web Filtering Plugin for the inspection pipeline. """
    
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="web_filter", priority=40)
        self.block_on_match = block_on_match
        self.checker = URLChecker()
        
    def can_inspect(self, context: InspectionContext) -> bool:
        # We need a URL or HOST to filter. 
        if context.protocol in ("http", "https") or "host" in context.metadata or "url" in context.metadata:
            return True
        return False
        
    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW
        
        # Try metadata first
        target_url = context.metadata.get("url") or context.metadata.get("host")
        
        # Fallback: very basic extraction from passing HTTP data if proxy didn't fill it
        if not target_url and context.protocol == "http":
            try:
                head = data[:512].decode('utf-8', errors='ignore')
                for line in head.split('\n'):
                    if line.lower().startswith('host:'):
                        target_url = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass
                
        if target_url:
            chk_action, category, risk = self.checker.check_url(target_url)
            
            if chk_action == "BLOCK":
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity="HIGH",
                        category="WEB_FILTER",
                        description=f"Blocked by categorized policy: {category} (Risk: {risk})",
                        confidence=0.9,
                        metadata={"category": category, "target": target_url}
                    )
                )
                if self.block_on_match:
                    action = InspectionAction.BLOCK
                    
        return InspectionResult(action=action, findings=findings)
