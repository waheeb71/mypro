import logging
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from system.policy.schema import Action
from modules.web_filter.policy.engine import WebFilterEngine

logger = logging.getLogger(__name__)

class WebFilterPlugin(InspectorPlugin):
    """ Web Filtering Plugin for the inspection pipeline. """
    
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="web_filter", priority=40)
        self.block_on_match = block_on_match
        self.engine = WebFilterEngine()
        
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
            domain = target_url
            if target_url.startswith("http"):
                from urllib.parse import urlparse
                try:
                    domain = urlparse(target_url).netloc.lower()
                    if domain.startswith("www."):
                        domain = domain[4:]
                except Exception:
                    domain = target_url
            else:
                 if domain.startswith("www."):
                     domain = domain[4:]
                     
            result_action = self.engine.evaluate(url=target_url, domain=domain)
            
            if result_action in (Action.BLOCK, Action.REJECT):
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity="HIGH",
                        category="WEB_FILTER",
                        description=f"Blocked by categorized policy",
                        confidence=0.9,
                        metadata={"target": target_url, "domain": domain}
                    )
                )
                if self.block_on_match:
                    action = InspectionAction.BLOCK
                    
        return InspectionResult(action=action, findings=findings)
