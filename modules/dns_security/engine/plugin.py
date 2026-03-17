import logging
import fnmatch
from sqlalchemy.orm import Session
from system.database.database import get_db, SessionLocal
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from .dga_detector import DGADetector
from .tunneling_detector import DNSTunnelingDetector
from modules.dns_security.models import DNSFilterRule, DNSModuleConfig, FilterType, ActionEnum

logger = logging.getLogger(__name__)

class DNSSecurityPlugin(InspectorPlugin):
    """ DNS Security Plugin for DGA, Tunneling detection, and Domain Filtering """
    
    def __init__(self, block_on_match: bool = True):
        super().__init__(name="dns_security", priority=20)
        self.block_on_match = block_on_match
        
    def can_inspect(self, context: InspectionContext) -> bool:
        # Check if traffic is DNS
        if context.protocol == "dns" or context.metadata.get("is_dns", False):
            return True
        return False
        
    def get_db_session(self) -> Session:
        return SessionLocal()
        
    def _check_domain_filters(self, domain: str, db: Session) -> InspectionResult:
        rules = db.query(DNSFilterRule).filter(DNSFilterRule.enabled == True).all()
        for rule in rules:
            match = False
            if rule.filter_type == FilterType.EXACT:
                match = (domain.lower() == rule.domain_pattern.lower())
            elif rule.filter_type == FilterType.WILDCARD:
                match = fnmatch.fnmatchcase(domain.lower(), rule.domain_pattern.lower())
                
            if match:
                action = InspectionAction.BLOCK if rule.action == ActionEnum.BLOCK else InspectionAction.ALLOW
                # If explicit allow, return early without checking DGA/Tunneling
                if action == InspectionAction.ALLOW:
                    return InspectionResult(action=InspectionAction.ALLOW, findings=[])
                    
                finding = InspectionFinding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    category="DNS_FILTER",
                    description=f"Domain matched blocklist rule '{rule.domain_pattern}': {domain}",
                    confidence=1.0
                )
                return InspectionResult(action=action, findings=[finding])
        return None

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW
        
        # Domain name from metadata (extracted by proxy or flow tracker)
        domain = context.metadata.get("domain", "")
        qtype = context.metadata.get("query_type", "A")
        
        if not domain:
             return InspectionResult(action=action, findings=findings)
             
        db = self.get_db_session()
        try:
            config = db.query(DNSModuleConfig).first()
            if not config or not config.is_active:
                return InspectionResult(action=action, findings=findings)
                
            # 1. Check Custom Domain Filters
            filter_result = self._check_domain_filters(domain, db)
            if filter_result:
                # If it's a block, or an explicit allow whitelist
                return filter_result
                
            # 2. Check DGA
            if config.enable_dga_detection and DGADetector.is_dga(domain, config.dga_entropy_threshold):
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity="HIGH",
                        category="DGA_DETECTED",
                        description=f"High entropy domain detected (Possible DGA): {domain}",
                        confidence=0.9
                    )
                )
                if self.block_on_match:
                    action = InspectionAction.BLOCK
                    
            # 3. Check Tunneling
            if config.enable_tunneling_detection and DNSTunnelingDetector.is_tunneling(domain, qtype):
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        category="DNS_TUNNELING",
                        description=f"DNS Tunneling characteristics detected: {domain}",
                        confidence=0.95
                    )
                )
                if self.block_on_match:
                    action = InspectionAction.BLOCK
                    
        except Exception as e:
            logger.error(f"DNS Plugin inspection error: {e}")
        finally:
            db.close()
            
        return InspectionResult(action=action, findings=findings)

