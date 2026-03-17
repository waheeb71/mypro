import logging
import time
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from modules.firewall.models import FirewallRule as DBFirewallRule
from modules.firewall.policy.access_control.acl_engine import ACLEngine
from modules.firewall.policy.access_control.geoip import GeoIPFilter
from modules.firewall.policy.app_control.engine import AppControlEngine
from system.policy.schema import FirewallRule, AppRule, PolicyContext, Action, Protocol, TimeSchedule

logger = logging.getLogger(__name__)

class UnifiedEvaluator:
    """ Evaluates network traffic seamlessly against multiple firewall module policy engines """
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.acl_engine = ACLEngine()
        self.app_engine = AppControlEngine()
        self.geoip_filter = GeoIPFilter()  # Configure with DB paths if required later
        
        self._load_rules()
        
    def _parse_schedule(self, schedule_str: str) -> Optional[TimeSchedule]:
        if not schedule_str or schedule_str.lower() == "always":
            return None
        # Simplified: Assuming schedule string is comma separated: "Mon,Tue,09:00,17:00" for demo
        # In a real system, you'd look this up from a Schedules table.
        parts = schedule_str.split(',')
        if len(parts) >= 4:
            days = parts[:-2]
            return TimeSchedule(name="ParsedSchedule", days=days, start_time=parts[-2], end_time=parts[-1])
        return None

    def _load_rules(self):
        """ Loads rules from database and maps them to policy schemas """
        if not self.db_session:
            return
            
        try:
            db_rules = self.db_session.query(DBFirewallRule)\
                                      .filter(DBFirewallRule.enabled == True)\
                                      .order_by(DBFirewallRule.priority.asc(), DBFirewallRule.id.asc())\
                                      .all()
            
            acl_rules = []
            app_rules = []
            
            for dbr in db_rules:
                action_enum = Action.ALLOW
                if dbr.action.value == "DROP": action_enum = Action.BLOCK
                elif dbr.action.value == "REJECT": action_enum = Action.REJECT
                elif dbr.action.value == "LOG": action_enum = Action.LOG_ONLY
                
                proto = Protocol.ANY
                if dbr.protocol.lower() == "tcp": proto = Protocol.TCP
                elif dbr.protocol.lower() == "udp": proto = Protocol.UDP
                elif dbr.protocol.lower() == "icmp": proto = Protocol.ICMP
                
                # If app_category is strictly any, or we treat it as an L3/L4 rule primarily:
                if dbr.app_category == "any":
                    acl_rule = FirewallRule(
                        id=str(dbr.id),
                        name=dbr.name,
                        action=action_enum,
                        enabled=dbr.enabled,
                        priority=dbr.priority,
                        src_zone=dbr.zone_src,
                        dst_zone=dbr.zone_dst,
                        src_ip=dbr.source_ip,
                        dst_ip=dbr.destination_ip,
                        src_port=dbr.source_port,
                        dst_port=dbr.destination_port,
                        protocol=proto,
                        schedule=self._parse_schedule(dbr.schedule),
                        log=dbr.log_traffic
                    )
                    acl_rules.append(acl_rule)
                else:
                    # Treat as App Rule
                    app_rule = AppRule(
                        id=str(dbr.id),
                        name=dbr.name,
                        action=action_enum,
                        enabled=dbr.enabled,
                        priority=dbr.priority,
                        application="any", # In full implementation, map file_type or app_category
                        category=dbr.app_category,
                        schedule=self._parse_schedule(dbr.schedule),
                        log=dbr.log_traffic
                    )
                    app_rules.append(app_rule)
            
            self.acl_engine.load_rules(acl_rules)
            self.app_engine.load_rules(app_rules)
            logger.debug(f"Loaded {len(acl_rules)} ACL rules and {len(app_rules)} App rules.")
            
        except Exception as e:
            logger.error(f"Failed to load firewall rules: {e}")
                
    def reload(self):
        """ Reload rules from database """
        self._load_rules()
        
    def evaluate(self, context_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a context dict against the unified rulebase (GeoIP -> ACL -> App Control).
        """
        try:
            # 1. GeoIP evaluation
            src_ip = context_dict.get('src_ip', '')
            if src_ip:
                is_blocked, reason = self.geoip_filter.is_blocked(src_ip)
                if is_blocked:
                    return {"action": "DROP", "confidence": 1.0, "reason": reason, "rule_name": "GeoIP Block"}

            # Build PolicyContext
            context = PolicyContext(
                src_ip=src_ip,
                dst_ip=context_dict.get('dst_ip', ''),
                src_port=context_dict.get('src_port', 0),
                dst_port=context_dict.get('dst_port', 0),
                protocol=context_dict.get('protocol', 'any'),
                interface=context_dict.get('interface', 'any'),
                app_id=context_dict.get('app_id')
            )
            
            # 2. Layer 3/4 ACL evaluation
            acl_action = self.acl_engine.evaluate(context)
            if acl_action in [Action.BLOCK, Action.REJECT]:
                return {"action": acl_action.value.upper(), "confidence": 1.0, "reason": "Matched ACL Rule", "rule_name": "ACLEngine"}
                
            # 3. Layer 7 App Control evaluation if App_ID is present or domains are known
            if context.app_id or context_dict.get('domain'):
                if not context.app_id:
                    context.domain = context_dict['domain']
                app_action = self.app_engine.evaluate(context)
                if app_action in [Action.BLOCK, Action.REJECT]:
                    return {"action": app_action.value.upper(), "confidence": 1.0, "reason": "Matched App Rule", "rule_name": "AppEngine"}
            
            # 4. Default Allow (since ACL passed and App didn't block or wasn't applicable)
            return {"action": "ALLOW", "confidence": 0.8, "reason": "Allowed by Unified Policy", "rule_name": "Default"}
            
        except Exception as e:
            logger.error(f"Error during policy evaluation: {e}")
            return {"action": "DROP", "confidence": 0.0, "reason": f"Evaluation Error: {e}", "rule_name": "Error"}
