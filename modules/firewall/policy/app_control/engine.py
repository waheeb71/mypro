"""
Application Control Engine
Layer 7 Policy Enforcement
"""

import logging
from typing import List
from datetime import datetime
from system.policy.schema import AppRule, PolicyContext, Action
from .signatures import EncryptedAppSignatures

logger = logging.getLogger(__name__)

class AppControlEngine:
    """
    Evaluates Application Control Rules.
    Focuses on identified applications (Facebook, WhatsApp, TikTok)
    regardless of port/protocol.
    """
    
    def __init__(self):
        self.rules: List[AppRule] = []
        self.logger = logger
        self.default_action = Action.ALLOW

    def load_rules(self, rules: List[AppRule]):
        self.rules = sorted(rules, key=lambda r: r.priority)
        self.logger.info(f"Loaded {len(self.rules)} App Control rules")

    def evaluate(self, context: PolicyContext) -> Action:
        """Evaluate identified application against rules"""
        
        # Try to identify App ID if not present
        if not context.app_id and context.domain:
            context.app_id = EncryptedAppSignatures.identify_by_sni(context.domain)
            if context.app_id:
                self.logger.debug(f"Identified App: {context.app_id} from SNI: {context.domain}")

        if not context.app_id:
            return Action.ALLOW

        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._match_rule(rule, context):
                self.logger.info(f"Matched App Rule: {rule.name} [{context.app_id}] -> {rule.action.value}")
                return rule.action
                
        return self.default_action

    def _match_rule(self, rule: AppRule, context: PolicyContext) -> bool:
        # 0. Time Schedule Match
        if rule.schedule:
            if not self._match_schedule(rule.schedule):
                return False

        # 1. Match Application Name
        if rule.application != "any" and rule.application.lower() != context.app_id.lower():
            return False
            
        # 2. Match Category
        # App Categories would typically be mapped via the signature database.
        # Assuming EncryptedAppSignatures can return a category for an app_id
        if rule.category:
            # Placeholder logic for obtaining an app's category from signature metadata
            app_category = getattr(EncryptedAppSignatures, 'get_category', lambda x: None)(context.app_id)
            # If the app's category doesn't match the rule's category, skip the rule
            if app_category and app_category.lower() != rule.category.lower():
                return False
            
        # 3. Match User/Group
        if rule.users and context.user_id:
            # user_id string might contain group information if integrated with Active Directory
            # Format expectation: "username", "group:Marketing", etc.
            if context.user_id not in rule.users:
                # Also check if any group the user belongs to is in the rule (Stub implementation)
                user_groups = getattr(context, 'groups', []) # Fallback to empty list if no groups
                if not any(group in rule.users for group in user_groups):
                    return False
        
        return True

    def _match_schedule(self, schedule) -> bool:
        """Check if current time falls within rule schedule (Copied from ACLEngine)"""
        now = datetime.now()
        current_day = now.strftime("%a")
        
        if current_day not in schedule.days:
            return False
            
        try:
            now_time = now.time()
            start_time = datetime.strptime(schedule.start_time, "%H:%M").time()
            end_time = datetime.strptime(schedule.end_time, "%H:%M").time()
            return start_time <= now_time <= end_time
        except Exception as e:
            self.logger.error(f"Schedule parse error in AppControl: {e}")
            return False
