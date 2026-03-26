"""
Web Filter Engine
URL Filtering, Safe Search, and Category Blocking based on DB policies.
"""

import logging
import fnmatch
from typing import List
from system.policy.schema import WebFilterRule, PolicyContext, Action
from system.database.database import SessionLocal
from modules.web_filter.models import WebFilterConfig
from modules.web_filter.policy.category import CategoryEngine
from modules.web_filter.policy.safe_search import SafeSearch

logger = logging.getLogger(__name__)

class WebFilterEngine:
    """
    Evaluates Web Filtering Rules and global settings.
    - Global Safe Search Enforcement
    - Category-based Actions (ALLOW/BLOCK) from DB
    """
    
    def __init__(self):
        self.rules: List[WebFilterRule] = []
        self.logger = logger
        self.category_engine = CategoryEngine()
        self.config = self._load_config()

    def _load_config(self) -> WebFilterConfig:
        with SessionLocal() as db:
            conf = db.query(WebFilterConfig).first()
            if not conf:
                conf = WebFilterConfig()
                db.add(conf)
                db.commit()
                db.refresh(conf)
            return conf

    def reload(self):
        self.config = self._load_config()
        self.category_engine.reload()

    def evaluate(self, url: str, domain: str) -> Action:
        """Evaluate web request against global config and categorizations"""
        if not self.config.enabled:
            return Action.ALLOW
            
        # 1. Safe Search Enforcement
        if self.config.safe_search_enabled and domain:
             if "google.com" in domain or "bing.com" in domain or "youtube.com" in domain:
                 # In a true proxy, rewrite URL or return MONITOR to indicate interception.
                 self.logger.info(f"WebFilter Enforcing Safe Search for: {domain}")
                 # You could return Action.CHALLENGE or similar to rewrite
                 pass # We rely on proxy/DNS level for CNAME enforcement or return specific action if we intercept HTTP

        # 2. Categorize the domain
        match = self.category_engine.categorize(domain)
        
        # 3. Apply action based on the highest priority category match
        for cat in match.categories:
            if cat == "UNRATED":
                continue
            
            action_map = {
                "ALLOW": Action.ALLOW,
                "BLOCK": Action.BLOCK,
                "REJECT": Action.REJECT,
                "MONITOR": Action.MONITOR
            }
            
            action_str = self.category_engine.get_category_action(cat)
            action = action_map.get(action_str, Action.BLOCK)
            
            if action in (Action.BLOCK, Action.REJECT):
                self.logger.info(f"WebFilter Blocked Domain '{domain}' due to category '{cat}'")
                return action
            elif action == Action.ALLOW:
                 # If explicitly allowed, return ALLOW immediately
                 return Action.ALLOW
                 
        # By default, rely on global config
        default_act_str = self.config.default_action.upper()
        if default_act_str == "ALLOW":
            return Action.ALLOW
        else:
            return Action.BLOCK
