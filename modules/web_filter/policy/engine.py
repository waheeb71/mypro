"""
Web Filter Engine
URL Filtering, Safe Search, and Category Blocking
"""

import logging
import fnmatch
from typing import List
from system.policy.schema import WebFilterRule, PolicyContext, Action
from .category import CategoryEngine, ContentCategory

logger = logging.getLogger(__name__)

class WebFilterEngine:
    """
    Evaluates Web Filtering Rules.
    - Category Blocking (Gambling, Adult, etc.)
    - Exact URL Blocking
    - Safe Search Enforcement
    """
    
    def __init__(self):
        self.rules: List[WebFilterRule] = []
        self.logger = logger
        self.category_engine = CategoryEngine()
        self.default_action = Action.ALLOW

    def load_rules(self, rules: List[WebFilterRule]):
        self.rules = rules
        self.logger.info(f"Loaded {len(self.rules)} Web Filter rules")

    def evaluate(self, context: PolicyContext) -> Action:
        """Evaluate web request"""
        if not context.domain and not context.url:
            return Action.ALLOW
            
        # Get category of the requested domain
        domain_categories = []
        if context.domain:
            match = self.category_engine.categorize(context.domain)
            # The categorize method returns ContentCategory enums (IntEnum). 
            # We convert the IntEnum `.name` to lowercase string to match rule logic which expects strings like "social_networking"
            domain_categories = [cat.name.lower() for cat in match.categories]

        # Iterate through rules according to priority
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            match = False
            
            # 1. Rule-based Categories Check
            if domain_categories and rule.categories:
                # Check if there is an intersection between the domain's categories and rule's blocked categories
                blocked_cats = [cat.lower() for cat in rule.categories]
                intersection = set(domain_categories).intersection(set(blocked_cats))
                
                if intersection:
                    self.logger.info(f"WebFilter Rule '{rule.name}' Blocked Category '{intersection}': {context.domain}")
                    match = True
                
            # 2. File Types Check
            if not match and context.url and rule.block_file_types:
                url_lower = context.url.lower()
                if any(url_lower.endswith(f".{ext.strip('.')}") for ext in rule.block_file_types):
                    self.logger.info(f"WebFilter Rule '{rule.name}' Blocked File Type: {context.url}")
                    match = True
                    
            # 3. Exact & Wildcard URLs Check
            if not match and context.url and rule.exact_urls:
                for target_url in rule.exact_urls:
                    # Support wildcards like *example.com/admin*
                    if fnmatch.fnmatch(context.url, target_url):
                        self.logger.info(f"WebFilter Rule '{rule.name}' Blocked URL Pattern '{target_url}': {context.url}")
                        match = True
                        break
                        
            # 4. Exact Domain fallback logic inside wildcard check
            if not match and context.domain and rule.exact_urls:
                 for target_url in rule.exact_urls:
                    if fnmatch.fnmatch(context.domain, target_url):
                        self.logger.info(f"WebFilter Rule '{rule.name}' Blocked Domain Pattern '{target_url}': {context.domain}")
                        match = True
                        break
            
            # 5. Safe Search Enforcement
            if not match and rule.safe_search and context.domain:
                if "google.com" in context.domain or "bing.com" in context.domain or "youtube.com" in context.domain:
                    # In a true proxy, we would rewrite the URL to append ?safe=active. 
                    # Here we simulate the enforcement action.
                    self.logger.info(f"WebFilter Rule '{rule.name}' Enforcing Safe Search for: {context.domain}")
                    # Usually returned as a special action or handled transparently. returning MONITOR to indicate interception.
                    return Action.MONITOR
            
            if match:
                return rule.action
        
        return self.default_action
