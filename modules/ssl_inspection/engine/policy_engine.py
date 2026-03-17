#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SSL Policy Engine - Inspection Decision Maker
═══════════════════════════════════════════════════════════════════

Determines whether to inspect or bypass SSL/TLS connections based on:
- Domain bypass lists
- IP bypass lists
- Certificate pinning detection
- Application identification
- User/group policies

Author: Enterprise Security Team
"""

import logging
import re
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class SSLAction(Enum):
    """SSL inspection action"""
    INSPECT = "inspect"       # Full SSL interception
    BYPASS = "bypass"         # Pass through without inspection
    BLOCK = "block"           # Block connection
    MONITOR = "monitor"       # Log only, no interception


class SSLPolicyEngine:
    """
    SSL Policy Engine
    
    Makes decisions about SSL/TLS inspection.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.ssl_config = config.get('ssl_inspection', {})
        
        # Global enable/disable
        self.enabled = self.ssl_config.get('enabled', True)
        
        # Bypass lists
        self.bypass_domains = self.ssl_config.get('bypass_domains', [])
        self.bypass_ips = self.ssl_config.get('bypass_ips', [])
        self.bypass_categories = self.ssl_config.get('bypass_categories', [])
        
        # Pinning detection
        self.detect_pinning = self.ssl_config.get('detect_pinning', True)
        self.pinning_action = SSLAction(
            self.ssl_config.get('pinning_action', 'bypass')
        )
        
        # Statistics
        self.stats = {
            'total_decisions': 0,
            'inspected': 0,
            'bypassed': 0,
            'blocked': 0,
        }
        
        logger.info(f"SSL Policy Engine initialized (enabled={self.enabled})")
        logger.info(f"Bypass domains: {len(self.bypass_domains)}")
        logger.info(f"Bypass IPs: {len(self.bypass_ips)}")
    
    def decide(self,
              client_ip: str,
              target_host: Optional[str],
              target_port: int = 443,
              **kwargs) -> SSLAction:
        """
        Decide whether to inspect SSL connection
        
        Args:
            client_ip: Client IP address
            target_host: Target hostname
            target_port: Target port
            **kwargs: Additional context (category, application, etc.)
        
        Returns:
            SSLAction (INSPECT, BYPASS, BLOCK, MONITOR)
        """
        self.stats['total_decisions'] += 1
        
        # Step 1: Check if SSL inspection is globally enabled
        if not self.enabled:
            logger.debug("SSL inspection globally disabled")
            return self._record_action(SSLAction.BYPASS)
        
        # Step 2: Check IP bypass list
        if client_ip in self.bypass_ips:
            logger.debug(f"SSL inspection bypassed for IP {client_ip}")
            return self._record_action(SSLAction.BYPASS)
        
        # Step 3: Check domain bypass list
        if target_host:
            if self._is_bypassed_domain(target_host):
                logger.debug(f"SSL inspection bypassed for domain {target_host}")
                return self._record_action(SSLAction.BYPASS)
        
        # Step 4: Check category bypass
        category = kwargs.get('category')
        if category and category in self.bypass_categories:
            logger.debug(f"SSL inspection bypassed for category {category}")
            return self._record_action(SSLAction.BYPASS)
        
        # Step 5: Check for certificate pinning (if enabled)
        if self.detect_pinning:
            is_pinned = self._detect_pinning(target_host, **kwargs)
            if is_pinned:
                logger.info(f"Certificate pinning detected for {target_host}")
                return self._record_action(self.pinning_action)
        
        # Step 6: Check user/group policies (future enhancement)
        username = kwargs.get('username')
        if username:
            action = self._check_user_policy(username, target_host)
            if action:
                return self._record_action(action)
        
        # Default: Inspect
        logger.debug(f"SSL inspection enabled for {target_host}")
        return self._record_action(SSLAction.INSPECT)
    
    def _is_bypassed_domain(self, domain: str) -> bool:
        """Check if domain is in bypass list (supports wildcards)"""
        for pattern in self.bypass_domains:
            if self._match_domain(domain, pattern):
                return True
        return False
    
    def _match_domain(self, domain: str, pattern: str) -> bool:
        """Match domain against pattern (supports wildcards)"""
        # Exact match
        if domain.lower() == pattern.lower():
            return True
        
        # Wildcard match
        regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
        return bool(re.match(f'^{regex_pattern}$', domain, re.IGNORECASE))
    
    def _detect_pinning(self, target_host: Optional[str], **kwargs) -> bool:
        """
        Detect certificate pinning
        
        Heuristics:
        - Known pinned domains (hardcoded list)
        - Mobile app user-agents
        - Specific applications
        
        Future: Deep packet inspection to detect actual pinning
        """
        if not target_host:
            return False
        
        # Known pinned services
        pinned_domains = [
            'banking.app',
            'mobile.bank.com',
            'api.twitter.com',
            'api.facebook.com',
            # Add more as needed
        ]
        
        for pinned in pinned_domains:
            if target_host.endswith(pinned):
                return True
        
        # Check user-agent for mobile apps
        user_agent = kwargs.get('user_agent', '')
        if 'Mobile' in user_agent or 'Android' in user_agent or 'iOS' in user_agent:
            # Mobile apps are more likely to use pinning
            # This is a heuristic, not definitive
            pass
        
        return False
    
    def _check_user_policy(self, username: str, target_host: Optional[str]) -> Optional[SSLAction]:
        """
        Check user/group specific policies
        
        Future enhancement: LDAP/AD integration
        """
        # Placeholder for user-based policies
        # Example:
        # if username in ['admin', 'security_team']:
        #     return SSLAction.MONITOR
        
        return None
    
    def _record_action(self, action: SSLAction) -> SSLAction:
        """Record action in statistics"""
        if action == SSLAction.INSPECT:
            self.stats['inspected'] += 1
        elif action == SSLAction.BYPASS:
            self.stats['bypassed'] += 1
        elif action == SSLAction.BLOCK:
            self.stats['blocked'] += 1
        
        return action
    
    def get_statistics(self) -> dict:
        """Get policy statistics"""
        return self.stats.copy()
    
    def add_bypass_domain(self, domain: str):
        """Dynamically add domain to bypass list"""
        if domain not in self.bypass_domains:
            self.bypass_domains.append(domain)
            logger.info(f"Added {domain} to SSL bypass list")
    
    def remove_bypass_domain(self, domain: str):
        """Remove domain from bypass list"""
        if domain in self.bypass_domains:
            self.bypass_domains.remove(domain)
            logger.info(f"Removed {domain} from SSL bypass list")
    
    def add_bypass_ip(self, ip: str):
        """Dynamically add IP to bypass list"""
        if ip not in self.bypass_ips:
            self.bypass_ips.append(ip)
            logger.info(f"Added {ip} to SSL bypass list")
    
    def remove_bypass_ip(self, ip: str):
        """Remove IP from bypass list"""
        if ip in self.bypass_ips:
            self.bypass_ips.remove(ip)
            logger.info(f"Removed {ip} from SSL bypass list")
