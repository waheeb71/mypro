#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise CyberNexus - Decision Engine Enhancement Methods

Additional methods for Phase 2 enhancements:
- Rate limiting
- Quarantine
- Fail-safe modes

These methods extend BlockingDecisionEngine functionality.
"""

import asyncio
import logging
from typing import Optional
from .decision_engine import BlockingDecision, BlockingAction, FailMode


logger = logging.getLogger(__name__)


class DecisionEngineEnhancements:
    """
    Mixin class for Decision Engine enhancements
    
    This provides additional functionality for:
    - Rate limiting
    - Quarantine management
    - Fail-safe modes
    """
    
    async def apply_rate_limit(
        self,
        ip: str,
        rate: int,
        ttl: int = 3600,
        reason: str = "Rate limit exceeded"
    ) -> BlockingDecision:
        """
        Apply rate limiting to an IP address
        
        Args:
            ip: IP address to rate limit
            rate: Maximum requests per second
            ttl: Time to live in seconds
            reason: Reason for rate limit
            
        Returns:
            BlockingDecision with RATE_LIMIT action
        """
        # Add to TTL manager
        await self.ttl_manager.add_rate_limit(ip, ttl, rate, reason)
        
        # Update statistics
        with self._lock:
            self._rate_limited_decisions += 1
        
        # Create decision
        decision = BlockingDecision(
            action=BlockingAction.RATE_LIMIT,
            reasons=[reason],
            confidence=1.0,
            sources=['rate_limiter'],
            metadata={
                'ip': ip,
                'rate': rate,
                'ttl': ttl
            }
        )
        
        self.logger.info(f"Applied rate limit to {ip}: {rate} req/s (TTL: {ttl}s)")
        return decision
    
    async def quarantine_ip(
        self,
        ip: str,
        ttl: int = 7200,
        reason: str = "Quarantined due to suspicious activity"
    ) ->BlockingDecision:
        """
        Quarantine an IP address
        
        Args:
            ip: IP address to quarantine
            ttl: Time to live in seconds
            reason: Reason for quarantine
            
        Returns:
            BlockingDecision with QUARANTINE action
        """
        # Add to TTL manager
        await self.ttl_manager.add_quarantine(ip, ttl, reason)
        
        # Update statistics
        with self._lock:
            self._quarantined_decisions += 1
        
        # Create decision
        decision = BlockingDecision(
            action=BlockingAction.QUARANTINE,
            reasons=[reason],
            confidence=1.0,
            sources=['quarantine_system'],
            metadata={
                'ip': ip,
                'ttl': ttl
            }
        )
        
        self.logger.warning(f"Quarantined IP {ip} (TTL: {ttl}s): {reason}")
        return decision
    
    async def check_ttl_restrictions(self, ip: str) -> Optional[BlockingDecision]:
        """
        Check if IP has any active TTL restrictions
        
        Args:
            ip: IP address to check
            
        Returns:
            BlockingDecision if restricted, None otherwise
        """
        # Check for active blocks
        if self.ttl_manager.is_active('BLOCK', ip):
            entry = self.ttl_manager.get_entry('BLOCK', ip)
            return BlockingDecision(
                action=BlockingAction.BLOCK,
                reasons=[entry.reason],
                confidence=1.0,
                sources=['ttl_block'],
                metadata={
                    'time_remaining': entry.time_remaining(),
                    'created_at': entry.created_at.isoformat()
                }
            )
        
        # Check for rate limits
        if self.ttl_manager.is_active('RATE_LIMIT', ip):
            entry = self.ttl_manager.get_entry('RATE_LIMIT', ip)
            return BlockingDecision(
                action=BlockingAction.RATE_LIMIT,
                reasons=[entry.reason],
                confidence=1.0,
                sources=['ttl_rate_limit'],
                metadata={
                    **entry.metadata,
                    'time_remaining': entry.time_remaining()
                }
            )
        
        # Check for quarantine
        if self.ttl_manager.is_active('QUARANTINE', ip):
            entry = self.ttl_manager.get_entry('QUARANTINE', ip)
            return BlockingDecision(
                action=BlockingAction.QUARANTINE,
                reasons=[entry.reason],
                confidence=1.0,
                sources=['ttl_quarantine'],
                metadata={
                    'time_remaining': entry.time_remaining(),
                    'created_at': entry.created_at.isoformat()
                }
            )
        
        return None
    
    def apply_fail_safe_mode(
        self,
        component_name: str,
        error: Exception
    ) -> BlockingDecision:
        """
        Apply fail-safe decision when a component fails
        
        Args:
            component_name: Name of failed component
            error: Exception that occurred
            
        Returns:
            BlockingDecision based on fail_mode
        """
        self.logger.error(
            f"Component '{component_name}' failed: {error}. "
            f"Applying fail-safe mode: {self.fail_mode.name}"
        )
        
        if self.fail_mode == FailMode.FAIL_CLOSED:
            # Block traffic when components fail
            return BlockingDecision(
                action=BlockingAction.BLOCK,
                reasons=[f"Component failure: {component_name}"],
                confidence=1.0,
                sources=['fail_safe_closed'],
                metadata={
                    'component': component_name,
                    'error': str(error),
                    'fail_mode': 'fail_closed'
                }
            )
        else:  # FAIL_OPEN
            # Allow traffic when components fail (but log)
            return BlockingDecision(
                action=BlockingAction.ALLOW,
                reasons=[f"Component failure (fail-open): {component_name}"],
                confidence=0.5,
                sources=['fail_safe_open'],
                metadata={
                    'component': component_name,
                    'error': str(error),
                    'fail_mode': 'fail_open',
                    'warning': 'Traffic allowed due to component failure'
                }
            )
    
    async def start_components(self):
        """Start async components like TTL manager"""
        await self.ttl_manager.start()
        self.logger.info("✅ Decision engine enhanced components started")
    
    async def stop_components(self):
        """Stop async components gracefully"""
        await self.ttl_manager.stop()
        self.logger.info("✅ Decision engine enhanced components stopped")
    
    def get_enhanced_statistics(self) -> dict:
        """
        Get enhanced statistics including new actions
        
        Returns:
            Dictionary with statistics
        """
        base_stats = {
            'total_decisions': self._total_decisions,
            'blocked_decisions': self._blocked_decisions,
            'allowed_decisions': self._allowed_decisions,
            'monitored_decisions': self._monitored_decisions,
            'rate_limited_decisions': self._rate_limited_decisions,
            'quarantined_decisions': self._quarantined_decisions,
            'block_reasons': dict(self._block_reasons)
        }
        
        # Add TTL manager statistics
        ttl_stats = self.ttl_manager.get_statistics()
        
        return {
            **base_stats,
            'ttl_manager': ttl_stats,
            'fail_mode': self.fail_mode.name
        }
