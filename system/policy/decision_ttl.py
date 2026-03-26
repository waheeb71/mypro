#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Decision TTL Manager
═══════════════════════════════════════════════════════════════════

Manages TTL (Time-To-Live) for temporary decisions like blocks,
rate limits, and quarantines.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
from typing import Dict, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict


logger = logging.getLogger(__name__)


@dataclass
class TTLEntry:
    """TTL entry for a temporary decision"""
    target: str  # IP address or identifier
    action: str  # BLOCK, RATE_LIMIT, QUARANTINE
    created_at: datetime
    expires_at: datetime
    reason: str
    metadata: Dict = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return datetime.utcnow() >= self.expires_at
    
    def time_remaining(self) -> float:
        """Get remaining time in seconds"""
        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.total_seconds())


class DecisionTTLManager:
    """
    Manages TTL for temporary decisions
    
    Features:
    - Automatic cleanup of expired entries
    - TTL extension
    - Statistics and monitoring
    - Async operations
    """
    
    def __init__(self, cleanup_interval: int = 60):
        """
        Initialize TTL manager
        
        Args:
            cleanup_interval: Seconds between cleanup runs
        """
        self.cleanup_interval = cleanup_interval
        
        # TTL entries by action type
        self._entries: Dict[str, Dict[str, TTLEntry]] = {
            'BLOCK': {},
            'RATE_LIMIT': {},
            'QUARANTINE': {}
        }
        
        # Statistics
        self._stats = {
            'total_added': 0,
            'total_expired': 0,
            'total_extended': 0,
            'active_entries': 0
        }
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        self.logger = logger
    
    async def start(self):
        """Start TTL manager and cleanup task"""
        self.logger.info("Starting Decision TTL Manager...")
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.logger.info("✅ Decision TTL Manager started")
    
    async def stop(self):
        """Stop TTL manager"""
        if not self._running:
            return
        
        self.logger.info("Stopping Decision TTL Manager...")
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("✅ Decision TTL Manager stopped")
    
    async def add_temporary_block(self, ip: str, ttl: int, reason: str = "Temporary block"):
        """
        Add temporary block with TTL
        
        Args:
            ip: IP address to block
            ttl: Time to live in seconds
            reason: Reason for block
        """
        await self._add_entry('BLOCK', ip, ttl, reason)
        self.logger.debug(f"Added temporary block for {ip} (TTL: {ttl}s)")
    
    async def add_rate_limit(self, ip: str, ttl: int, rate: int, reason: str = "Rate limit"):
        """
        Add rate limit with TTL
        
        Args:
            ip: IP address
            ttl: Time to live in seconds
            rate: Rate limit (requests/sec)
            reason: Reason for rate limit
        """
        await self._add_entry('RATE_LIMIT', ip, ttl, reason, {'rate': rate})
        self.logger.debug(f"Added rate limit for {ip}: {rate} req/s (TTL: {ttl}s)")
    
    async def add_quarantine(self, ip: str, ttl: int, reason: str = "Quarantine"):
        """
        Add quarantine with TTL
        
        Args:
            ip: IP address
            ttl: Time to live in seconds
            reason: Reason for quarantine
        """
        await self._add_entry('QUARANTINE', ip, ttl, reason)
        self.logger.debug(f"Added quarantine for {ip} (TTL: {ttl}s)")
    
    async def _add_entry(self, action: str, target: str, ttl: int, reason: str, metadata: Dict = None):
        """
        Internal method to add TTL entry
        
        Args:
            action: Action type (BLOCK, RATE_LIMIT, QUARANTINE)
            target: Target identifier (usually IP)
            ttl: Time to live in seconds
            reason: Reason for action
            metadata: Optional metadata
        """
        if action not in self._entries:
            raise ValueError(f"Invalid action: {action}")
        
        entry = TTLEntry(
            target=target,
            action=action,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=ttl),
            reason=reason,
            metadata=metadata or {}
        )
        
        self._entries[action][target] = entry
        self._stats['total_added'] += 1
        self._stats['active_entries'] += 1
    
    async def extend_ttl(self, action: str, target: str, additional_time: int) -> bool:
        """
        Extend TTL for an existing entry
        
        Args:
            action: Action type
            target: Target identifier
            additional_time: Additional seconds to add
            
        Returns:
            True if extended, False if entry not found
        """
        if action not in self._entries:
            return False
        
        entry = self._entries[action].get(target)
        if not entry:
            return False
        
        entry.expires_at += timedelta(seconds=additional_time)
        self._stats['total_extended'] += 1
        
        self.logger.debug(f"Extended TTL for {target} ({action}) by {additional_time}s")
        return True
    
    async def remove_entry(self, action: str, target: str) -> bool:
        """
        Manually remove an entry
        
        Args:
            action: Action type
            target: Target identifier
            
        Returns:
            True if removed, False if not found
        """
        if action not in self._entries:
            return False
        
        if target in self._entries[action]:
            del self._entries[action][target]
            self._stats['active_entries'] -= 1
            self.logger.debug(f"Manually removed entry for {target} ({action})")
            return True
        
        return False
    
    def is_active(self, action: str, target: str) -> bool:
        """
        Check if entry is active (exists and not expired)
        
        Args:
            action: Action type
            target: Target identifier
            
        Returns:
            True if active, False otherwise
        """
        if action not in self._entries:
            return False
        
        entry = self._entries[action].get(target)
        if not entry:
            return False
        
        return not entry.is_expired()
    
    def get_entry(self, action: str, target: str) -> Optional[TTLEntry]:
        """
        Get TTL entry
        
        Args:
            action: Action type
            target: Target identifier
            
        Returns:
            TTLEntry if found, None otherwise
        """
        if action not in self._entries:
            return None
        
        entry = self._entries[action].get(target)
        
        # Auto-cleanup if expired
        if entry and entry.is_expired():
            return None
        
        return entry
    
    def get_all_active(self, action: Optional[str] = None) -> Dict[str, TTLEntry]:
        """
        Get all active entries
        
        Args:
            action: Optional action filter
            
        Returns:
            Dictionary of active entries
        """
        result = {}
        
        actions_to_check = [action] if action else self._entries.keys()
        
        for act in actions_to_check:
            if act in self._entries:
                for target, entry in self._entries[act].items():
                    if not entry.is_expired():
                        result[f"{act}:{target}"] = entry
        
        return result
    
    async def cleanup_expired(self) -> int:
        """
        Cleanup expired entries
        
        Returns:
            Number of expired entries removed
        """
        expired_count = 0
        
        for action in self._entries:
            to_remove = []
            
            for target, entry in self._entries[action].items():
                if entry.is_expired():
                    to_remove.append(target)
            
            for target in to_remove:
                del self._entries[action][target]
                expired_count += 1
        
        if expired_count > 0:
            self._stats['total_expired'] += expired_count
            self._stats['active_entries'] -= expired_count
            self.logger.debug(f"Cleaned up {expired_count} expired entries")
        
        return expired_count
    
    async def _cleanup_loop(self):
        """Background cleanup task"""
        self.logger.info(f"Cleanup loop started (interval={self.cleanup_interval}s)")
        
        try:
            while self._running:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired()
                
        except asyncio.CancelledError:
            self.logger.info("Cleanup loop cancelled")
        except Exception as e:
            self.logger.error(f"Error in cleanup loop: {e}", exc_info=True)
    
    def get_statistics(self) -> Dict:
        """
        Get TTL manager statistics
        
        Returns:
            Statistics dictionary
        """
        # Count active entries by type
        active_by_type = {}
        for action in self._entries:
            count = sum(1 for e in self._entries[action].values() if not e.is_expired())
            active_by_type[action.lower()] = count
        
        return {
            **self._stats,
            'active_by_type': active_by_type
        }
