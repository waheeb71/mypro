#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Unit Tests for Decision Engine

Tests for:
- Decision logic
- Rate limiting
- Quarantine
- TTL management
- Fail-safe modes
"""

import pytest
import asyncio
from policy.smart_blocker.decision_engine import (
    BlockingDecisionEngine,
    BlockingAction,
    BlockingDecision,
    PolicyMode,
    FailMode
)
from policy.decision_ttl import DecisionTTLManager


class TestDecisionLogic:
    """Test basic decision-making logic"""
    
    def setup_method(self):
        """Setup decision engine for each test"""
        self.engine = BlockingDecisionEngine(
            policy_mode=PolicyMode.BALANCED,
            fail_mode=FailMode.FAIL_OPEN
        )
    
    def test_engine_initialization(self):
        """Test decision engine initialization"""
        assert self.engine.policy_mode == PolicyMode.BALANCED
        assert self.engine.fail_mode == FailMode.FAIL_OPEN
        assert self.engine.ttl_manager is not None
    
    def test_evaluate_connection_allow(self):
        """Test evaluating connection that should be allowed"""
        decision = self.engine.evaluate_connection(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            domain="google.com"
        )
        
        assert isinstance(decision, BlockingDecision)
        # Should allow by default for unknown IPs
        assert decision.action in [BlockingAction.ALLOW, BlockingAction.MONITOR]
    
    def test_policy_mode_changes(self):
        """Test changing policy modes"""
        self.engine.set_policy_mode(PolicyMode.STRICT)
        assert self.engine.policy_mode == PolicyMode.STRICT
        
        self.engine.set_policy_mode(PolicyMode.PERMISSIVE)
        assert self.engine.policy_mode == PolicyMode.PERMISSIVE


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    @pytest.mark.asyncio
    async def test_apply_rate_limit(self):
        """Test applying rate limit to an IP"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Apply rate limit
            decision = await engine.apply_rate_limit(
                ip="192.168.1.200",
                rate=10,
                ttl=60,
                reason="Too many requests"
            )
            
            assert decision.action == BlockingAction.RATE_LIMIT
            assert decision.metadata['rate'] == 10
            assert decision.metadata['ttl'] == 60
            assert "Too many requests" in decision.reasons
            
        finally:
            await engine.ttl_manager.stop()
    
    @pytest.mark.asyncio
    async def test_rate_limit_ttl_expiry(self):
        """Test rate limit TTL expiry"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Apply short TTL
            await engine.apply_rate_limit(
                ip="10.0.0.50",
                rate=5,
                ttl=1,  # 1 second
                reason="Test"
            )
            
            # Check it's active
            assert engine.ttl_manager.is_active('RATE_LIMIT', "10.0.0.50")
            
            # Wait for expiry
            await asyncio.sleep(1.5)
            
            # Should be expired
            assert not engine.ttl_manager.is_active('RATE_LIMIT', "10.0.0.50")
            
        finally:
            await engine.ttl_manager.stop()


class TestQuarantine:
    """Test quarantine functionality"""
    
    @pytest.mark.asyncio
    async def test_quarantine_ip(self):
        """Test quarantining an IP address"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Quarantine IP
            decision = await engine.quarantine_ip(
                ip="172.16.0.100",
                ttl=120,
                reason="Suspicious activity"
            )
            
            assert decision.action == BlockingAction.QUARANTINE
            assert decision.metadata['ip'] == "172.16.0.100"
            assert decision.metadata['ttl'] == 120
            assert "Suspicious activity" in decision.reasons
            
        finally:
            await engine.ttl_manager.stop()
    
    @pytest.mark.asyncio
    async def test_check_quarantine_restriction(self):
        """Test checking for quarantine restrictions"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Quarantine IP
            await engine.quarantine_ip(
                ip="192.168.99.99",
                ttl=60,
                reason="Test quarantine"
            )
            
            # Check for restriction
            decision = await engine.check_ttl_restrictions("192.168.99.99")
            
            assert decision is not None
            assert decision.action == BlockingAction.QUARANTINE
            
        finally:
            await engine.ttl_manager.stop()


class TestTTLManagement:
    """Test TTL management"""
    
    @pytest.mark.asyncio
    async def test_ttl_manager_initialization(self):
        """Test TTL manager initialization"""
        ttl_mgr = DecisionTTLManager(cleanup_interval=30)
        await ttl_mgr.start()
        
        try:
            assert ttl_mgr._running is True
            stats = ttl_mgr.get_statistics()
            assert stats['total_added'] == 0
            
        finally:
            await ttl_mgr.stop()
    
    @pytest.mark.asyncio
    async def test_ttl_add_and_remove(self):
        """Test adding and removing TTL entries"""
        ttl_mgr = DecisionTTLManager()
        await ttl_mgr.start()
        
        try:
            # Add block
            await ttl_mgr.add_temporary_block(
                ip="10.0.0.1",
                ttl=60,
                reason="Test block"
            )
            
            assert ttl_mgr.is_active('BLOCK', "10.0.0.1")
            
            # Remove
            removed = await ttl_mgr.remove_entry('BLOCK', "10.0.0.1")
            assert removed is True
            assert not ttl_mgr.is_active('BLOCK', "10.0.0.1")
            
        finally:
            await ttl_mgr.stop()
    
    @pytest.mark.asyncio
    async def test_ttl_cleanup(self):
        """Test automatic TTL cleanup"""
        ttl_mgr = DecisionTTLManager(cleanup_interval=1)
        await ttl_mgr.start()
        
        try:
            # Add short-lived entries
            await ttl_mgr.add_temporary_block("10.0.0.1", 1, "Test 1")
            await ttl_mgr.add_temporary_block("10.0.0.2", 1, "Test 2")
            
            # Wait for expiry + cleanup
            await asyncio.sleep(2)
            
            stats = ttl_mgr.get_statistics()
            assert stats['total_expired'] >= 2
            
        finally:
            await ttl_mgr.stop()
    
    @pytest.mark.asyncio
    async def test_ttl_extension(self):
        """Test extending TTL for an entry"""
        ttl_mgr = DecisionTTLManager()
        await ttl_mgr.start()
        
        try:
            # Add entry
            await ttl_mgr.add_temporary_block("10.0.0.1", 60, "Test")
            
            entry = ttl_mgr.get_entry('BLOCK', "10.0.0.1")
            initial_expiry = entry.expires_at
            
            # Extend TTL
            await ttl_mgr.extend_ttl('BLOCK', "10.0.0.1", 30)
            
            entry = ttl_mgr.get_entry('BLOCK', "10.0.0.1")
            assert entry.expires_at > initial_expiry
            
        finally:
            await ttl_mgr.stop()


class TestFailSafeModes:
    """Test fail-safe modes"""
    
    def test_fail_open_mode(self):
        """Test fail-open mode"""
        engine = BlockingDecisionEngine(fail_mode=FailMode.FAIL_OPEN)
        
        decision = engine.apply_fail_safe_mode(
            component_name="threat_intel",
            error=Exception("Connection timeout")
        )
        
        # Should allow traffic
        assert decision.action == BlockingAction.ALLOW
        assert 'fail_open' in decision.metadata['fail_mode']
    
    def test_fail_closed_mode(self):
        """Test fail-closed mode"""
        engine = BlockingDecisionEngine(fail_mode=FailMode.FAIL_CLOSED)
        
        decision = engine.apply_fail_safe_mode(
            component_name="reputation_engine",
            error=Exception("Service unavailable")
        )
        
        # Should block traffic
        assert decision.action == BlockingAction.BLOCK
        assert 'fail_closed' in decision.metadata['fail_mode']


class TestStatistics:
    """Test statistics tracking"""
    
    @pytest.mark.asyncio
    async def test_decision_statistics(self):
        """Test decision engine statistics"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Make some decisions
            await engine.apply_rate_limit("10.0.0.1", 10, 60, "Test")
            await engine.quarantine_ip("10.0.0.2", 120, "Test")
            
            stats = engine.get_enhanced_statistics()
            
            assert stats['rate_limited_decisions'] == 1
            assert stats['quarantined_decisions'] == 1
            assert 'ttl_manager' in stats
            assert 'fail_mode' in stats
            
        finally:
            await engine.ttl_manager.stop()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
