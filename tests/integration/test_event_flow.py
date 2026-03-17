#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Integration Tests

Tests for:
- XDP to Sink event flow
- Normal mode to Sink event flow
- End-to-end decision flow
"""

import pytest
import asyncio
from datetime import datetime
import tempfile
from pathlib import Path

from system.telemetry.events import UnifiedEventSink, SinkConfig
from system.telemetry.events.event_schema import EventSchema, EventDirection, EventVerdict, SourcePath
from acceleration.ebpf.xdp_engine import create_xdp_engine
from policy.smart_blocker.decision_engine import BlockingDecisionEngine, BlockingAction


@pytest.fixture
def temp_log_dir():
    """Temporary directory for logs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def integrated_event_sink(temp_log_dir):
    """Create event sink for integration testing"""
    config = SinkConfig(
        buffer_size=100,
        flush_interval=0.5,
        batch_size=10,
        backends=[
            {
                'type': 'file',
                'output_dir': str(temp_log_dir),
                'format': 'json'
            }
        ]
    )
    
    sink = UnifiedEventSink(config)
    await sink.start()
    yield sink
    await sink.stop()


class TestXDPToSinkFlow:
    """Test XDP to Sink event flow"""
    
    @pytest.mark.asyncio
    async def test_xdp_event_submission(self, integrated_event_sink):
        """Test XDP events flow to sink"""
        # Create XDP event
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="xdp-flow-123",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=45123,
            dst_port=80,
            protocol="tcp",
            iface_in="eth0",
            iface_out="eth0",
            bytes=1024,
            packets=5,
            direction=EventDirection.OUTBOUND,
            source_path=SourcePath.XDP,
            verdict=EventVerdict.ALLOW,
            reason="XDP fast path"
        )
        
        # Submit to sink
        await integrated_event_sink.submit_event(event)
        
        # Flush and verify
        await integrated_event_sink.flush()
        await asyncio.sleep(0.5)
        
        stats = integrated_event_sink.get_statistics()
        assert stats['total_events'] >= 1
        assert stats['events_flushed'] >= 1
    
    @pytest.mark.asyncio
    async def test_xdp_batch_submission(self, integrated_event_sink):
        """Test batch XDP events"""
        events = []
        for i in range(10):
            event = EventSchema(
                timestamp=datetime.utcnow(),
                flow_id=f"xdp-flow-{i}",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.100",
                src_port=10000 + i,
                dst_port=80,
                protocol="tcp",
                iface_in="eth0",
                iface_out="eth0",
                bytes=512,
                packets=3,
                direction=EventDirection.OUTBOUND,
                source_path=SourcePath.XDP,
                verdict=EventVerdict.DROP if i % 2 == 0 else EventVerdict.ALLOW,
                reason="Test batch"
            )
            events.append(event)
        
        # Batch submit
        await integrated_event_sink.batch_submit(events)
        await integrated_event_sink.flush()
        await asyncio.sleep(0.5)
        
        stats = integrated_event_sink.get_statistics()
        assert stats['total_events'] == 10


class TestNormalToSinkFlow:
    """Test Normal (Proxy) mode to Sink event flow"""
    
    @pytest.mark.asyncio
    async def test_proxy_event_submission(self, integrated_event_sink):
        """Test proxy events flow to sink"""
        # Create proxy event
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="proxy-flow-456",
            src_ip="172.16.0.50",
            dst_ip="example.com",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            iface_in="eth0",
            iface_out="eth0",
            bytes=2048,
            packets=10,
            direction=EventDirection.OUTBOUND,
            source_path=SourcePath.NORMAL,
            url="https://example.com/api",
            http_method="GET",
            verdict=EventVerdict.ALLOW,
            reason="Proxy inspection passed"
        )
        
        # Submit to sink
        await integrated_event_sink.submit_event(event)
        await integrated_event_sink.flush()
        await asyncio.sleep(0.5)
        
        stats = integrated_event_sink.get_statistics()
        assert stats['total_events'] >= 1


class TestDecisionToSinkFlow:
    """Test decision engine to sink integration"""
    
    @pytest.mark.asyncio
    async def test_decision_creates_event(self, integrated_event_sink):
        """Test that decisions create events in sink"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Make a decision
            decision = engine.evaluate_connection(
                src_ip="192.168.1.200",
                dst_ip="malicious.example.com"
            )
            
            # Create event from decision
            event = EventSchema(
                timestamp=datetime.utcnow(),
                flow_id="decision-flow-789",
                src_ip="192.168.1.200",
                dst_ip="malicious.example.com",
                src_port=0,
                dst_port=0,
                protocol="tcp",
                iface_in="eth0",
                iface_out="eth0",
                bytes=0,
                packets=0,
                direction=EventDirection.OUTBOUND,
                source_path=SourcePath.NORMAL,
                verdict=EventVerdict(decision.action.name.lower()),
                reason=", ".join(decision.reasons) if decision.reasons else "Policy decision"
            )
            
            # Submit event
            await integrated_event_sink.submit_event(event)
            await integrated_event_sink.flush()
            await asyncio.sleep(0.5)
            
            stats = integrated_event_sink.get_statistics()
            assert stats['total_events'] >= 1
            
        finally:
            await engine.ttl_manager.stop()
    
    @pytest.mark.asyncio
    async def test_rate_limit_decision_flow(self, integrated_event_sink):
        """Test rate limit decision flow"""
        engine = BlockingDecisionEngine()
        await engine.ttl_manager.start()
        
        try:
            # Apply rate limit
            decision = await engine.apply_rate_limit(
                ip="10.0.0.50",
                rate=10,
                ttl=60,
                reason="API rate limit exceeded"
            )
            
            assert decision.action == BlockingAction.RATE_LIMIT
            
            # Create event
            event = EventSchema(
                timestamp=datetime.utcnow(),
                flow_id="rate-limit-flow",
                src_ip="10.0.0.50",
                dst_ip="api.example.com",
                src_port=34567,
                dst_port=443,
                protocol="tcp",
                iface_in="eth0",
                iface_out="eth0",
                bytes=512,
                packets=1,
                direction=EventDirection.OUTBOUND,
                source_path=SourcePath.NORMAL,
                verdict=EventVerdict.RATE_LIMIT,
                reason="API rate limit exceeded",
                metadata={'rate': 10, 'ttl': 60}
            )
            
            await integrated_event_sink.submit_event(event)
            await integrated_event_sink.flush()
            
            stats = integrated_event_sink.get_statistics()
            assert stats['total_events'] >= 1
            
        finally:
            await engine.ttl_manager.stop()


class TestEndToEndFlow:
    """Test complete end-to-end scenarios"""
    
    @pytest.mark.asyncio
    async def test_mixed_source_paths(self, integrated_event_sink):
        """Test events from both XDP and Normal paths"""
        # XDP event
        xdp_event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="xdp-mixed-1",
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            protocol="udp",
            iface_in="eth0",
            iface_out="eth0",
            bytes=64,
            packets=1,
            direction=EventDirection.OUTBOUND,
            source_path=SourcePath.XDP,
            verdict=EventVerdict.ALLOW,
            reason="DNS query allowed"
        )
        
        # Normal/Proxy event
        proxy_event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="proxy-mixed-1",
            src_ip="192.168.1.1",
            dst_ip="example.com",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            iface_in="eth0",
            iface_out="eth0",
            bytes=4096,
            packets=20,
            direction=EventDirection.OUTBOUND,
            source_path=SourcePath.NORMAL,
            url="https://example.com",
            verdict=EventVerdict.ALLOW,
            reason="HTTPS inspection passed"
        )
        
        # Submit both
        await integrated_event_sink.submit_event(xdp_event)
        await integrated_event_sink.submit_event(proxy_event)
        await integrated_event_sink.flush()
        await asyncio.sleep(0.5)
        
        stats = integrated_event_sink.get_statistics()
        assert stats['total_events'] == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
