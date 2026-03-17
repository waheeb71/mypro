#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Unit Tests for Unified Event Sink

Tests for:
- Event submission
- Buffering and batching
- Backend integration
- Statistics and health checks
"""

import pytest
import asyncio
from datetime import datetime
from pathlib import Path
import tempfile
import json

from system.telemetry.events import UnifiedEventSink, SinkConfig
from system.telemetry.events.event_schema import EventSchema, EventDirection, EventVerdict, SourcePath


@pytest.fixture
def temp_log_dir():
    """Temporary directory for test logs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def basic_sink_config(temp_log_dir):
    """Basic sink configuration for testing"""
    return SinkConfig(
        buffer_size=10,
        flush_interval=1.0,
        batch_size=5,
        backends=[
            {
                'type': 'file',
                'output_dir': str(temp_log_dir),
                'format': 'json',
                'rotation': 'none'
            }
        ]
    )


@pytest.fixture
async def event_sink(basic_sink_config):
    """Create and start event sink for testing"""
    sink = UnifiedEventSink(basic_sink_config)
    await sink.start()
    yield sink
    await sink.stop()


@pytest.fixture
def sample_event():
    """Create a sample event for testing"""
    return EventSchema(
        timestamp=datetime.utcnow(),
        flow_id="test-flow-123",
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
        reason="Test event"
    )


class TestEventSubmission:
    """Test event submission to sink"""
    
    @pytest.mark.asyncio
    async def test_submit_single_event(self, event_sink, sample_event):
        """Test submitting a single event"""
        await event_sink.submit_event(sample_event)
        
        stats = event_sink.get_statistics()
        assert stats['total_events'] == 1
        assert stats['events_buffered'] <= 1
    
    @pytest.mark.asyncio
    async def test_submit_multiple_events(self, event_sink, sample_event):
        """Test submitting multiple events"""
        for i in range(5):
            event = EventSchema(
                **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
            )
            await event_sink.submit_event(event)
        
        stats = event_sink.get_statistics()
        assert stats['total_events'] == 5
    
    @pytest.mark.asyncio
    async def test_batch_submit(self, event_sink, sample_event):
        """Test batch event submission"""
        events = [
            EventSchema(**{**sample_event.__dict__, 'flow_id': f'flow-{i}'})
            for i in range(10)
        ]
        
        await event_sink.batch_submit(events)
        
        stats = event_sink.get_statistics()
        assert stats['total_events'] == 10


class TestBufferingAndBatching:
    """Test buffering and batching logic"""
    
    @pytest.mark.asyncio
    async def test_buffer_size_limit(self, basic_sink_config, sample_event):
        """Test that buffer respects size limit"""
        # Set small buffer size
        basic_sink_config.buffer_size = 3
        
        sink = UnifiedEventSink(basic_sink_config)
        await sink.start()
        
        try:
            # Submit more events than buffer size
            for i in range(5):
                event = EventSchema(
                    **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
                )
                await sink.submit_event(event)
            
            # Give time for flush
            await asyncio.sleep(0.5)
            
            stats = sink.get_statistics()
            # Should have flushed at least once
            assert stats['flush_count'] >= 1
            
        finally:
            await sink.stop()
    
    @pytest.mark.asyncio
    async def test_auto_flush_on_interval(self, event_sink, sample_event):
        """Test automatic flush based on interval"""
        # Submit events
        for i in range(3):
            event = EventSchema(
                **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
            )
            await event_sink.submit_event(event)
        
        initial_flush_count = event_sink.get_statistics()['flush_count']
        
        # Wait for flush interval
        await asyncio.sleep(1.5)
        
        final_flush_count = event_sink.get_statistics()['flush_count']
        assert final_flush_count > initial_flush_count
    
    @pytest.mark.asyncio
    async def test_flush_on_stop(self, basic_sink_config, sample_event):
        """Test that remaining events are flushed on stop"""
        sink = UnifiedEventSink(basic_sink_config)
        await sink.start()
        
        # Submit events
        for i in range(3):
            event = EventSchema(
                **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
            )
            await sink.submit_event(event)
        
        # Stop should flush remaining
        await sink.stop()
        
        stats = sink.get_statistics()
        assert stats['events_flushed'] == 3


class TestBackendIntegration:
    """Test backend integration"""
    
    @pytest.mark.asyncio
    async def test_file_backend_writes(self, event_sink, sample_event, temp_log_dir):
        """Test that events are written to file backend"""
        # Submit events
        for i in range(3):
            event = EventSchema(
                **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
            )
            await event_sink.submit_event(event)
        
        # Force flush
        await event_sink.flush()
        await asyncio.sleep(0.5)
        
        # Check that file was created
        log_files = list(temp_log_dir.glob('*.json'))
        assert len(log_files) > 0
        
        # Check file contents
        with open(log_files[0], 'r') as f:
            lines = f.readlines()
            assert len(lines) == 3
            
            # Validate JSON
            for line in lines:
                event_data = json.loads(line)
                assert 'flow_id' in event_data
                assert 'timestamp' in event_data
    
    @pytest.mark.asyncio
    async def test_multiple_backends(self, temp_log_dir, sample_event):
        """Test configuration with multiple backends"""
        config = SinkConfig(
            buffer_size=10,
            flush_interval=1.0,
            batch_size=5,
            backends=[
                {
                    'type': 'file',
                    'output_dir': str(temp_log_dir / 'json'),
                    'format': 'json'
                },
                {
                    'type': 'file',
                    'output_dir': str(temp_log_dir / 'csv'),
                    'format': 'csv'
                }
            ]
        )
        
        sink = UnifiedEventSink(config)
        await sink.start()
        
        try:
            await sink.submit_event(sample_event)
            await sink.flush()
            await asyncio.sleep(0.5)
            
            # Check both backends wrote files
            json_files = list((temp_log_dir / 'json').glob('*.json'))
            csv_files = list((temp_log_dir / 'csv').glob('*.csv'))
            
            assert len(json_files) > 0
            assert len(csv_files) > 0
            
        finally:
            await sink.stop()


class TestStatisticsAndHealth:
    """Test statistics and health check functionality"""
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, event_sink, sample_event):
        """Test that statistics are correctly tracked"""
        # Initial stats
        stats = event_sink.get_statistics()
        assert stats['total_events'] == 0
        assert stats['events_flushed'] == 0
        
        # Submit events
        for i in range(5):
            event = EventSchema(
                **{**sample_event.__dict__, 'flow_id': f'flow-{i}'}
            )
            await event_sink.submit_event(event)
        
        # Check updated stats
        stats = event_sink.get_statistics()
        assert stats['total_events'] == 5
    
    @pytest.mark.asyncio
    async def test_health_check(self, event_sink):
        """Test health check functionality"""
        health = await event_sink.health_check()
        
        assert health['sink_running'] is True
        assert 'buffer_usage' in health
        assert 'backends' in health
        assert len(health['backends']) > 0
        
        # Check backend health
        for backend in health['backends']:
            assert 'type' in backend
            assert 'healthy' in backend
    
    @pytest.mark.asyncio
    async def test_health_after_stop(self, event_sink):
        """Test health check after stopping sink"""
        await event_sink.stop()
        
        health = await event_sink.health_check()
        assert health['sink_running'] is False


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    @pytest.mark.asyncio
    async def test_invalid_backend_config(self):
        """Test handling of invalid backend configuration"""
        config = SinkConfig(
            buffer_size=10,
            flush_interval=1.0,
            batch_size=5,
            backends=[
                {
                    'type': 'invalid_backend_type',
                    'output_dir': '/tmp'
                }
            ]
        )
        
        sink = UnifiedEventSink(config)
        # Should handle gracefully
        await sink.start()
        await sink.stop()
    
    @pytest.mark.asyncio
    async def test_submit_after_stop(self, basic_sink_config, sample_event):
        """Test submitting events after sink is stopped"""
        sink = UnifiedEventSink(basic_sink_config)
        await sink.start()
        await sink.stop()
        
        # Should handle gracefully
        try:
            await sink.submit_event(sample_event)
        except Exception:
            # Expected to fail or be ignored
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
