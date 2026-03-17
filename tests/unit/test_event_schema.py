#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Unit Tests for Event Schema

Tests for:
- Schema validation
- Field constraints
- Helper functions
- Enum validations
"""

import pytest
from datetime import datetime
from system.telemetry.events.event_schema import (
    EventSchema,
    EventDirection,
    EventVerdict,
    SourcePath,
    create_event_from_xdp,
    create_event_from_proxy
)


class TestEventSchemaValidation:
    """Test event schema validation"""
    
    def test_create_valid_event(self):
        """Test creating a valid event"""
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="flow-123",
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
            reason="Test"
        )
        
        assert event.flow_id == "flow-123"
        assert event.src_ip == "192.168.1.100"
        assert event.verdict == EventVerdict.ALLOW
    
    def test_event_to_dict(self):
        """Test converting event to dictionary"""
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="flow-123",
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
            reason="Test"
        )
        
        event_dict = event.to_dict()
        
        assert isinstance(event_dict, dict)
        assert event_dict['flow_id'] == "flow-123"
        assert event_dict['src_ip'] == "192.168.1.100"
        assert event_dict['verdict'] == "allow"
        assert 'timestamp' in event_dict
    
    def test_event_from_dict(self):
        """Test creating event from dictionary"""
        event_dict = {
            'timestamp': datetime.utcnow().isoformat(),
            'flow_id': 'flow-456',
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'src_port': 12345,
            'dst_port': 443,
            'protocol': 'tcp',
            'iface_in': 'eth0',
            'iface_out': 'eth0',
            'bytes': 2048,
            'packets': 10,
            'direction': 'inbound',
            'source_path': 'normal',
            'verdict': 'drop',
            'reason': 'Blocked by policy'
        }
        
        event = EventSchema.from_dict(event_dict)
        
        assert event.flow_id == "flow-456"
        assert event.src_ip == "10.0.0.1"
        assert event.verdict == EventVerdict.DROP


class TestEnumValidations:
    """Test enum field validations"""
    
    def test_event_direction_enum(self):
        """Test EventDirection enum values"""
        assert EventDirection.INBOUND.value == "inbound"
        assert EventDirection.OUTBOUND.value == "outbound"
        assert EventDirection.INTERNAL.value == "internal"
        assert EventDirection.EXTERNAL.value == "external"
    
    def test_event_verdict_enum(self):
        """Test EventVerdict enum values"""
        assert EventVerdict.ALLOW.value == "allow"
        assert EventVerdict.DROP.value == "drop"
        assert EventVerdict.RATE_LIMIT.value == "rate_limit"
        assert EventVerdict.QUARANTINE.value == "quarantine"
        assert EventVerdict.LOG_ONLY.value == "log_only"
    
    def test_source_path_enum(self):
        """Test SourcePath enum values"""
        assert SourcePath.XDP.value == "xdp"
        assert SourcePath.NORMAL.value == "normal"
        assert SourcePath.HYBRID.value == "hybrid"


class TestHelperFunctions:
    """Test helper functions for creating events"""
    
    def test_create_event_from_xdp(self):
        """Test creating event from XDP path"""
        event = create_event_from_xdp(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=45123,
            dst_port=80,
            protocol="tcp",
            bytes=1024,
            packets=5,
            verdict=EventVerdict.ALLOW,
            reason="Allowed by XDP"
        )
        
        assert event.source_path == SourcePath.XDP
        assert event.src_ip == "192.168.1.100"
        assert event.verdict == EventVerdict.ALLOW
        assert event.iface_in == "eth0"  # Default value
    
    def test_create_event_from_proxy(self):
        """Test creating event from proxy path"""
        event = create_event_from_proxy(
            src_ip="10.0.0.1",
            dst_ip="example.com",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            bytes=2048,
            packets=10,
            url="https://example.com/api",
            method="GET",
            verdict=EventVerdict.DROP,
            reason="Blocked by WAF"
        )
        
        assert event.source_path == SourcePath.NORMAL
        assert event.src_ip == "10.0.0.1"
        assert event.verdict == EventVerdict.DROP
        assert event.url == "https://example.com/api"
        assert event.http_method == "GET"
    
    def test_xdp_event_with_rate_limit(self):
        """Test XDP event with rate limit verdict"""
        event = create_event_from_xdp(
            src_ip="192.168.1.200",
            dst_ip="10.0.0.254",
            src_port=34567,
            dst_port=22,
            protocol="tcp",
            bytes=512,
            packets=3,
            verdict=EventVerdict.RATE_LIMIT,
            reason="Rate limit exceeded"
        )
        
        assert event.verdict == EventVerdict.RATE_LIMIT
        assert event.reason == "Rate limit exceeded"
    
    def test_proxy_event_with_quarantine(self):
        """Test proxy event with quarantine verdict"""
        event = create_event_from_proxy(
            src_ip="172.16.0.50",
            dst_ip="malicious.example.com",
            src_port=49876,
            dst_port=80,
            protocol="tcp",
            bytes=1500,
            packets=8,
            url="http://malicious.example.com/exploit",
            method="POST",
            verdict=EventVerdict.QUARANTINE,
            reason="Suspicious activity detected"
        )
        
        assert event.verdict == EventVerdict.QUARANTINE
        assert event.reason == "Suspicious activity detected"


class TestMLFields:
    """Test ML-related fields"""
    
    def test_event_with_ml_score(self):
        """Test event with ML score"""
        event = create_event_from_proxy(
            src_ip="10.0.0.100",
            dst_ip="example.com",
            src_port=12345,
            dst_port=443,
            protocol="tcp",
            bytes=1024,
            packets=5,
            url="https://example.com",
            method="GET",
            verdict=EventVerdict.ALLOW,
            reason="Normal traffic",
            ml_score=0.95,
            ml_label="benign",
            confidence=0.98
        )
        
        assert event.ml_score == 0.95
        assert event.ml_label == "benign"
        assert event.confidence == 0.98
    
    def test_event_with_feature_vector_ref(self):
        """Test event with feature vector reference"""
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="flow-ml-123",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            protocol="tcp",
            iface_in="eth0",
            iface_out="eth0",
            bytes=2048,
            packets=10,
            direction=EventDirection.OUTBOUND,
            source_path=SourcePath.NORMAL,
            verdict=EventVerdict.ALLOW,
            reason="ML prediction",
            feature_vector_ref="fv-abc123",
            ml_score=0.87,
            ml_label="suspicious",
            confidence=0.75
        )
        
        assert event.feature_vector_ref == "fv-abc123"
        assert event.ml_label == "suspicious"


class TestMetadataField:
    """Test metadata field functionality"""
    
    def test_event_with_metadata(self):
        """Test event with custom metadata"""
        event = EventSchema(
            timestamp=datetime.utcnow(),
            flow_id="flow-meta-123",
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
            reason="Test",
            metadata={
                'geo_country': 'US',
                'asn': 15169,
                'threat_level': 'low'
            }
        )
        
        assert event.metadata['geo_country'] == 'US'
        assert event.metadata['asn'] == 15169
        assert event.metadata['threat_level'] == 'low'
    
    def test_metadata_in_dict_conversion(self):
        """Test metadata is preserved in dict conversion"""
        event = create_event_from_xdp(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            protocol="tcp",
            bytes=1024,
            packets=5,
            verdict=EventVerdict.ALLOW,
            reason="Test",
            metadata={'custom_field': 'custom_value'}
        )
        
        event_dict = event.to_dict()
        assert 'metadata' in event_dict
        assert event_dict['metadata']['custom_field'] == 'custom_value'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
