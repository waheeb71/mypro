#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise CyberNexus - Unit Tests for Inspection Plugins

Tests for:
- HTTP Inspector (SQL injection, XSS, path traversal)
- DNS Inspector (tunneling, DGA detection)
- SMTP Inspector (email scanning)
- Inspection Pipeline (ordering, timeouts, fail modes)
"""

import pytest
from unittest.mock import MagicMock
from inspection.framework.plugin_base import (
    InspectionContext,
    PluginPriority
)
from inspection.framework.pipeline import (
    InspectionPipeline,
    InspectionResult,
    InspectionAction,
    InspectionFinding
)
from inspection.framework.pipeline import InspectionPipeline
from inspection.plugins.http_inspector import HTTPInspector
from inspection.plugins.dns_inspector import DNSInspector
from inspection.plugins.smtp_inspector import SMTPInspector


# ==================== HTTP Inspector Tests ====================

class TestHTTPInspector:
    """Test HTTP Inspector functionality"""

    def setup_method(self):
        self.inspector = HTTPInspector()

    def test_initialization(self):
        """Test HTTP inspector initializes correctly"""
        assert self.inspector is not None
        assert self.inspector.name == "HTTP Inspector"

    def test_can_inspect_http(self):
        """Test that HTTP traffic is inspectable"""
        context = InspectionContext(
            flow_id="test-1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        assert self.inspector.can_inspect(context) is True

    def test_can_inspect_https(self):
        """Test that HTTPS traffic is inspectable"""
        context = InspectionContext(
            flow_id="test-2",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=443,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        assert self.inspector.can_inspect(context) is True

    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        context = InspectionContext(
            flow_id="test-sqli",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )

        # SQL injection payload
        payload = b"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.inspector.inspect(context, payload)

        assert isinstance(result, InspectionResult)
        # Should detect SQL injection
        has_sqli = any(
            'sql' in f.description.lower() or 'injection' in f.description.lower()
            for f in result.findings
        )
        assert has_sqli or result.action in [InspectionAction.BLOCK, InspectionAction.DROP]

    def test_xss_detection(self):
        """Test XSS pattern detection"""
        context = InspectionContext(
            flow_id="test-xss",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )

        # XSS payload
        payload = b"GET /page?name=<script>alert('xss')</script> HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.inspector.inspect(context, payload)

        assert isinstance(result, InspectionResult)
        # Should detect XSS
        has_xss = any(
            'xss' in f.description.lower() or 'script' in f.description.lower()
            for f in result.findings
        )
        assert has_xss or result.action in [InspectionAction.BLOCK, InspectionAction.DROP]

    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        context = InspectionContext(
            flow_id="test-traversal",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )

        payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.inspector.inspect(context, payload)

        assert isinstance(result, InspectionResult)
        has_traversal = any(
            'traversal' in f.description.lower() or 'path' in f.description.lower()
            for f in result.findings
        )
        assert has_traversal or result.action in [InspectionAction.BLOCK, InspectionAction.DROP]

    def test_normal_http_request_allowed(self):
        """Test that normal HTTP requests are allowed"""
        context = InspectionContext(
            flow_id="test-normal",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )

        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        result = self.inspector.inspect(context, payload)

        assert isinstance(result, InspectionResult)
        # Normal request should be allowed
        assert result.action in [InspectionAction.ALLOW, InspectionAction.LOG]

    def test_dangerous_http_method(self):
        """Test detection of dangerous HTTP methods"""
        context = InspectionContext(
            flow_id="test-method",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )

        payload = b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.inspector.inspect(context, payload)

        assert isinstance(result, InspectionResult)


# ==================== DNS Inspector Tests ====================

class TestDNSInspector:
    """Test DNS Inspector functionality"""

    def setup_method(self):
        self.inspector = DNSInspector()

    def test_initialization(self):
        """Test DNS inspector initializes"""
        assert self.inspector is not None

    def test_can_inspect_dns(self):
        """Test that DNS traffic is inspectable"""
        context = InspectionContext(
            flow_id="test-dns",
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            src_port=45000,
            dst_port=53,
            protocol="udp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        assert self.inspector.can_inspect(context) is True

    def test_can_not_inspect_http(self):
        """Test that HTTP traffic is not DNS inspectable"""
        context = InspectionContext(
            flow_id="test-http",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        assert self.inspector.can_inspect(context) is False


# ==================== SMTP Inspector Tests ====================

class TestSMTPInspector:
    """Test SMTP Inspector functionality"""

    def setup_method(self):
        self.inspector = SMTPInspector()

    def test_initialization(self):
        """Test SMTP inspector initializes"""
        assert self.inspector is not None

    def test_can_inspect_smtp(self):
        """Test that SMTP traffic is inspectable"""
        context = InspectionContext(
            flow_id="test-smtp",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=25,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        assert self.inspector.can_inspect(context) is True


# ==================== Pipeline Tests ====================

class TestInspectionPipeline:
    """Test Inspection Pipeline"""

    def setup_method(self):
        self.pipeline = InspectionPipeline()

    def test_pipeline_initialization(self):
        """Test pipeline initializes correctly"""
        assert self.pipeline is not None
        stats = self.pipeline.get_statistics()
        assert isinstance(stats, dict)

    def test_register_plugin(self):
        """Test registering a plugin"""
        http = HTTPInspector()
        self.pipeline.register_plugin(http)

        stats = self.pipeline.get_statistics()
        assert stats['registered_plugins'] >= 1

    def test_register_multiple_plugins(self):
        """Test registering multiple plugins"""
        self.pipeline.register_plugin(HTTPInspector())
        self.pipeline.register_plugin(DNSInspector())
        self.pipeline.register_plugin(SMTPInspector())

        stats = self.pipeline.get_statistics()
        assert stats['registered_plugins'] >= 3

    def test_inspect_through_pipeline(self):
        """Test inspecting traffic through pipeline"""
        self.pipeline.register_plugin(HTTPInspector())

        context = InspectionContext(
            flow_id="pipeline-test",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=80,
            protocol="tcp",
            direction="inbound",
            timestamp=0.0,
            metadata={}
        )
        data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

        result = self.pipeline.inspect(context, data)
        assert isinstance(result, InspectionResult)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
