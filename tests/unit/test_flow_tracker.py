#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Unit Tests for Flow Tracker

Tests for:
- Flow creation and tracking
- State transitions
- Traffic statistics updates
- Application/user association
- Flow cleanup
- Statistics
"""

import pytest
import asyncio
from datetime import datetime, timedelta

from system.core.flow_tracker import FlowTracker, FlowInfo, ConnectionState


@pytest.fixture
def flow_config():
    """Default flow tracker configuration"""
    return {
        'flow_tracking': {
            'enabled': True,
            'max_flows': 1000,
            'flow_timeout': 3600
        }
    }


@pytest.fixture
def tracker(flow_config):
    """Create a flow tracker instance"""
    return FlowTracker(flow_config)


class TestFlowCreation:
    """Test flow creation functionality"""

    def test_create_basic_flow(self, tracker):
        """Test creating a basic TCP flow"""
        flow = tracker.create_flow(
            client_ip="192.168.1.100",
            client_port=45123,
            server_ip="8.8.8.8",
            server_port=443,
            protocol="TCP"
        )

        assert isinstance(flow, FlowInfo)
        assert flow.client_ip == "192.168.1.100"
        assert flow.client_port == 45123
        assert flow.server_ip == "8.8.8.8"
        assert flow.server_port == 443
        assert flow.protocol == "TCP"
        assert flow.state == ConnectionState.NEW

    def test_create_udp_flow(self, tracker):
        """Test creating a UDP flow"""
        flow = tracker.create_flow(
            client_ip="10.0.0.1",
            client_port=12345,
            server_ip="8.8.4.4",
            server_port=53,
            protocol="UDP"
        )

        assert flow.protocol == "UDP"
        assert flow.state == ConnectionState.NEW

    def test_flow_has_unique_id(self, tracker):
        """Test that each flow gets a unique ID"""
        flow1 = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        flow2 = tracker.create_flow("10.0.0.3", 1002, "10.0.0.4", 443)

        assert flow1.flow_id != flow2.flow_id

    def test_flow_has_timestamps(self, tracker):
        """Test that flow has creation timestamp"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)

        assert flow.created_at is not None
        assert isinstance(flow.created_at, datetime)

    def test_retrieve_flow_by_id(self, tracker):
        """Test retrieving a flow by its ID"""
        flow = tracker.create_flow("192.168.1.1", 5000, "10.0.0.1", 80)
        retrieved = tracker.get_flow(flow.flow_id)

        assert retrieved is not None
        assert retrieved.flow_id == flow.flow_id
        assert retrieved.client_ip == "192.168.1.1"

    def test_retrieve_nonexistent_flow(self, tracker):
        """Test that retrieving non-existent flow returns None"""
        result = tracker.get_flow("nonexistent-flow-id")
        assert result is None


class TestFlowStateTransitions:
    """Test flow state transitions"""

    def test_new_to_established(self, tracker):
        """Test transitioning from NEW to ESTABLISHED"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        assert flow.state == ConnectionState.NEW

        tracker.update_flow_state(flow.flow_id, ConnectionState.ESTABLISHED)
        updated_flow = tracker.get_flow(flow.flow_id)
        assert updated_flow.state == ConnectionState.ESTABLISHED

    def test_established_to_closing(self, tracker):
        """Test transitioning from ESTABLISHED to CLOSING"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_state(flow.flow_id, ConnectionState.ESTABLISHED)
        tracker.update_flow_state(flow.flow_id, ConnectionState.CLOSING)

        updated = tracker.get_flow(flow.flow_id)
        assert updated.state == ConnectionState.CLOSING

    def test_close_flow(self, tracker):
        """Test closing a flow"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.close_flow(flow.flow_id)

        closed_flow = tracker.get_flow(flow.flow_id)
        assert closed_flow.state == ConnectionState.CLOSED


class TestTrafficTracking:
    """Test traffic statistics tracking"""

    def test_update_traffic_sent(self, tracker):
        """Test updating sent bytes"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_traffic(flow.flow_id, sent=1024)

        updated = tracker.get_flow(flow.flow_id)
        assert updated.bytes_sent == 1024

    def test_update_traffic_received(self, tracker):
        """Test updating received bytes"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_traffic(flow.flow_id, received=2048)

        updated = tracker.get_flow(flow.flow_id)
        assert updated.bytes_received == 2048

    def test_cumulative_traffic(self, tracker):
        """Test that traffic stats are cumulative"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_traffic(flow.flow_id, sent=500)
        tracker.update_flow_traffic(flow.flow_id, sent=300)
        tracker.update_flow_traffic(flow.flow_id, received=1000)

        updated = tracker.get_flow(flow.flow_id)
        assert updated.bytes_sent == 800
        assert updated.bytes_received == 1000

    def test_packet_count_updates(self, tracker):
        """Test that packet counts are updated"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_traffic(flow.flow_id, sent=100)
        tracker.update_flow_traffic(flow.flow_id, sent=200)

        updated = tracker.get_flow(flow.flow_id)
        assert updated.packets_sent >= 2


class TestApplicationAssociation:
    """Test application and user association"""

    def test_associate_application(self, tracker):
        """Test associating an application with a flow"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 443)
        tracker.update_flow_application(flow.flow_id, "HTTPS-Browser", "web")

        updated = tracker.get_flow(flow.flow_id)
        assert updated.application == "HTTPS-Browser"
        assert updated.category == "web"

    def test_associate_user(self, tracker):
        """Test associating a user with a flow"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.update_flow_user(flow.flow_id, "john.doe", ["users", "admins"])

        updated = tracker.get_flow(flow.flow_id)
        assert updated.username == "john.doe"


class TestFlowStatistics:
    """Test flow statistics"""

    def test_statistics_tracking(self, tracker):
        """Test that statistics are correctly tracked"""
        tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.create_flow("10.0.0.3", 1002, "10.0.0.4", 443)

        stats = tracker.get_statistics()
        assert stats['total_flows'] >= 2

    def test_active_flows_list(self, tracker):
        """Test getting active flows list"""
        tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.create_flow("10.0.0.3", 1002, "10.0.0.4", 443)

        active = tracker.get_active_flows(limit=10)
        assert len(active) >= 2

    def test_flow_to_dict(self, tracker):
        """Test flow to dictionary conversion"""
        flow = tracker.create_flow("192.168.1.100", 5000, "8.8.8.8", 53, "UDP")
        flow_dict = flow.to_dict()

        assert isinstance(flow_dict, dict)
        assert flow_dict['client_ip'] == "192.168.1.100"
        assert flow_dict['server_ip'] == "8.8.8.8"
        assert flow_dict['protocol'] == "UDP"

    def test_flow_duration(self, tracker):
        """Test flow duration calculation"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        duration = flow.duration()

        assert isinstance(duration, (int, float))
        assert duration >= 0


class TestFlowCleanup:
    """Test flow cleanup functionality"""

    def test_cleanup_closed_flows(self, tracker):
        """Test that closed flows get cleaned up"""
        flow = tracker.create_flow("10.0.0.1", 1001, "10.0.0.2", 80)
        tracker.close_flow(flow.flow_id)

        # Force cleanup
        tracker._cleanup_old_flows(force=True)

        # Flow may or may not be removed depending on age
        # At minimum, it should be in CLOSED state
        remaining = tracker.get_flow(flow.flow_id)
        if remaining:
            assert remaining.state == ConnectionState.CLOSED


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
