import pytest
import asyncio
from system.core.flow_tracker import FlowTracker
from system.ha.state_sync import StateSynchronizer
from modules.qos.qos_manager import TokenBucket, QoSManager
from integration.vpn.wireguard import WireGuardManager, PeerConfig

def test_qos_manager_update():
    qos = QoSManager()
    assert qos.default_per_ip_rate == 1250000
    
    # Test update
    qos.update_limits(enabled=True, rate_bytes=500, burst_bytes=1000)
    assert qos.enabled is True
    assert qos.default_per_ip_rate == 500
    assert qos.default_per_ip_burst == 1000

@pytest.mark.asyncio
async def test_ha_state_sync_hook():
    tracker = FlowTracker({'flow_tracking': {'max_flows': 10}})
    
    # Mock sync manager
    class MockSyncManager:
        def __init__(self):
            self.is_master = True
            self.broadcasted = []
        
        async def broadcast_flow_state(self, flow_data):
            self.broadcasted.append(flow_data)
            
    sync = MockSyncManager()
    tracker.set_sync_manager(sync)
    
    # Create flow and ensure it would attempt broadcast
    tracker.create_flow(
        client_ip="1.2.3.4", client_port=1234,
        server_ip="5.6.7.8", server_port=80, protocol="TCP"
    )
    
    # Allow the task to start
    await asyncio.sleep(0.1)
    
    # The broadcast is an asyncio.Task, so in a sync test it might not run immediately, 
    # but the tracker should successfully inject it without syntax errors.
    assert tracker.state_sync is not None
    assert len(sync.broadcasted) == 1
    
def test_synced_flow_handling():
    tracker = FlowTracker({'flow_tracking': {'max_flows': 10}})
    
    # Simulate receiving a synced flow from master
    flow_data = {
        'flow_id': 'sync-flow-123',
        'client_ip': '10.0.0.1',
        'client_port': 55555,
        'server_ip': '8.8.8.8',
        'server_port': 53,
        'protocol': 'UDP',
        'application': 'dns',
        'start_time': '2026-03-04T12:00:00.000000'
    }
    
    tracker.handle_synced_flow(flow_data)
    
    assert 'sync-flow-123' in tracker.flows
    assert tracker.flows['sync-flow-123'].server_ip == '8.8.8.8'
    assert tracker.flows['sync-flow-123'].client_ip == '10.0.0.1'
