import pytest
import asyncio
from system.core.flow_tracker import FlowTracker, ConnectionState
from ml.analytics.user_behavior import UserBehaviorAnalytics
from ml.analytics.vulnerability_scorer import VulnerabilityPredictor

@pytest.fixture
def flow_tracker():
    config = {'flow_tracking': {'max_flows': 100}}
    tracker = FlowTracker(config)
    
    uba = UserBehaviorAnalytics()
    vuln_pred = VulnerabilityPredictor()
    tracker.set_analytics(uba, vuln_pred)
    
    return tracker, uba, vuln_pred

def test_vulnerability_predictor_integration(flow_tracker):
    tracker, uba, vuln = flow_tracker
    
    # Simulating a new connection to an internal asset
    flow = tracker.create_flow(
        client_ip="192.168.1.50",
        client_port=54321,
        server_ip="10.0.0.5",
        server_port=443,
        protocol="TCP"
    )
    
    # Vulnerability Predictor should have recorded the asset
    assert "10.0.0.5" in vuln.asset_profiles
    assert 443 in vuln.asset_profiles["10.0.0.5"]["open_ports"]

def test_user_behavior_analytics_integration(flow_tracker):
    tracker, uba, vuln = flow_tracker
    
    flow = tracker.create_flow(
        client_ip="192.168.1.50",
        client_port=54321,
        server_ip="10.0.0.5",
        server_port=443,
        protocol="TCP"
    )
    
    # Assign user to flow
    tracker.update_flow_user(flow.flow_id, username="admin_user")
    
    # Update traffic (simulating downloaded data)
    tracker.update_flow_traffic(flow.flow_id, sent=1000, received=5000)
    
    # UBA should have created a profile and logged the IP and port
    assert "admin_user" in uba.profiles
    profile = uba.profiles["admin_user"]
    assert "192.168.1.50" in profile.typical_ips
    assert "443" in profile.typical_services
