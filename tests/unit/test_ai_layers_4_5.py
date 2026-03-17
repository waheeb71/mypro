import pytest
from datetime import datetime
from policy.manager import PolicyManager
from policy.schema import PolicyContext, Action
from policy.smart_blocker.threat_intelligence import ThreatLevel, ThreatType

def test_threat_intelligence_layer_4():
    manager = PolicyManager()
    
    # Manually inject a threat into the IPS engine's threat intel component
    manager.ips_engine.threat_intel.add_indicator(
        indicator="1.1.1.99",
        indicator_type="ip",
        threat_level=ThreatLevel.CRITICAL,
        threat_types=[ThreatType.MALWARE],
        source="TestFeed"
    )
    
    manager.ips_engine.threat_intel.add_indicator(
        indicator="evil-malware.com",
        indicator_type="domain",
        threat_level=ThreatLevel.HIGH,
        threat_types=[ThreatType.C2_SERVER],
        source="TestFeed"
    )
    
    # 1. Test clean IP
    clean_ctx = PolicyContext(
        src_ip="192.168.1.100", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp"
    )
    assert manager.evaluate(clean_ctx) == Action.ALLOW
    
    # 2. Test Malicious IP
    bad_ip_ctx = PolicyContext(
        src_ip="1.1.1.99", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp"
    )
    assert manager.evaluate(bad_ip_ctx) == Action.BLOCK
    
    # 3. Test Malicious Domain
    bad_domain_ctx = PolicyContext(
        src_ip="192.168.1.100", dst_ip="1.2.3.4",
        src_port=1234, dst_port=443, protocol="tcp",
        domain="evil-malware.com"
    )
    assert manager.evaluate(bad_domain_ctx) == Action.BLOCK


def test_adaptive_policy_layer_5():
    manager = PolicyManager()
    
    # Wait, the manager instantiated the Adaptive Engine.
    assert manager.adaptive_engine is not None
    
    # Let's simulate a repeat offender IP
    offender_ip = "10.0.0.55"
    
    # Pre-adaptation, the flow is ALLOWED because nothing else blocks it
    ctx = PolicyContext(
        src_ip=offender_ip, dst_ip="8.8.8.8",
        src_port=1234, dst_port=80, protocol="tcp"
    )
    assert manager.evaluate(ctx) == Action.ALLOW
    
    # Force 5 malicious feedback entries directly into the adaptive buffer to trigger a block rule
    from system.ml_core.adaptive_policy import PolicyAction as MLPolicyAction
    for _ in range(5):
        manager.adaptive_engine.add_feedback(
            src_ip=offender_ip,
            action_taken=MLPolicyAction.BLOCK,
            was_threat=True,
            threat_type="simulated_threat"
        )
        
    # Manually trigger adaptation instead of waiting for adaptation_interval
    manager.adaptive_engine._perform_adaptation()
    
    # Now evaluate the flow again from the same source IP.
    # It should hit the newly generated adaptive rule and block it.
    assert manager.evaluate(ctx) == Action.BLOCK
