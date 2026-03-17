import pytest
from datetime import datetime
from policy.schema import FirewallRule, PolicyContext, Action, Protocol, TimeSchedule
from policy.access_control.acl_engine import ACLEngine

def test_acl_implicit_deny():
    engine = ACLEngine()
    # No rules loaded
    ctx = PolicyContext(
        src_ip="192.168.1.10", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="LAN"
    )
    assert engine.evaluate(ctx) == Action.BLOCK

def test_acl_zone_matching():
    engine = ACLEngine()
    rule = FirewallRule(
        name="Allow LAN to WAN",
        action=Action.ALLOW,
        src_zone="LAN",
        dst_zone="WAN", # Currently schema doesn't match dst_zone in the _match_rule but let's test src_zone
    )
    engine.load_rules([rule])
    
    # Should match because interface maps to "LAN"
    ctx_match = PolicyContext(
        src_ip="192.168.1.10", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="LAN"
    )
    assert engine.evaluate(ctx_match) == Action.ALLOW
    
    # Should block because interface is "DMZ"
    ctx_block = PolicyContext(
        src_ip="10.0.0.5", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="DMZ"
    )
    assert engine.evaluate(ctx_block) == Action.BLOCK

def test_acl_precompiled_ips():
    engine = ACLEngine()
    rule = FirewallRule(
        name="Block bad subnet",
        action=Action.BLOCK,
        src_ip="10.10.10.0/24",
        priority=10
    )
    rule_allow = FirewallRule(
        name="Allow all",
        action=Action.ALLOW,
        priority=100
    )
    engine.load_rules([rule, rule_allow])
    
    # Should hit the block rule
    ctx_bad = PolicyContext(
        src_ip="10.10.10.55", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="LAN"
    )
    assert engine.evaluate(ctx_bad) == Action.BLOCK
    
    # Should fall through to allow rule
    ctx_good = PolicyContext(
        src_ip="10.10.20.55", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="LAN"
    )
    assert engine.evaluate(ctx_good) == Action.ALLOW

def test_acl_time_schedule(monkeypatch):
    engine = ACLEngine()
    
    schedule = TimeSchedule(
        name="Working Hours",
        days=["Mon", "Tue", "Wed", "Thu", "Fri"],
        start_time="09:00",
        end_time="17:00"
    )
    
    rule = FirewallRule(
        name="Allow during working hours",
        action=Action.ALLOW,
        schedule=schedule
    )
    
    engine.load_rules([rule])
    
    ctx = PolicyContext(
        src_ip="192.168.1.10", dst_ip="8.8.8.8",
        src_port=1234, dst_port=443, protocol="tcp", interface="LAN"
    )
    
    # Mock datetime to a Wednesday at 14:00 (inside schedule)
    class MockDatetimeInside(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 3, 4, 14, 0, 0) # Wednesday
    
    monkeypatch.setattr('policy.access_control.acl_engine.datetime', MockDatetimeInside)
    assert engine.evaluate(ctx) == Action.ALLOW
    
    # Mock datetime to a Sunday at 14:00 (outside schedule day)
    class MockDatetimeOutsideDay(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 3, 8, 14, 0, 0) # Sunday
            
    monkeypatch.setattr('policy.access_control.acl_engine.datetime', MockDatetimeOutsideDay)
    assert engine.evaluate(ctx) == Action.BLOCK
    
    # Mock datetime to a Wednesday at 20:00 (outside schedule time)
    class MockDatetimeOutsideTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 3, 4, 20, 0, 0) # Wednesday 20:00
            
    monkeypatch.setattr('policy.access_control.acl_engine.datetime', MockDatetimeOutsideTime)
    assert engine.evaluate(ctx) == Action.BLOCK
