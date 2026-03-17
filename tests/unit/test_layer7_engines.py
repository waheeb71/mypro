import pytest
from datetime import datetime
from policy.schema import AppRule, WebFilterRule, PolicyContext, Action, TimeSchedule
from policy.app_control.engine import AppControlEngine
from policy.web_filter.engine import WebFilterEngine

def test_app_control_category_blocking():
    engine = AppControlEngine()
    rule = AppRule(
        name="Block Social Media",
        action=Action.BLOCK,
        category="social-media"
    )
    engine.load_rules([rule])
    
    # Needs a mock since EncryptedAppSignatures is a stub without categories mapped
    class MockSignatures:
        @staticmethod
        def get_category(app_id):
            return "social-media" if app_id == "facebook" else "other"
            
    import policy.app_control.engine
    policy.app_control.engine.EncryptedAppSignatures = MockSignatures
    
    ctx_block = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443, protocol="tcp",
        app_id="facebook"
    )
    assert engine.evaluate(ctx_block) == Action.BLOCK
    
    ctx_allow = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443, protocol="tcp",
        app_id="zoom"
    )
    assert engine.evaluate(ctx_allow) == Action.ALLOW

def test_web_filter_file_types():
    engine = WebFilterEngine()
    rule = WebFilterRule(
        name="Block EXEs",
        action=Action.BLOCK,
        block_file_types=["exe", "bat"]
    )
    engine.load_rules([rule])
    
    ctx_block = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=80, protocol="tcp",
        url="http://badsite.com/malware.exe"
    )
    assert engine.evaluate(ctx_block) == Action.BLOCK
    
    ctx_allow = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=80, protocol="tcp",
        url="http://goodsite.com/image.png"
    )
    assert engine.evaluate(ctx_allow) == Action.ALLOW

def test_web_filter_wildcards():
    engine = WebFilterEngine()
    rule = WebFilterRule(
        name="Block Admin Panels",
        action=Action.BLOCK,
        exact_urls=["*/admin*"]
    )
    engine.load_rules([rule])
    
    ctx_block = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=80, protocol="tcp",
        url="http://somesite.com/admin/login.php"
    )
    assert engine.evaluate(ctx_block) == Action.BLOCK

def test_web_filter_safe_search():
    engine = WebFilterEngine()
    rule = WebFilterRule(
        name="Enforce Google SafeSearch",
        action=Action.ALLOW,
        safe_search=True
    )
    engine.load_rules([rule])
    
    ctx = PolicyContext(
        src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443, protocol="tcp",
        domain="www.google.com"
    )
    
    # The action returned is MONITOR indicating interception/modification
    assert engine.evaluate(ctx) == Action.MONITOR
