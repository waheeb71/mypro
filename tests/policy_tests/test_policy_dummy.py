from datetime import datetime, time

from policy.schema import (
    Action,
    Protocol,
    FirewallRule,
    AppRule,
    WebFilterRule,
    PolicyContext,
)
from policy.manager import PolicyManager
from policy.access_control.acl_engine import ACLEngine
from policy.access_control.schedules import Schedule
from policy.access_control.zones import ZoneManager
from policy.app_control.signatures import EncryptedAppSignatures
from policy.web_filter.category import CategoryEngine, ContentCategory
from policy.web_filter.dns_filter import DNSFilter
from policy.web_filter.safe_search import SafeSearch
from policy.ips.engine import IPSEngine
from policy.ips.threat_intel import ThreatLevel, ThreatType
from policy.ips.signatures import SignatureEngine


def test_acl_port_range_and_list():
    acl = ACLEngine()
    acl.load_rules(
        [
            FirewallRule(
                name="block-web-range",
                action=Action.BLOCK,
                dst_port="80-90",
                protocol=Protocol.TCP,
                priority=1,
            ),
            FirewallRule(
                name="block-multi",
                action=Action.BLOCK,
                dst_port=[22, 2222, "2223-2225"],
                protocol=Protocol.TCP,
                priority=2,
            ),
        ]
    )

    ctx_range = PolicyContext(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5555,
        dst_port=85,
        protocol="tcp",
    )
    assert acl.evaluate(ctx_range) == Action.BLOCK

    ctx_list = PolicyContext(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5555,
        dst_port=2224,
        protocol="tcp",
    )
    assert acl.evaluate(ctx_list) == Action.BLOCK


def test_schedule_cross_midnight():
    sched = Schedule(
        name="night",
        days=["Mon"],
        start_time=time(22, 0),
        end_time=time(2, 0),
    )
    monday_23 = datetime(2024, 1, 1, 23, 0, 0)
    tuesday_01 = datetime(2024, 1, 2, 1, 0, 0)
    tuesday_10 = datetime(2024, 1, 2, 10, 0, 0)

    assert sched.is_active(monday_23) is True
    assert sched.is_active(tuesday_01) is True
    assert sched.is_active(tuesday_10) is False


def test_web_filter_exact_url():
    wf = PolicyManager().web_engine
    wf.load_rules(
        [
            WebFilterRule(
                name="block-exact",
                action=Action.BLOCK,
                exact_urls=["https://example.com/private"],
            )
        ]
    )
    ctx = PolicyContext(
        src_ip="10.0.0.1",
        dst_ip="1.1.1.1",
        src_port=1234,
        dst_port=443,
        protocol="tcp",
        domain="example.com",
        url="https://example.com/private",
    )
    assert wf.evaluate(ctx) == Action.BLOCK


def test_acl_deny_by_default():
    acl = ACLEngine(default_action=Action.BLOCK)
    acl.load_rules(
        [
            FirewallRule(
                name="allow-dns",
                action=Action.ALLOW,
                dst_port=53,
                protocol=Protocol.UDP,
                priority=1,
            )
        ]
    )

    ctx_allow = PolicyContext(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=5555,
        dst_port=53,
        protocol="udp",
    )
    ctx_block = PolicyContext(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=5555,
        dst_port=80,
        protocol="tcp",
    )

    assert acl.evaluate(ctx_allow) == Action.ALLOW
    assert acl.evaluate(ctx_block) == Action.BLOCK


def test_existing_components_still_work():
    pm = PolicyManager()
    pm.app_engine.load_rules(
        [
            AppRule(
                name="block-tiktok",
                action=Action.BLOCK,
                application="tiktok",
                priority=1,
            )
        ]
    )
    app_ctx = PolicyContext(
        src_ip="10.0.0.2",
        dst_ip="8.8.8.8",
        src_port=1234,
        dst_port=443,
        protocol="tcp",
        app_id="tiktok",
        user_id="user1",
    )
    assert pm.app_engine.evaluate(app_ctx) == Action.BLOCK
    assert EncryptedAppSignatures.identify_by_sni("media.tiktok.com") == "tiktok"

    wf = pm.web_engine
    wf.category_engine.block_category(ContentCategory.SOCIAL_NETWORKING)
    web_ctx = PolicyContext(
        src_ip="10.0.0.2",
        dst_ip="1.1.1.1",
        src_port=1234,
        dst_port=443,
        protocol="tcp",
        domain="facebook.com",
        url="https://facebook.com",
    )
    assert wf.evaluate(web_ctx) == Action.BLOCK

    dns = DNSFilter()
    dns.add_domain("bad.example")
    assert dns.check_query("bad.example") is True
    assert dns.get_response() == "0.0.0.0"

    assert (
        SafeSearch.get_safe_cname("google.com") == "forcesafesearch.google.com"
    )
    assert SafeSearch.append_safe_param("https://google.com/search?q=test").endswith(
        "safe=active"
    )

    cat_engine = CategoryEngine()
    match = cat_engine.categorize("example-facebook.com")
    assert ContentCategory.SOCIAL_NETWORKING in match.categories

    ips = IPSEngine()
    ips.threat_intel.add_indicator(
        indicator="5.5.5.5",
        type="ip",
        level=ThreatLevel.HIGH,
        types=[ThreatType.MALWARE],
        source="unit-test",
    )
    ctx_threat = PolicyContext(
        src_ip="5.5.5.5",
        dst_ip="8.8.8.8",
        src_port=1234,
        dst_port=80,
        protocol="tcp",
    )
    assert ips.evaluate(ctx_threat) == Action.BLOCK

    sig = SignatureEngine()
    sig.load_defaults()
    alerts = sig.scan(b"GET /?q=1 UNION SELECT * FROM users")
    assert any("SQL Injection" in a for a in alerts)

    zones = ZoneManager({"eth0": "wan", "eth1": "lan"})
    assert zones.get_zone("eth0") == "wan"
