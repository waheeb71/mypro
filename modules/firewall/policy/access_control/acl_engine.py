"""
Access Control List (ACL) Engine
Layer 3/4 Firewall Rule Evaluation
"""

import logging
import ipaddress
from datetime import datetime
from typing import List, Optional, Union, Dict, Any
from system.policy.schema import FirewallRule, PolicyContext, Action, Protocol

logger = logging.getLogger(__name__)

class ACLEngine:
    """
    Evaluates Firewall Rules based on 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Proto).
    Supports Zones (LAN, WAN, DMZ).
    """
    
    def __init__(self, default_action: Action = Action.BLOCK):
        self.rules: List[FirewallRule] = []
        self._compiled_ips: Dict[str, Dict[str, Any]] = {}
        self.logger = logger
        # Zero Trust: Default policy is implicit deny
        self.default_action = default_action 

    def load_rules(self, rules: List[FirewallRule]):
        """Load rules, sort by priority, and pre-compile network CIDRs for performance"""
        self.rules = sorted(rules, key=lambda r: r.priority)
        self._compiled_ips.clear()
        
        for rule in self.rules:
            self._compiled_ips[rule.id] = {
                'src': self._precompile_ip(rule.src_ip),
                'dst': self._precompile_ip(rule.dst_ip)
            }
            
        self.logger.info(f"Loaded and compiled {len(self.rules)} ACL rules")

    def evaluate(self, context: PolicyContext) -> Action:
        """Find first matching rule"""
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._match_rule(rule, context):
                self.logger.debug(f"Matched ACL Rule: {rule.name} -> {rule.action.value}")
                return rule.action
                
        return self.default_action

    def _match_rule(self, rule: FirewallRule, context: PolicyContext) -> bool:
        """Check if context matches rule criteria"""
        
        # 0. Time Schedule Match
        if rule.schedule:
            if not self._match_schedule(rule.schedule):
                return False

        # 1. Protocol Match
        if rule.protocol != Protocol.ANY:
            if rule.protocol.value.lower() != context.protocol.lower():
                return False

        # 2. Zone Match (Source & Dest)
        if rule.src_zone != "any" and rule.src_zone != context.interface: # Assuming context.interface maps to zone
            return False
            
        # 3. IP Match (Source & Dest using precompiled networks)
        compiled = self._compiled_ips.get(rule.id, {})
        if compiled.get('src') and not self._fast_match_ip(compiled['src'], context.src_ip):
            return False
            
        if compiled.get('dst') and not self._fast_match_ip(compiled['dst'], context.dst_ip):
            return False

        # 4. Port Match (Source)
        if rule.src_port:
            if not self._match_port(rule.src_port, context.src_port):
                return False

        # 5. Port Match (Dest)
        if rule.dst_port:
            if not self._match_port(rule.dst_port, context.dst_port):
                return False
                
        return True

    def _precompile_ip(self, rule_ip: Optional[Union[str, List[str]]]) -> Any:
        """Parse IPs and CIDRs into network objects once during loading"""
        if not rule_ip or rule_ip == "any":
            return None
            
        if isinstance(rule_ip, list):
            return [self._precompile_single_ip(rip) for rip in rule_ip]
        return self._precompile_single_ip(rule_ip)
        
    def _precompile_single_ip(self, ip_str: str) -> Any:
        try:
            if '/' in ip_str:
                return ipaddress.ip_network(ip_str, strict=False)
            return ipaddress.ip_address(ip_str)
        except ValueError:
            self.logger.warning(f"Invalid IP rule format: {ip_str}")
            return None

    def _fast_match_ip(self, compiled_target: Any, packet_ip_str: str) -> bool:
        """Fast match using precompiled network objects"""
        if compiled_target is None:
            return True
            
        try:
            packet_ip = ipaddress.ip_address(packet_ip_str)
            if isinstance(compiled_target, list):
                return any(self._check_compiled(ct, packet_ip) for ct in compiled_target if ct)
            return self._check_compiled(compiled_target, packet_ip)
        except ValueError:
            return False
            
    def _check_compiled(self, compiled_target: Any, packet_ip: Any) -> bool:
        if isinstance(compiled_target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return packet_ip in compiled_target
        return packet_ip == compiled_target

    def _match_schedule(self, schedule: Any) -> bool:
        """Check if current time falls within rule schedule"""
        now = datetime.now() # Depending on timezone configuration
        current_day = now.strftime("%a") # Mon, Tue, etc.
        
        if current_day not in schedule.days:
            return False
            
        try:
            now_time = now.time()
            start_time = datetime.strptime(schedule.start_time, "%H:%M").time()
            end_time = datetime.strptime(schedule.end_time, "%H:%M").time()
            return start_time <= now_time <= end_time
        except Exception as e:
            self.logger.error(f"Schedule parse error: {e}")
            return False

    def _match_port(self, rule_port: Union[int, str, List[Union[int, str]]], packet_port: int) -> bool:
        """Match Port (supports range '80-90', list, single)"""
        if rule_port == "any":
            return True
        if isinstance(rule_port, list):
            return any(self._match_port(rp, packet_port) for rp in rule_port)
        if isinstance(rule_port, int):
            return rule_port == packet_port
        # String handling
        if "-" in rule_port:
            start_s, end_s = rule_port.split("-", 1)
            try:
                start = int(start_s.strip())
                end = int(end_s.strip())
                return start <= packet_port <= end
            except ValueError:
                self.logger.warning(f"Invalid port range: {rule_port}")
                return False
        return str(rule_port).strip() == str(packet_port)
