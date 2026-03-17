"""
IPS Signatures
Signature-based detection with basic Snort-like rule parsing.
"""

from typing import List, NamedTuple, Optional, Dict
import re
import logging

logger = logging.getLogger(__name__)

class Signature(NamedTuple):
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    msg: str
    content: bytes
    sid: int
    
class SignatureEngine:
    """ Snort-like Signature Matcher """
    
    def __init__(self):
        self.signatures: List[Signature] = []
        
    def load_defaults(self):
        # Default rules if none provided
        self.parse_rule('alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection"; content:"UNION SELECT"; sid:1001;)')
        self.parse_rule('alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"Path Traversal"; content:"../.."; sid:1002;)')
        self.parse_rule('alert tcp any any -> any any (msg:"Possible SSH Brute Force"; content:"SSH-2.0-OpenSSH"; sid:1003;)')
        
    def load_from_db(self, db_signatures: List[any]):
        """Clear and load signatures from SQLAlchemy models"""
        self.signatures = []
        for db_sig in db_signatures:
            self.parse_rule(db_sig.raw_rule)
        
    def parse_rule(self, rule_str: str) -> bool:
        """ 
        Parses a basic Snort rule:
        alert tcp any any -> any any (msg:"Test"; content:"foo"; sid:1;)
        """
        try:
            rule_str = rule_str.strip()
            if not rule_str or rule_str.startswith('#'):
                return False
                
            header, options_str = rule_str.split('(', 1)
            options_str = options_str.rstrip(')')
            
            header_parts = header.strip().split()
            if len(header_parts) != 7:
                return False
                
            action, proto, src_ip, src_port, direction, dst_ip, dst_port = header_parts
            
            # Parse options
            opts: Dict[str, str] = {}
            for opt in options_str.split(';'):
                opt = opt.strip()
                if not opt: continue
                if ':' in opt:
                    k, v = opt.split(':', 1)
                    opts[k.strip()] = v.strip().strip('"')
            
            content_str = opts.get('content', '')
            content_bytes = content_str.encode('utf-8')
            
            sig = Signature(
                action=action,
                protocol=proto,
                src_ip=src_ip,
                src_port=src_port,
                direction=direction,
                dst_ip=dst_ip,
                dst_port=dst_port,
                msg=opts.get('msg', 'Unknown Alert'),
                content=content_bytes,
                sid=int(opts.get('sid', 0))
            )
            self.signatures.append(sig)
            return True
        except Exception as e:
            logger.error(f"Failed to parse rule '{rule_str[:30]}...': {e}")
            return False

    def load_rules_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                loaded = 0
                for line in f:
                    if self.parse_rule(line):
                        loaded += 1
                logger.info(f"Loaded {loaded} signatures from {file_path}")
        except FileNotFoundError:
            logger.warning(f"Signature file {file_path} not found")

    def scan(self, payload: bytes, protocol: str = "any") -> List[str]:
        alerts = []
        for sig in self.signatures:
            if sig.protocol != 'any' and sig.protocol.lower() != protocol.lower():
                continue
                
            if sig.content and sig.content in payload:
                alerts.append(f"[{sig.sid}] {sig.msg}")
        return alerts
