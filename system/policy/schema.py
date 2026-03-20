"""
Enterprise NGFW Policy Schema
Data models for policy rules and definitions.
"""

from typing import List, Optional, Dict, Union, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import uuid

class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REJECT = "reject"  # Send RST/ICMP unreachable
    MONITOR = "monitor"  # Log but allow
    CHALLENGE = "challenge"  # CAPTCHA/Auth
    RATE_LIMIT = "rate_limit"  # ✨ NEW: Apply rate limiting
    QUARANTINE = "quarantine"  # ✨ NEW: Isolate suspicious traffic
    LOG_ONLY = "log_only"  # ✨ NEW: Only log, no action
    DECEIVE = "deceive"  # ✨ NEW: Send deceptive payloads/tarpits to prove intent

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

@dataclass
class TimeSchedule:
    """Time-based restriction"""
    name: str
    days: List[str] # ["Mon", "Tue"...]
    start_time: str # "09:00"
    end_time: str   # "17:00"
    timezone: str = "UTC"

@dataclass
class BaseRule:
    """Base class for all policy rules"""
    name: str
    action: Action
    enabled: bool = True
    priority: int = 100
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    schedule: Optional[TimeSchedule] = None
    log: bool = True
    tags: List[str] = field(default_factory=list)

@dataclass
class FirewallRule(BaseRule):
    """Layer 3/4 Access Control Rule"""
    src_zone: str = "any" # LAN, WAN, DMZ
    dst_zone: str = "any"
    src_ip: Optional[Union[str, List[str]]] = None # CIDR or IP
    dst_ip: Optional[Union[str, List[str]]] = None
    src_port: Optional[Union[int, str]] = None # "80", "1024-65535"
    dst_port: Optional[Union[int, str]] = None
    protocol: Protocol = Protocol.ANY

@dataclass
class AppRule(BaseRule):
    """Layer 7 Application Control Rule"""
    application: str = "any" # "facebook", "bittorrent"
    category: Optional[str] = None # "social-media", "p2p"
    users: List[str] = field(default_factory=list) # User/Group names
    bandwidth_limit: Optional[int] = None # kbps

@dataclass
class WebFilterRule(BaseRule):
    """Web/URL Filtering Rule"""
    categories: List[str] = field(default_factory=list) # "gambling", "adult"
    exact_urls: List[str] = field(default_factory=list)
    block_file_types: List[str] = field(default_factory=list) # "exe", "zip"
    safe_search: bool = False

@dataclass
class IPSRule(BaseRule):
    """Intrusion Prevention Rule"""
    signature_id: Optional[str] = None
    severity_threshold: Optional[str] = None # "high", "critical"
    
@dataclass
class PolicyContext:
    """Context for policy evaluation"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    interface: str = "unknown"
    app_id: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
