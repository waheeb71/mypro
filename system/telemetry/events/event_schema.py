#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - Event Schema
═══════════════════════════════════════════════════════════════════

Unified event schema for all traffic paths (XDP + Normal mode).
Implements the mandatory schema fields as per requirements.

Required fields:
- timestamp, flow_id, src_ip, dst_ip, src_port, dst_port, protocol
- iface_in, iface_out, bytes, packets, direction
- source_path (xdp|normal)
- feature_vector_ref, ml_score, ml_label, confidence
- policy_id, verdict, reason

Author: Enterprise Security Team
License: Proprietary
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
import json


class EventDirection(Enum):
    """Traffic direction"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    EXTERNAL = "external"


class EventVerdict(Enum):
    """Final verdict for the event"""
    ALLOW = "allow"
    DROP = "drop"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    LOG_ONLY = "log_only"
    REDIRECT = "redirect"


class SourcePath(Enum):
    """Source path of the event"""
    XDP = "xdp"
    NORMAL = "normal"
    HYBRID = "hybrid"


@dataclass
class EventMetadata:
    """
    Additional metadata for the event.
    Flexible structure for extra information.
    """
    user_agent: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    asn: Optional[int] = None
    threat_level: Optional[str] = None
    threat_types: List[str] = field(default_factory=list)
    reputation_score: Optional[float] = None
    categories: List[str] = field(default_factory=list)
    custom: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class EventSchema:
    """
    Unified Event Schema for Enterprise NGFW
    
    This schema is used by all traffic paths (XDP and Normal mode)
    to ensure consistent event logging and processing.
    
    All fields marked as required MUST be populated.
    Optional fields can be None but should be filled when available.
    """
    
    # ═══ Required Core Fields ═══
    timestamp: datetime
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # tcp, udp, icmp, etc.
    
    # ═══ Interface Information ═══
    iface_in: str  # Input interface
    iface_out: str  # Output interface
    
    # ═══ Traffic Metrics ═══
    bytes: int  # Total bytes transferred
    packets: int  # Total packets
    
    # ═══ Direction and Path ═══
    direction: EventDirection
    source_path: SourcePath  # xdp or normal
    
    # ═══ ML/AI Fields ═══
    feature_vector_ref: Optional[str] = None  # Reference to feature vector
    ml_score: Optional[float] = None  # ML model score (0.0 - 1.0)
    ml_label: Optional[str] = None  # ML predicted label
    confidence: Optional[float] = None  # Confidence level (0.0 - 1.0)
    
    # ═══ Policy and Decision ═══
    policy_id: Optional[str] = None  # ID of applied policy
    verdict: EventVerdict = EventVerdict.ALLOW
    reason: str = "No specific reason"  # Human-readable reason
    
    # ═══ Additional Context ═══
    domain: Optional[str] = None
    url: Optional[str] = None
    application: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # ═══ Metadata ═══
    metadata: EventMetadata = field(default_factory=EventMetadata)
    
    # ═══ System Fields ═══
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ingestion_time: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validation after initialization"""
        # Ensure enum types
        if isinstance(self.direction, str):
            self.direction = EventDirection(self.direction)
        if isinstance(self.source_path, str):
            self.source_path = SourcePath(self.source_path)
        if isinstance(self.verdict, str):
            self.verdict = EventVerdict(self.verdict)
        
        # Validate required fields
        if not self.flow_id:
            raise ValueError("flow_id is required")
        if not self.src_ip or not self.dst_ip:
            raise ValueError("src_ip and dst_ip are required")
        if self.src_port < 0 or self.src_port > 65535:
            raise ValueError("src_port must be between 0 and 65535")
        if self.dst_port < 0 or self.dst_port > 65535:
            raise ValueError("dst_port must be between 0 and 65535")
        if self.bytes < 0 or self.packets < 0:
            raise ValueError("bytes and packets must be non-negative")
        
        # Validate ML fields if present
        if self.ml_score is not None and not (0.0 <= self.ml_score <= 1.0):
            raise ValueError("ml_score must be between 0.0 and 1.0")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert event to dictionary for serialization
        
        Returns:
            Dictionary representation of the event
        """
        data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'ingestion_time': self.ingestion_time.isoformat(),
            'flow_id': self.flow_id,
            
            # Network tuple
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            
            # Interface
            'iface_in': self.iface_in,
            'iface_out': self.iface_out,
            
            # Metrics
            'bytes': self.bytes,
            'packets': self.packets,
            
            # Direction and path
            'direction': self.direction.value,
            'source_path': self.source_path.value,
            
            # ML fields
            'feature_vector_ref': self.feature_vector_ref,
            'ml_score': self.ml_score,
            'ml_label': self.ml_label,
            'confidence': self.confidence,
            
            # Policy
            'policy_id': self.policy_id,
            'verdict': self.verdict.value,
            'reason': self.reason,
            
            # Additional
            'domain': self.domain,
            'url': self.url,
            'application': self.application,
            'user_id': self.user_id,
            'session_id': self.session_id,
            
            # Metadata
            'metadata': self.metadata.to_dict()
        }
        
        # Remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """
        Convert event to JSON string
        
        Args:
            indent: JSON indentation level (None for compact)
            
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventSchema':
        """
        Create EventSchema from dictionary
        
        Args:
            data: Dictionary with event data
            
        Returns:
            EventSchema instance
        """
        # Parse timestamps
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        if isinstance(data.get('ingestion_time'), str):
            data['ingestion_time'] = datetime.fromisoformat(data['ingestion_time'])
        
        # Parse enums
        if 'direction' in data and isinstance(data['direction'], str):
            data['direction'] = EventDirection(data['direction'])
        if 'source_path' in data and isinstance(data['source_path'], str):
            data['source_path'] = SourcePath(data['source_path'])
        if 'verdict' in data and isinstance(data['verdict'], str):
            data['verdict'] = EventVerdict(data['verdict'])
        
        # Parse metadata
        if 'metadata' in data and isinstance(data['metadata'], dict):
            data['metadata'] = EventMetadata(**data['metadata'])
        
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EventSchema':
        """
        Create EventSchema from JSON string
        
        Args:
            json_str: JSON string
            
        Returns:
            EventSchema instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def __str__(self) -> str:
        """String representation"""
        return (
            f"Event({self.event_id[:8]}): "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"[{self.protocol}] {self.verdict.value} via {self.source_path.value} "
            f"({self.bytes}B, {self.packets}pkts)"
        )
    
    def __repr__(self) -> str:
        """Detailed representation"""
        return f"EventSchema({self.to_dict()})"


# ═══ Helper Functions ═══

def create_event_from_xdp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    interface: str,
    bytes_count: int,
    packets_count: int,
    verdict: EventVerdict,
    reason: str,
    **kwargs
) -> EventSchema:
    """
    Helper function to create event from XDP path
    
    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        src_port: Source port
        dst_port: Destination port
        protocol: Protocol (tcp/udp/icmp)
        interface: Network interface
        bytes_count: Bytes transferred
        packets_count: Packets count
        verdict: Final verdict
        reason: Reason for verdict
        **kwargs: Additional fields
        
    Returns:
        EventSchema instance
    """
    return EventSchema(
        timestamp=datetime.utcnow(),
        flow_id=kwargs.get('flow_id', f"xdp-{uuid.uuid4()}"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        iface_in=interface,
        iface_out=interface,
        bytes=bytes_count,
        packets=packets_count,
        direction=kwargs.get('direction', EventDirection.INBOUND),
        source_path=SourcePath.XDP,
        verdict=verdict,
        reason=reason,
        policy_id=kwargs.get('policy_id'),
        ml_score=kwargs.get('ml_score'),
        ml_label=kwargs.get('ml_label'),
        confidence=kwargs.get('confidence'),
        metadata=kwargs.get('metadata', EventMetadata())
    )


def create_event_from_proxy(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    bytes_count: int,
    packets_count: int,
    verdict: EventVerdict,
    reason: str,
    **kwargs
) -> EventSchema:
    """
    Helper function to create event from Normal (Proxy) path
    
    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        src_port: Source port
        dst_port: Destination port
        protocol: Protocol
        bytes_count: Bytes transferred
        packets_count: Packets count
        verdict: Final verdict
        reason: Reason for verdict
        **kwargs: Additional fields
        
    Returns:
        EventSchema instance
    """
    return EventSchema(
        timestamp=datetime.utcnow(),
        flow_id=kwargs.get('flow_id', f"proxy-{uuid.uuid4()}"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        iface_in=kwargs.get('iface_in', 'proxy'),
        iface_out=kwargs.get('iface_out', 'proxy'),
        bytes=bytes_count,
        packets=packets_count,
        direction=kwargs.get('direction', EventDirection.OUTBOUND),
        source_path=SourcePath.NORMAL,
        verdict=verdict,
        reason=reason,
        domain=kwargs.get('domain'),
        url=kwargs.get('url'),
        application=kwargs.get('application'),
        user_id=kwargs.get('user_id'),
        session_id=kwargs.get('session_id'),
        policy_id=kwargs.get('policy_id'),
        ml_score=kwargs.get('ml_score'),
        ml_label=kwargs.get('ml_label'),
        confidence=kwargs.get('confidence'),
        feature_vector_ref=kwargs.get('feature_vector_ref'),
        metadata=kwargs.get('metadata', EventMetadata())
    )
