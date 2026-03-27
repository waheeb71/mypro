"""
CyberNexus NGFW — Event Schema Definitions
==========================================
Strongly-typed event payloads for all bus topics.
All events must inherit from BaseEvent.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid() -> str:
    return str(uuid.uuid4())


@dataclass
class BaseEvent:
    """All events must inherit from this."""
    event_id: str = field(default_factory=_uid)
    timestamp: str = field(default_factory=_now)
    node_id: str = "local"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Data Plane Events ──────────────────────────────────────────────

@dataclass
class PacketInspectedEvent(BaseEvent):
    session_id: str = ""
    module: str = ""
    action: str = "ALLOW"           # "ALLOW" | "BLOCK"
    score: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    latency_ms: float = 0.0


@dataclass
class ConnectionEstablishedEvent(BaseEvent):
    session_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""


@dataclass
class ConnectionClosedEvent(BaseEvent):
    session_id: str = ""
    duration_ms: float = 0.0
    bytes_rx: int = 0
    bytes_tx: int = 0


# ── Security Events ────────────────────────────────────────────────

@dataclass
class ThreatDetectedEvent(BaseEvent):
    session_id: str = ""
    module: str = ""               # Which module detected it
    threat_type: str = ""          # "sqli", "xss", "malware", "botnet" …
    confidence: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    reason: str = ""
    rule_id: Optional[int] = None
    raw_evidence: Optional[str] = None


@dataclass
class PolicyEvaluatedEvent(BaseEvent):
    session_id: str = ""
    rule_id: int = 0
    rule_name: str = ""
    action: str = "ALLOW"
    src_ip: str = ""
    dst_ip: str = ""


@dataclass
class AnomalyScoredEvent(BaseEvent):
    user_id: str = ""
    device_id: str = ""
    score: float = 0.0
    reason: str = ""
    source_module: str = "uba"


# ── AI Events ──────────────────────────────────────────────────────

@dataclass
class AIScoreRequestedEvent(BaseEvent):
    session_id: str = ""
    features: dict = field(default_factory=dict)
    priority: str = "normal"       # "high" | "normal" | "low"


@dataclass
class AIScoreGeneratedEvent(BaseEvent):
    session_id: str = ""
    score: float = 0.0
    confidence: float = 0.0
    model_version: str = ""
    inference_ms: float = 0.0
    skipped: bool = False


# ── Response Events ────────────────────────────────────────────────

@dataclass
class ResponseBlockEvent(BaseEvent):
    src_ip: str = ""
    reason: str = ""
    duration_s: int = 3600         # Block duration (0 = permanent)
    triggered_by: str = ""         # Module that triggered the block


@dataclass
class ResponseAlertEvent(BaseEvent):
    severity: str = "medium"       # "low" | "medium" | "high" | "critical"
    title: str = ""
    message: str = ""
    src_ip: str = ""


# ── System Health Events ───────────────────────────────────────────

@dataclass
class ModuleHealthEvent(BaseEvent):
    module_name: str = ""
    status: str = "healthy"        # "healthy" | "degraded" | "failed"
    circuit_state: str = "CLOSED"  # "CLOSED" | "OPEN" | "HALF-OPEN"
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0


@dataclass
class ConfigReloadedEvent(BaseEvent):
    changed_keys: list = field(default_factory=list)
    triggered_by: str = "watcher"  # "watcher" | "api" | "cli"
