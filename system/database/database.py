#!/usr/bin/env python3
"""
Enterprise CyberNexus - Database Layer

SQLAlchemy models for persistent storage:
- User: user accounts with hashed passwords
- Rule: firewall rules
- Event: security events log
- AuditLog: admin action audit trail

Supports SQLite (dev) and PostgreSQL (production).
"""

import logging
from datetime import datetime
from typing import Optional, AsyncGenerator

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, JSON,
    create_engine, event
)
from sqlalchemy.orm import (
    DeclarativeBase, sessionmaker, Session
)

logger = logging.getLogger(__name__)


# ==================== Base ====================

class Base(DeclarativeBase):
    """SQLAlchemy declarative base"""
    pass


# ==================== Models ====================

class User(Base):
    """User account"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default='viewer')
    email = Column(String(128), nullable=True)
    display_name = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True)
    is_ldap = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Rule(Base):
    """Firewall rule / user resource-permission rule"""
    __tablename__ = 'rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    # ── User-permission fields (used by RBAC in auth.py / users_routes.py) ──
    user_id = Column(Integer, nullable=True, index=True)   # FK → users.id
    resource = Column(String(64), nullable=True, index=True)  # e.g. 'firewall', 'vpn'
    # ── Firewall-rule fields ─────────────────────────────────────────────────
    name = Column(String(128), nullable=True)
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    action = Column(String(20), nullable=False, default='BLOCK')
    priority = Column(Integer, default=50)
    enabled = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'action': self.action,
            'priority': self.priority,
            'enabled': self.enabled,
            'description': self.description,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Rule #{self.id} {self.action} {self.src_ip}→{self.dst_port}>"


class SecurityEvent(Base):
    """Security event log"""
    __tablename__ = 'security_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default='info')
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    action = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    event_metadata = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'action': self.action,
            'description': self.description,
            'anomaly_score': self.anomaly_score,
        }


class AuditLog(Base):
    """Admin action audit trail"""
    __tablename__ = 'audit_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(64), nullable=True)


class EmailSecurityConfig(Base):
    """Email Security Profile Settings"""
    __tablename__ = 'email_security_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=True)
    mode = Column(String(32), default='enforce')
    monitored_ports = Column(JSON, default=[25, 587, 465, 143, 993, 110, 995])
    
    preprocessing = Column(JSON, default={})
    phishing = Column(JSON, default={})
    url_scanner = Column(JSON, default={})
    attachment_guard = Column(JSON, default={})
    sender_reputation = Column(JSON, default={})
    spam_filter = Column(JSON, default={})
    smtp_commands = Column(JSON, default={})
    thresholds = Column(JSON, default={})
    logging = Column(JSON, default={})
    whitelist = Column(JSON, default={})


# ==================== QoS Model ====================

class QoSConfig(Base):
    """Quality of Service — global rate-limit configuration."""
    __tablename__ = 'qos_config'
    

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=False)

    # Per-IP defaults (Token Bucket)
    default_user_rate_bytes = Column(Integer, default=1_250_000)   # ~10 Mbps
    default_user_burst_bytes = Column(Integer, default=2_500_000)  # ~20 Mbps burst

    # Global ceiling (optional, 0 = unlimited)
    global_rate_bytes = Column(Integer, default=0)

    # Traffic class priorities (JSON list of dicts: {dscp, priority, rate_bytes})
    traffic_classes = Column(JSON, default=[])

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ── DB session helpers (FastAPI Depends compatible) ───────────────────────────

_db_manager_ref = None  # Set by DatabaseManager.initialize() for global access


def get_db():
    """
    FastAPI dependency that yields a SQLAlchemy session.

    Usage:
        @router.get("/foo")
        async def foo(db: Session = Depends(get_db)):
            ...
    """
    if _db_manager_ref is None:
        raise RuntimeError("DatabaseManager not initialized — call DatabaseManager.initialize() first")
    session = _db_manager_ref.session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def SessionLocal():
    """Backward-compat alias — returns a plain session (not a context manager)."""
    if _db_manager_ref is None:
        raise RuntimeError("DatabaseManager not initialized")
    return _db_manager_ref.session()


# ==================== VPN Models ====================

class VPNConfig(Base):
    """WireGuard interface configuration — one row per interface."""
    __tablename__ = 'vpn_config'

    id              = Column(Integer, primary_key=True, autoincrement=True)
    enabled         = Column(Boolean, default=False)
    interface       = Column(String(32), default='wg0', unique=True)
    listen_port     = Column(Integer, default=51820)
    server_ip       = Column(String(50), default='10.10.0.1/24')
    public_key      = Column(String(256), default='')
    # Private key stored ONLY for initial bootstrap; should be rotated to a secrets manager
    private_key     = Column(String(256), default='')
    dns             = Column(String(128), default='')
    mtu             = Column(Integer, default=1420)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VPNPeer(Base):
    """Registered WireGuard peer — persisted across restarts."""
    __tablename__ = 'vpn_peers'

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    name                 = Column(String(128), default='')          # friendly label
    public_key           = Column(String(256), unique=True, nullable=False)
    preshared_key        = Column(String(256), default='')
    allowed_ips          = Column(JSON, default=[])                 # List[str]
    endpoint             = Column(String(256), default='')          # "IP:PORT"
    persistent_keepalive = Column(Integer, default=25)
    enabled              = Column(Boolean, default=True)
    created_at           = Column(DateTime, default=datetime.utcnow)
    updated_at           = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "name":                  self.name,
            "public_key":            self.public_key,
            "allowed_ips":           self.allowed_ips or [],
            "endpoint":              self.endpoint,
            "persistent_keepalive":  self.persistent_keepalive,
            "enabled":               self.enabled,
            "created_at":            self.created_at.isoformat() if self.created_at else None,
        }


# ==================== UBA Models ====================



class UBAUserProfile(Base):
    """Per-user behavioral baseline for UBA engine."""
    __tablename__ = 'uba_user_profiles'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)   # FK → users.id (soft ref)
    peer_group = Column(String(64), nullable=True, index=True)  # e.g., "IT", "Finance"

    # ── Time baseline ──────────────────────────────────────────────────────────
    typical_hours_start = Column(Integer, default=8)   # learned work-start hour (0-23)
    typical_hours_end = Column(Integer, default=18)    # learned work-end hour  (0-23)
    hour_histogram = Column(JSON, default={})          # {0..23: event_count} for 3-sigma

    # ── Location baseline ──────────────────────────────────────────────────────
    known_ips = Column(JSON, default=[])               # up to 30 most recent IPs

    # ── Services baseline ──────────────────────────────────────────────────────
    known_services = Column(JSON, default=[])          # up to 100 services/ports

    # ── Volume baseline (EMA) ──────────────────────────────────────────────────
    avg_daily_bytes = Column(Float, default=0.0)
    daily_bytes_stddev = Column(Float, default=0.0)
    max_observed_bytes = Column(Float, default=0.0)

    # ── Session baseline ───────────────────────────────────────────────────────
    avg_session_duration = Column(Float, default=0.0)   # seconds
    avg_failed_logins = Column(Float, default=0.0)

    # ── Risk state ─────────────────────────────────────────────────────────────
    risk_score = Column(Float, default=0.0)            # 0–100 (EMA-smoothed)
    risk_level = Column(String(16), default='low')     # low|medium|high|critical

    # ── Learning state ─────────────────────────────────────────────────────────
    event_count = Column(Integer, default=0)
    baseline_locked = Column(Boolean, default=False)   # True = enough data to trust
    baseline_min_events = Column(Integer, default=50)

    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<UBAUserProfile {self.username} risk={self.risk_level}>"


class UBAEvent(Base):
    """Single observed behavior event with anomaly scoring."""
    __tablename__ = 'uba_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(64), nullable=True)
    target_service = Column(String(128), nullable=True)
    bytes_transferred = Column(Float, default=0.0)
    session_duration = Column(Float, default=0.0)    # seconds

    event_time = Column(DateTime, default=datetime.utcnow, index=True)

    # ── Analysis results ────────────────────────────────────────────────────────
    anomaly_score = Column(Float, default=0.0)        # 0.0–1.0
    risk_contribution = Column(Float, default=0.0)    # score delta applied to profile
    detectors_triggered = Column(JSON, default=[])    # e.g. ["time_detector", "location_detector"]
    action_taken = Column(String(16), default='allow')  # allow|alert|block
    details = Column(JSON, default={})

    # ── Context ─────────────────────────────────────────────────────────────────
    peer_group = Column(String(64), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'source_ip': self.source_ip,
            'target_service': self.target_service,
            'bytes_transferred': self.bytes_transferred,
            'event_time': self.event_time.isoformat() if self.event_time else None,
            'anomaly_score': self.anomaly_score,
            'risk_contribution': self.risk_contribution,
            'detectors_triggered': self.detectors_triggered or [],
            'action_taken': self.action_taken,
            'details': self.details or {},
        }

    def __repr__(self):
        return f"<UBAEvent {self.username} score={self.anomaly_score:.2f}>"


class UBAConfig(Base):
    """UBA module global configuration."""
    __tablename__ = 'uba_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=True)
    deception_enabled = Column(Boolean, default=True) # Patent PoC
    mode = Column(String(16), default='monitor')      # monitor|enforce|learning

    baseline_min_events = Column(Integer, default=50)
    max_known_ips = Column(Integer, default=30)
    max_known_services = Column(Integer, default=100)
    ema_alpha = Column(Float, default=0.1)            # EMA smoothing: 0=slow, 1=instant

    # Per-detector weights (JSON) — sum should be ≤ 1.0
    detector_weights = Column(JSON, default={
        "time": 0.20,
        "location": 0.30,
        "exfil": 0.25,
        "privilege": 0.15,
        "peer": 0.10,
    })
    # Risk thresholds
    thresholds = Column(JSON, default={
        "medium": 25.0,
        "high": 55.0,
        "critical": 80.0,
    })
    # Alert on risk level
    alert_on_risk_level = Column(String(16), default='high')

    # High-privilege services list for PrivilegeDetector
    privileged_services = Column(JSON, default=[
        "ssh", "rdp", "winrm", "admin", "root", "sudo",
        "3389", "22", "5985", "5986", "445",
    ])



class WAFTrainingData(Base):
    """
    WAF Self-Learning — stores every WAF decision for weekly model retraining.

    Enabled / disabled by WAFSettings.self_learning.enabled in waf.yaml.
    Max records enforced at write time by WAFSelfLearningLogger.
    """
    __tablename__ = 'waf_training_data'

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)

    # ── Request fingerprint ────────────────────────────────────────────
    src_ip        = Column(String(64), nullable=True, index=True)
    request_path  = Column(Text,       nullable=True)
    request_method= Column(String(16), nullable=True)
    payload       = Column(Text,       nullable=True)   # decoded text after Preprocessor

    # ── Extracted features (JSON snapshot) ───────────────────────────
    features      = Column(JSON, nullable=True)

    # ── AI decision ───────────────────────────────────────────────────
    risk_score    = Column(Float,      nullable=True)
    decision      = Column(String(32), nullable=True)   # ALLOW/CHALLENGE/SOFT_BLOCK/BLOCK
    nlp_score     = Column(Float,      nullable=True)
    bot_score     = Column(Float,      nullable=True)
    anomaly_score = Column(Float,      nullable=True)
    reputation    = Column(Float,      nullable=True)

    # ── Ground-truth label (set by admin feedback or automation) ─────
    # 0=benign  1=attack  2=suspicious  None=unreviewed
    label         = Column(Integer,    nullable=True, index=True)
    label_source  = Column(String(32), nullable=True)  # auto_block|admin_confirmed|fp_corrected

    # ── Versioning for retraining accountability ──────────────────────
    model_version = Column(String(64), nullable=True)

    def to_dict(self) -> dict:
        return {
            'id':             self.id,
            'timestamp':      self.timestamp.isoformat() if self.timestamp else None,
            'src_ip':         self.src_ip,
            'request_path':   self.request_path,
            'request_method': self.request_method,
            'risk_score':     self.risk_score,
            'decision':       self.decision,
            'label':          self.label,
            'label_source':   self.label_source,
            'model_version':  self.model_version,
        }


class DatabaseManager:

    """
    Database connection and session management

    Usage:
        db = DatabaseManager('sqlite:///CyberNexus.db')
        db.initialize()

        with db.session() as session:
            user = session.query(User).filter_by(username='admin').first()
    """

    def __init__(self, database_url: str = 'sqlite:///CyberNexus.db'):
        self.database_url = database_url
        self.engine = None
        self._session_factory = None
        logger.info(f"DatabaseManager initialized: {database_url.split('://')[0]}")

    def initialize(self):
        """Create engine, tables, and session factory"""
        self.engine = create_engine(
            self.database_url,
            echo=False,
            pool_pre_ping=True
        )

        # Create all tables
        Base.metadata.create_all(self.engine)

        self._session_factory = sessionmaker(bind=self.engine)

        # Wire the global get_db / SessionLocal helpers
        global _db_manager_ref
        _db_manager_ref = self

        logger.info("Database tables created")


    def session(self) -> Session:
        """Get a database session"""
        if not self._session_factory:
            self.initialize()
        return self._session_factory()

    def add_default_users(self, admin_hash: str, operator_hash: str):
        """Add default users if they don't exist"""
        with self.session() as session:
            if not session.query(User).filter_by(username='admin').first():
                session.add(User(
                    username='admin',
                    password_hash=admin_hash,
                    role='admin',
                    display_name='Administrator'
                ))
            if not session.query(User).filter_by(username='operator').first():
                session.add(User(
                    username='operator',
                    password_hash=operator_hash,
                    role='operator',
                    display_name='Operator'
                ))
            session.commit()
        logger.info("Default users ensured")

    def close(self):
        """Close database connection"""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connection closed")


# ── Model registration ────────────────────────────────────────────────────────
# Import module-specific models so they register in Base.metadata and are
# auto-created by DatabaseManager.initialize() → Base.metadata.create_all().
# Delayed import avoids circular dependencies.

def _register_module_models():
    """
    Auto-discover models/ in each module directory to ensure they are
    registered in Base.metadata for automatic table creation.
    """
    import os
    from pathlib import Path
    import importlib

    base_dir = Path(__file__).parent.parent.parent
    modules_dir = base_dir / "modules"

    if not modules_dir.exists():
        return

    for entry in os.listdir(modules_dir):
        mod_path = modules_dir / entry
        if mod_path.is_dir() and (mod_path / "models").exists():
            # Try to import modules.<entry>.models
            try:
                full_module_name = f"modules.{entry}.models"
                importlib.import_module(full_module_name)
                # logger.debug(f"  ✅ Registered models for module: {entry}")
            except Exception:
                # Some modules might have models dir but no __init__.py or other issues
                pass


_register_module_models()

