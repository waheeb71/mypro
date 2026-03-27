"""
Email Security — Database Models

EmailLog: persists every inspection result for statistics and audit.
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from datetime import datetime
from system.database.database import Base


class EmailLog(Base):
    """
    Persisted record of every email inspection result.
    Written by EmailInspectorPlugin after each decision.

    Used by:
      - GET /api/v1/email_security/logs   → recent events feed
      - GET /api/v1/email_security/stats  → aggregate counters
    """
    __tablename__ = 'email_logs'

    id               = Column(Integer, primary_key=True, index=True)

    # Source / destination
    src_ip           = Column(String(45),  index=True, nullable=True)
    dst_port         = Column(Integer,     nullable=True)
    sender           = Column(String(255), index=True, nullable=True)
    subject          = Column(String(512), nullable=True)

    # Risk scores (0.0 – 1.0)
    risk_score       = Column(Float, default=0.0)
    phishing_score   = Column(Float, default=0.0)
    spam_score       = Column(Float, default=0.0)
    url_score        = Column(Float, default=0.0)
    attachment_score = Column(Float, default=0.0)
    sender_score     = Column(Float, default=0.0)

    # Policy decision
    decision         = Column(String(16), index=True, default='allow')   # allow | quarantine | block

    # Detection flags
    is_phishing      = Column(Boolean, default=False)
    is_spam          = Column(Boolean, default=False)
    has_malicious_url = Column(Boolean, default=False)
    has_bad_attachment = Column(Boolean, default=False)

    # Matched indicators
    matched_keywords = Column(JSON,    nullable=True)    # list[str]
    flagged_urls     = Column(JSON,    nullable=True)    # list[str]
    brand_spoof      = Column(String(64), nullable=True)

    # Raw finding categories
    finding_categories = Column(JSON, nullable=True)    # list[str]

    # Timing
    latency_ms       = Column(Float,    nullable=True)
    inspected_at     = Column(DateTime, default=datetime.utcnow, index=True)
