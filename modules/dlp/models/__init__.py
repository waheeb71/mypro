from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from system.database.database import Base

class DLPRule(Base):
    __tablename__ = 'dlp_rules'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False, unique=True)
    pattern = Column(String(255), nullable=False, comment="Regex pattern for matching")
    severity = Column(String(20), default="MEDIUM", comment="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description = Column(String(255))
    enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DLPConfig(Base):
    __tablename__ = 'dlp_config'
    id = Column(Integer, primary_key=True, index=True)
    
    is_active = Column(Boolean, default=True)
    block_on_match = Column(Boolean, default=True, comment="If true, traffic matching rules will be dropped")
    deception_enabled = Column(Boolean, default=True, comment="If true, generates Data Watermark Traps upon detecting exfiltration attempts")
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
