from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from datetime import datetime
from system.database.database import Base

class IPSConfig(Base):
    """
    Dynamic configuration for the IDS/IPS module.
    """
    __tablename__ = 'ips_config'
    id = Column(Integer, primary_key=True, index=True)
    
    is_active = Column(Boolean, default=True)
    mode = Column(String(20), default="blocking", comment="monitoring or blocking")
    
    # ML Engine Toggles
    enable_l3_anomaly = Column(Boolean, default=True, comment="Enable L3 Anomaly Detection (IsolationForest)")
    enable_l7_dpi = Column(Boolean, default=True, comment="Enable L7 DPI Classification (XGBoost/RF)")
    
    # Deception Toggle
    deception_enabled = Column(Boolean, default=True, comment="Dynamically deploy network tarpits/banners instead of dropping packets")
    
    # ML Threshold
    anomaly_threshold = Column(Float, default=0.5, comment="Threshold above which to block anomalies")
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class IPSSignature(Base):
    """
    Database model for dynamic Snort-like rules.
    """
    __tablename__ = 'ips_signatures'
    
    id = Column(Integer, primary_key=True, index=True)
    sid = Column(Integer, index=True, unique=True, comment="Snort Rule ID")
    
    # Example format: alert tcp any any -> any any (msg:"Test"; content:"foo"; sid:1;)
    raw_rule = Column(String(1024), nullable=False)
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
