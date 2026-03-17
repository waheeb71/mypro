from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Enum as SQLEnum
import enum
from datetime import datetime
from system.database.database import Base

class FilterType(str, enum.Enum):
    WILDCARD = "WILDCARD"
    EXACT = "EXACT"
    REGEX = "REGEX"

class ActionEnum(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

class DNSFilterRule(Base):
    __tablename__ = 'dns_filter_rules'
    id = Column(Integer, primary_key=True, index=True)
    domain_pattern = Column(String(255), unique=True, nullable=False, index=True)
    filter_type = Column(SQLEnum(FilterType), default=FilterType.EXACT)
    action = Column(SQLEnum(ActionEnum), default=ActionEnum.BLOCK)
    description = Column(String(255))
    enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DNSModuleConfig(Base):
    __tablename__ = 'dns_module_config'
    id = Column(Integer, primary_key=True, index=True)
    
    # Engine toggles
    enable_dga_detection = Column(Boolean, default=True)
    enable_tunneling_detection = Column(Boolean, default=True)
    enable_threat_intel = Column(Boolean, default=True)
    
    # Engine parameters
    dga_entropy_threshold = Column(Float, default=3.8)
    tunneling_query_threshold = Column(Integer, default=50)
    rate_limit_per_minute = Column(Integer, default=100)
    
    # General API status (enabled/disabled)
    is_active = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
