from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum as SQLEnum
import enum
from datetime import datetime
from system.database.database import Base

class ActionEnum(str, enum.Enum):
    ALLOW = "ALLOW"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"

class FirewallRule(Base):
    __tablename__ = 'firewall_rules'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    
    # Layer 3/4
    source_ip = Column(String(100), default="any") # any, specific IP, or CIDR
    destination_ip = Column(String(100), default="any")
    source_port = Column(String(50), default="any")
    destination_port = Column(String(50), default="any")
    protocol = Column(String(20), default="any") # tcp, udp, icmp, any
    
    # Next-Gen Fields
    zone_src = Column(String(50), default="any")
    zone_dst = Column(String(50), default="any")
    app_category = Column(String(100), default="any")
    file_type = Column(String(100), default="any")
    schedule = Column(String(100), default="always")

    action = Column(SQLEnum(ActionEnum), default=ActionEnum.ALLOW)
    log_traffic = Column(Boolean, default=True)
    
    priority = Column(Integer, default=100)
    enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
