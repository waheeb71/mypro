from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from system.database.database import Base

class WebFilterCategory(Base):
    """Categories for Web Filtering (e.g., malware, adult, social)"""
    __tablename__ = 'web_filter_categories'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(256), nullable=True)
    action = Column(String(16), default="BLOCK") # ALLOW, BLOCK, WARN
    risk_score = Column(Integer, default=50) # 0-100
    is_custom = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "risk_score": self.risk_score,
            "is_custom": self.is_custom,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class WebFilterDomain(Base):
    """Custom Domain Overrides (Whitelist/Blacklist)"""
    __tablename__ = 'web_filter_domains'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_pattern = Column(String(256), unique=True, nullable=False, index=True) 
    category_name = Column(String(64), nullable=True) 
    action = Column(String(16), default="BLOCK") # ALLOW, BLOCK
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "domain_pattern": self.domain_pattern,
            "category_name": self.category_name,
            "action": self.action,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class WebFilterConfig(Base):
    """Global configuration for the Web Filter"""
    __tablename__ = 'web_filter_config'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=True)
    mode = Column(String(32), default='enforce') # monitor | enforce
    safe_search_enabled = Column(Boolean, default=True)
    default_action = Column(String(16), default='ALLOW')
    
    def to_dict(self):
        return {
            "id": self.id,
            "enabled": self.enabled,
            "mode": self.mode,
            "safe_search_enabled": self.safe_search_enabled,
            "default_action": self.default_action
        }
