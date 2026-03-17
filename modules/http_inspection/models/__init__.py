from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from system.database.database import Base
class HTTPSuspiciousPattern(Base):
    """
    Model for holding suspicious regex patterns for URL, Headers, and Body inspection.
    """
    __tablename__ = 'http_suspicious_patterns'
    id = Column(Integer, primary_key=True, index=True)
    
    # Target can be: 'url', 'header', 'body'
    target = Column(String(20), nullable=False, index=True) 

    # If target is 'header', this defines which header to look for (e.g., 'User-Agent')
    # If target is not 'header', this can be null or empty
    target_key = Column(String(50), nullable=True)
    
    pattern = Column(String(255), nullable=False)
    description = Column(String(255))
    severity = Column(String(20), default="MEDIUM", comment="HIGH, MEDIUM, LOW")
    enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class HTTPInspectionConfig(Base):
    """
    Dynamic configuration for the HTTP Inspection module.
    """
    __tablename__ = 'http_inspection_config'
    id = Column(Integer, primary_key=True, index=True)
    
    is_active = Column(Boolean, default=True)
    block_dangerous_methods = Column(Boolean, default=True)
    scan_headers = Column(Boolean, default=True)
    scan_body = Column(Boolean, default=True)
    max_upload_size_mb = Column(Integer, default=100)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
