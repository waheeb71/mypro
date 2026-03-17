from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from system.database.database import Base


class ProxyConfig(Base):
    """
    Dynamic configuration for the Proxy Engine module.
    """
    __tablename__ = 'proxy_config'

    id = Column(Integer, primary_key=True, index=True)

    is_active = Column(Boolean, default=True)
    
    # Proxy operational mode: 'transparent_proxy', 'reverse_proxy', 'forward_proxy'
    mode = Column(String(50), default="transparent_proxy")
    
    # Listening ports
    listen_port = Column(Integer, default=8443)
    http_port = Column(Integer, default=8080)
    
    # Performance Limits
    max_connections = Column(Integer, default=10000)
    buffer_size = Column(Integer, default=65536)
    
    # Security options
    strict_cert_validation = Column(Boolean, default=True)

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
