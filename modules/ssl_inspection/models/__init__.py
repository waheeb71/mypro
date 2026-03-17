from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from datetime import datetime
from system.database.database import Base

class SSLPolicy(Base):
    """Database model for SSL Inspection policies (Decryption / Bypass / Block)"""
    __tablename__ = 'ssl_policies'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(255))
    action = Column(String(20), nullable=False) # DECRYPT, BYPASS, BLOCK
    
    # Matching criteria (Can be JSON holding specific domains, categories, IPs)
    target_domains = Column(Text, default="*") # Comma separated or *
    source_ips = Column(Text, default="*")
    
    # Options
    log_traffic = Column(Boolean, default=True)
    check_revocation = Column(Boolean, default=True)
    block_invalid_certs = Column(Boolean, default=True)
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SSLCertificateConfig(Base):
    """Stores generated or imported CA certificates for inspection"""
    __tablename__ = 'ssl_certificates'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    cert_type = Column(String(20), nullable=False) # ROOT_CA, INTERMEDIATE_CA, SERVER
    
    # PEM encoded active content
    public_cert = Column(Text, nullable=False)
    private_key = Column(Text) # Might be encrypted or left out if just trusting
    
    expiry_date = Column(DateTime)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
