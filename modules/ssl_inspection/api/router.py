from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime

from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.ssl_inspection.models import SSLPolicy, SSLCertificateConfig

router = APIRouter(
    prefix="/api/v1/ssl-inspection",
    tags=["ssl_inspection"],
    responses={404: {"description": "Not found"}},
)

# Admins always pass. Non-admins need a DB rule with resource="ssl_inspection".
require_ssl = make_permission_checker("ssl_inspection")

# --- Pydantic Schemas ---
class SSLPolicyCreate(BaseModel):
    name: str
    description: str = ""
    action: str  # DECRYPT, BYPASS, BLOCK
    target_domains: str = "*"
    source_ips: str = "*"
    log_traffic: bool = True
    check_revocation: bool = True
    block_invalid_certs: bool = True
    enabled: bool = True

class SSLPolicyResponse(SSLPolicyCreate):
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

class CertUpload(BaseModel):
    name: str
    cert_type: str
    public_cert: str
    private_key: str = None
    expiry_date: datetime = None
    is_active: bool = False

# --- Endpoints ---

@router.get("/policies", response_model=List[SSLPolicyResponse])
def list_ssl_policies(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                      token: dict = Depends(require_ssl)):
    """List all SSL Inspection Policies"""
    policies = db.query(SSLPolicy).offset(skip).limit(limit).all()
    return policies

@router.post("/policies", response_model=SSLPolicyResponse)
def create_ssl_policy(policy: SSLPolicyCreate, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    """Create a new SSL Inspection Policy"""
    existing = db.query(SSLPolicy).filter(SSLPolicy.name == policy.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Policy name already exists")
        
    db_policy = SSLPolicy(**policy.dict())
    db.add(db_policy)
    db.commit()
    db.refresh(db_policy)
    return db_policy

@router.put("/policies/{policy_id}", response_model=SSLPolicyResponse)
def update_ssl_policy(policy_id: int, policy: SSLPolicyCreate, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_policy = db.query(SSLPolicy).filter(SSLPolicy.id == policy_id).first()
    if not db_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    update_data = policy.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_policy, key, value)
        
    db.commit()
    db.refresh(db_policy)
    return db_policy

@router.delete("/policies/{policy_id}")
def delete_ssl_policy(policy_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_policy = db.query(SSLPolicy).filter(SSLPolicy.id == policy_id).first()
    if not db_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    db.delete(db_policy)
    db.commit()
    return {"status": "success", "message": "Policy deleted"}

@router.post("/certificates/upload")
def upload_certificate(cert: CertUpload, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    """Upload a new Root CA or Server Certificate for inspection"""
    db_cert = SSLCertificateConfig(**cert.dict())
    db.add(db_cert)
    db.commit()
    db.refresh(db_cert)
    return {"status": "success", "id": db_cert.id}

@router.get("/certificates")
def list_certificates(db: Session = Depends(get_db), token: dict = Depends(require_ssl)):
    """List configured certificates (omits private keys for security)"""
    certs = db.query(SSLCertificateConfig).all()
    return [
        {
            "id": c.id, 
            "name": c.name, 
            "type": c.cert_type, 
            "is_active": c.is_active,
            "expiry": c.expiry_date
        } 
        for c in certs
    ]
