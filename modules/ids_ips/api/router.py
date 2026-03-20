from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy.orm import Session
from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.ids_ips.models import IPSSignature as DBSignature, IPSConfig as DBConfig

router = APIRouter(prefix="/api/v1/ids_ips", tags=["ids_ips"])

require_ids = make_permission_checker("ids_ips")

# --- Pydantic Schemas ---
class SignatureBase(BaseModel):
    sid: int = Field(..., description="Snort Rule ID")
    raw_rule: str = Field(..., description="Raw Snort Rule string")
    enabled: bool = True

class SignatureCreate(SignatureBase):
    pass

class SignatureResponse(SignatureBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        orm_mode = True

class ConfigSchema(BaseModel):
    is_active: bool = True
    mode: str = Field("blocking", description="monitoring or blocking")
    enable_l3_anomaly: bool = True
    enable_l7_dpi: bool = True
    deception_enabled: bool = True
    anomaly_threshold: float = 0.5
    class Config:
        orm_mode = True

# --- API Endpoints: System Status & Config ---
@router.get("/status")
async def get_status(token: dict = Depends(require_ids)):
    return {"status": "active", "module": "ids_ips"}

@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_ids)):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/config", response_model=ConfigSchema)
async def update_config(
    new_config: ConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)
        
    for key, value in new_config.dict().items():
        setattr(config, key, value)
        
    db.commit()
    db.refresh(config)
    return config

# --- API Endpoints: Signatures ---
@router.get("/signatures", response_model=List[SignatureResponse])
async def list_signatures(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_ids)):
    return db.query(DBSignature).offset(skip).limit(limit).all()

@router.post("/signatures", response_model=SignatureResponse, status_code=status.HTTP_201_CREATED)
async def create_signature(
    signature: SignatureCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    # Check if SID exists
    existing = db.query(DBSignature).filter(DBSignature.sid == signature.sid).first()
    if existing:
        raise HTTPException(status_code=400, detail="SID already exists")
        
    db_sig = DBSignature(**signature.dict())
    db.add(db_sig)
    db.commit()
    db.refresh(db_sig)
    return db_sig

@router.delete("/signatures/{sig_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_signature(sig_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_sig = db.query(DBSignature).filter(DBSignature.id == sig_id).first()
    if not db_sig:
        raise HTTPException(status_code=404, detail="Signature not found")
        
    db.delete(db_sig)
    db.commit()
    return None
