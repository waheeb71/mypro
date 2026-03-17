from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy.orm import Session
from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.dlp.models import DLPRule as DBDLPRule, DLPConfig as DBDLPConfig

router = APIRouter(prefix="/api/v1/dlp", tags=["dlp"])

# Admins pass automatically. Others need DB rule: resource="dlp"
require_dlp = make_permission_checker("dlp")

# --- Pydantic Schemas ---
class DLPRuleBase(BaseModel):
    name: str = Field(..., max_length=50)
    pattern: str = Field(..., description="Regex pattern for matching")
    severity: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: Optional[str] = None
    enabled: bool = True

class DLPRuleCreate(DLPRuleBase):
    pass

class DLPRuleResponse(DLPRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        orm_mode = True

class DLPConfigSchema(BaseModel):
    is_active: bool = True
    block_on_match: bool = True
    class Config:
        orm_mode = True

# --- API Endpoints: System Status & Config ---

@router.get("/status")
async def get_status(token: dict = Depends(require_dlp)):
    return {"status": "active", "module": "dlp"}

@router.get("/config", response_model=DLPConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_dlp)):
    """Get DLP module configuration"""
    config = db.query(DBDLPConfig).first()
    if not config:
        # Create default if missing
        config = DBDLPConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/config", response_model=DLPConfigSchema)
async def update_config(
    new_config: DLPConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Update DLP module configuration"""
    config = db.query(DBDLPConfig).first()
    if not config:
        config = DBDLPConfig()
        db.add(config)
        
    for key, value in new_config.dict().items():
        setattr(config, key, value)
        
    db.commit()
    db.refresh(config)
    return config

# --- API Endpoints: DLP Rules ---

@router.get("/rules", response_model=List[DLPRuleResponse])
async def list_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_dlp)):
    return db.query(DBDLPRule).offset(skip).limit(limit).all()

@router.post("/rules", response_model=DLPRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: DLPRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Create a new custom DLP rule"""
    existing = db.query(DBDLPRule).filter(DBDLPRule.name == rule.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")
        
    db_rule = DBDLPRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    """Delete a custom DLP rule"""
    db_rule = db.query(DBDLPRule).filter(DBDLPRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    db.delete(db_rule)
    db.commit()
    return None
