from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy.orm import Session
from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.dns_security.models import DNSFilterRule as DBFilterRule, DNSModuleConfig as DBModuleConfig, FilterType, ActionEnum

router = APIRouter(prefix="/api/v1/dns_security", tags=["dns_security"])

# Admins pass automatically. Others need DB rule: resource="dns"
require_dns = make_permission_checker("dns")

# --- Pydantic Schemas ---
class DNSFilterRuleBase(BaseModel):
    domain_pattern: str = Field(..., description="Domain or pattern (e.g., example.com, *.tk)")
    filter_type: FilterType = FilterType.EXACT
    action: ActionEnum = ActionEnum.BLOCK
    description: Optional[str] = None
    enabled: bool = True

class DNSFilterRuleCreate(DNSFilterRuleBase):
    pass

class DNSFilterRuleResponse(DNSFilterRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        orm_mode = True

class DNSModuleConfigSchema(BaseModel):
    enable_dga_detection: bool = True
    enable_tunneling_detection: bool = True
    enable_threat_intel: bool = True
    dga_entropy_threshold: float = 3.8
    tunneling_query_threshold: int = 50
    rate_limit_per_minute: int = 100
    is_active: bool = True
    class Config:
        orm_mode = True

# --- API Endpoints: System Status & Config ---

@router.get("/status")
async def get_status(token: dict = Depends(require_dns)):
    return {"status": "active", "module": "dns_security", "engines": ["dga", "tunneling", "rate_limit", "tld_filter"]}

@router.get("/config", response_model=DNSModuleConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_dns)):
    """Get DNS security module configuration"""
    config = db.query(DBModuleConfig).first()
    if not config:
        # Create default if missing
        config = DBModuleConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/config", response_model=DNSModuleConfigSchema)
async def update_config(
    new_config: DNSModuleConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Update DNS security module configuration"""
    config = db.query(DBModuleConfig).first()
    if not config:
        config = DBModuleConfig()
        db.add(config)
        
    for key, value in new_config.dict().items():
        setattr(config, key, value)
        
    db.commit()
    db.refresh(config)
    return config

# --- API Endpoints: Domain Filter Rules (Blacklist/Whitelist) ---

@router.get("/rules", response_model=List[DNSFilterRuleResponse])
async def list_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_dns)):
    return db.query(DBFilterRule).offset(skip).limit(limit).all()

@router.post("/rules", response_model=DNSFilterRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: DNSFilterRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Create a new domain filter rule (Whitelist/Blacklist)"""
    existing = db.query(DBFilterRule).filter(DBFilterRule.domain_pattern == rule.domain_pattern).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain pattern already exists in rules")
        
    db_rule = DBFilterRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    """Delete a domain filter rule"""
    db_rule = db.query(DBFilterRule).filter(DBFilterRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    db.delete(db_rule)
    db.commit()
    return None
