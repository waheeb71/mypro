from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy.orm import Session
from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.http_inspection.models import HTTPSuspiciousPattern as DBPattern, HTTPInspectionConfig as DBConfig

router = APIRouter(prefix="/api/v1/http_inspection", tags=["http_inspection"])

require_http = make_permission_checker("http_inspection")

# --- Pydantic Schemas ---
class PatternBase(BaseModel):
    target: str = Field(..., description="'url', 'header', or 'body'")
    target_key: Optional[str] = Field(None, description="Specific header name if target is 'header'")
    pattern: str = Field(..., description="Regex pattern")
    description: Optional[str] = None
    severity: str = Field("MEDIUM", description="HIGH, MEDIUM, LOW")
    enabled: bool = True

class PatternCreate(PatternBase):
    pass

class PatternResponse(PatternBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        orm_mode = True

class ConfigSchema(BaseModel):
    is_active: bool = True
    block_dangerous_methods: bool = True
    scan_headers: bool = True
    scan_body: bool = True
    max_upload_size_mb: int = 100
    class Config:
        orm_mode = True

# --- API Endpoints: System Status & Config ---
@router.get("/status")
async def get_status(token: dict = Depends(require_http)):
    return {"status": "active", "module": "http_inspection"}

@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_http)):
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

# --- API Endpoints: Patterns ---
@router.get("/patterns", response_model=List[PatternResponse])
async def list_patterns(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_http)):
    return db.query(DBPattern).offset(skip).limit(limit).all()

@router.post("/patterns", response_model=PatternResponse, status_code=status.HTTP_201_CREATED)
async def create_pattern(
    pattern: PatternCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_pattern = DBPattern(**pattern.dict())
    db.add(db_pattern)
    db.commit()
    db.refresh(db_pattern)
    return db_pattern

@router.delete("/patterns/{pattern_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pattern(pattern_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_pattern = db.query(DBPattern).filter(DBPattern.id == pattern_id).first()
    if not db_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
        
    db.delete(db_pattern)
    db.commit()
    return None
