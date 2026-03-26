from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from api.rest.auth import make_permission_checker
from system.database.database import get_db
from modules.web_filter.models import WebFilterCategory, WebFilterDomain, WebFilterConfig

router = APIRouter(prefix="/api/v1/web_filter", tags=["web_filter"])
require_web_filter = make_permission_checker("web_filter")

# --- INITIALIZATION ---
def get_or_create_config(db: Session) -> WebFilterConfig:
    config = db.query(WebFilterConfig).first()
    if not config:
        config = WebFilterConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

# --- STATUS ---
@router.get("/status")
def get_status(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    config = get_or_create_config(db)
    domain_count = db.query(WebFilterDomain).count()
    category_count = db.query(WebFilterCategory).count()
    return {
        "status": "active" if config.enabled else "disabled", 
        "mode": config.mode,
        "module": "web_filter",
        "stats": {
            "domains": domain_count,
            "categories": category_count
        }
    }

# --- CONFIG ---
@router.get("/config")
def get_config(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    return get_or_create_config(db).to_dict()

@router.put("/config")
def update_config(payload: Dict[str, Any], db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    config = get_or_create_config(db)
    if "enabled" in payload:
        config.enabled = payload["enabled"]
    if "mode" in payload:
        config.mode = payload["mode"]
    if "safe_search_enabled" in payload:
        config.safe_search_enabled = payload["safe_search_enabled"]
    if "default_action" in payload:
        config.default_action = payload["default_action"]
        
    db.commit()
    db.refresh(config)
    return config.to_dict()

# --- CATEGORIES ---
@router.get("/categories")
def list_categories(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    categories = db.query(WebFilterCategory).all()
    return [c.to_dict() for c in categories]

@router.post("/categories")
def create_category(payload: Dict[str, Any], db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    name = payload.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
        
    if db.query(WebFilterCategory).filter_by(name=name).first():
        raise HTTPException(status_code=400, detail="Category already exists")
        
    category = WebFilterCategory(
        name=name,
        description=payload.get("description", ""),
        action=payload.get("action", "BLOCK"),
        risk_score=payload.get("risk_score", 50),
        is_custom=True
    )
    db.add(category)
    db.commit()
    db.refresh(category)
    return category.to_dict()

@router.delete("/categories/{cat_id}")
def delete_category(cat_id: int, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    cat = db.query(WebFilterCategory).filter(WebFilterCategory.id == cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
        
    db.delete(cat)
    db.commit()
    return {"message": "Category deleted"}

# --- DOMAINS ---
@router.get("/domains")
def list_domains(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domains = db.query(WebFilterDomain).all()
    return [d.to_dict() for d in domains]

@router.post("/domains")
def add_domain(payload: Dict[str, Any], db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domain_pattern = payload.get("domain_pattern")
    if not domain_pattern:
        raise HTTPException(status_code=400, detail="domain_pattern is required")
        
    if db.query(WebFilterDomain).filter_by(domain_pattern=domain_pattern).first():
        raise HTTPException(status_code=400, detail="Domain pattern already exists")
        
    domain = WebFilterDomain(
        domain_pattern=domain_pattern,
        category_name=payload.get("category_name"),
        action=payload.get("action", "BLOCK")
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain.to_dict()

@router.delete("/domains/{domain_id}")
def delete_domain(domain_id: int, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domain = db.query(WebFilterDomain).filter(WebFilterDomain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    db.delete(domain)
    db.commit()
    return {"message": "Domain deleted"}
