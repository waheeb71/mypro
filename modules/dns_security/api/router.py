"""
Enterprise NGFW v2.0 — DNS Security API Router
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, TypedDict
from pydantic import BaseModel, Field
from datetime import datetime

from sqlalchemy.orm import Session

from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.dns_security.models import (
    DNSFilterRule  as DBFilterRule,
    DNSModuleConfig as DBModuleConfig,
    FilterType,
    ActionEnum,
)

router = APIRouter(prefix="/api/v1/dns_security", tags=["dns_security"])

# Admins pass automatically; others need DB permission: resource="dns"
require_dns = make_permission_checker("dns")


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ──────────────────────────────────────────────────────────────────────────────

class DNSFilterRuleBase(BaseModel):
    domain_pattern: str       = Field(..., description="Domain or pattern (e.g. example.com, *.tk, ^bad.*\\.io$)")
    filter_type:    FilterType = FilterType.EXACT
    action:         ActionEnum = ActionEnum.BLOCK
    description:    Optional[str] = None
    enabled:        bool = True


class DNSFilterRuleCreate(DNSFilterRuleBase):
    pass


class DNSFilterRuleUpdate(BaseModel):
    domain_pattern: Optional[str]        = None
    filter_type:    Optional[FilterType] = None
    action:         Optional[ActionEnum] = None
    description:    Optional[str]        = None
    enabled:        Optional[bool]       = None


class DNSFilterRuleResponse(DNSFilterRuleBase):
    id:             int
    blocked_count:  int
    last_triggered: Optional[datetime]
    created_at:     datetime
    updated_at:     datetime

    class Config:
        orm_mode = True


class DNSModuleConfigSchema(BaseModel):
    enable_dga_detection:       bool  = True
    enable_tunneling_detection: bool  = True
    enable_threat_intel:        bool  = True
    enable_rate_limiting:       bool  = True
    enable_tld_blocking:        bool  = True
    dga_entropy_threshold:      float = 3.8
    tunneling_query_threshold:  int   = 50
    rate_limit_per_minute:      int   = 100
    suspicious_tlds:            str   = ".tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion"
    is_active:                  bool  = True

    class Config:
        orm_mode = True


class TopBlockedEntry(TypedDict):
    domain_pattern: str
    action:         str
    blocked_count:  int
    last_triggered: Optional[str]


class DNSStatsResponse(BaseModel):
    total_rules:    int
    active_rules:   int
    blocked_count:  int
    top_blocked:    List[TopBlockedEntry]


# ──────────────────────────────────────────────────────────────────────────────
# Status & Config
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(token: dict = Depends(require_dns)):
    """Return module health status."""
    return {
        "status":  "active",
        "module":  "dns_security",
        "engines": ["dga", "tunneling", "rate_limit", "tld_filter", "threat_intel"],
        "version": "2.0",
    }


@router.get("/config", response_model=DNSModuleConfigSchema)
async def get_config(
    db:    Session = Depends(get_db),
    token: dict    = Depends(require_dns),
):
    """Get DNS security module configuration."""
    config = db.query(DBModuleConfig).first()
    if not config:
        config = DBModuleConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


@router.put("/config", response_model=DNSModuleConfigSchema)
async def update_config(
    new_config: DNSModuleConfigSchema,
    db:         Session = Depends(get_db),
    token:      dict    = Depends(require_admin),
):
    """Update DNS security module configuration (admin only)."""
    config = db.query(DBModuleConfig).first()
    if not config:
        config = DBModuleConfig()
        db.add(config)

    for key, value in new_config.dict().items():
        setattr(config, key, value)

    db.commit()
    db.refresh(config)
    return config


# ──────────────────────────────────────────────────────────────────────────────
# Statistics
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=DNSStatsResponse)
async def get_stats(
    db:    Session = Depends(get_db),
    token: dict    = Depends(require_dns),
):
    """Return aggregate statistics for the DNS security module."""
    all_rules    = db.query(DBFilterRule).all()
    active_rules = [r for r in all_rules if r.enabled]
    total_blocked = sum(r.blocked_count or 0 for r in all_rules)

    raw_list: List[TopBlockedEntry] = [
        {
            "domain_pattern": r.domain_pattern,
            "action":         r.action.value if hasattr(r.action, 'value') else str(r.action),
            "blocked_count":  int(r.blocked_count or 0),
            "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None,
        }
        for r in all_rules
    ]
    sorted_list: List[TopBlockedEntry] = sorted(raw_list, key=lambda x: x["blocked_count"], reverse=True)
    top_blocked: List[TopBlockedEntry] = list(sorted_list[:10])

    return DNSStatsResponse(
        total_rules=len(all_rules),
        active_rules=len(active_rules),
        blocked_count=total_blocked,
        top_blocked=top_blocked,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Domain Filter Rules (CRUD)
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/rules", response_model=List[DNSFilterRuleResponse])
async def list_rules(
    skip:  int     = 0,
    limit: int     = 100,
    db:    Session = Depends(get_db),
    token: dict    = Depends(require_dns),
):
    """List all domain filter rules."""
    return db.query(DBFilterRule).offset(skip).limit(limit).all()


@router.post(
    "/rules",
    response_model=DNSFilterRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule(
    rule:  DNSFilterRuleCreate,
    db:    Session = Depends(get_db),
    token: dict    = Depends(require_admin),
):
    """Create a new domain filter rule (admin only)."""
    existing = (
        db.query(DBFilterRule)
        .filter(DBFilterRule.domain_pattern == rule.domain_pattern)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Domain pattern already exists in rules.",
        )

    db_rule = DBFilterRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.put("/rules/{rule_id}", response_model=DNSFilterRuleResponse)
async def update_rule(
    rule_id: int,
    updates: DNSFilterRuleUpdate,
    db:      Session = Depends(get_db),
    token:   dict    = Depends(require_admin),
):
    """Update an existing domain filter rule (admin only)."""
    db_rule = db.query(DBFilterRule).filter(DBFilterRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found.")

    for key, value in updates.dict(exclude_unset=True).items():
        setattr(db_rule, key, value)

    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    db:      Session = Depends(get_db),
    token:   dict    = Depends(require_admin),
):
    """Delete a domain filter rule (admin only)."""
    db_rule = db.query(DBFilterRule).filter(DBFilterRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found.")

    db.delete(db_rule)
    db.commit()
    return None
