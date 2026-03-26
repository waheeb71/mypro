"""
Enterprise CyberNexus — QoS REST API
================================
Prefix: /api/v1/qos

Endpoints:
  GET  /status   — Module status + live bucket count
  GET  /config   — Read QoS configuration from DB
  PUT  /config   — Update QoS config (DB + live memory)
  GET  /stats    — Per-IP bucket statistics (live)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional
import logging

from system.database.database import get_db, QoSConfig as DBConfig
from api.rest.auth import require_admin, make_permission_checker

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/qos", tags=["QoS"])

# Non-admins need a DB rule with resource="qos"
require_qos = make_permission_checker("qos")


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class QoSConfigRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable QoS shaping")
    default_user_rate_bytes: int = Field(
        ..., gt=0, description="Default rate limit per user in bytes/sec"
    )
    default_user_burst_bytes: int = Field(
        ..., gt=0, description="Default burst limit per user in bytes"
    )

    class Config:
        from_attributes = True   # Pydantic v2 compat (was orm_mode)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_or_create_config(db: Session) -> DBConfig:
    cfg = db.query(DBConfig).first()
    if not cfg:
        cfg = DBConfig()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _cfg_to_dict(cfg: DBConfig) -> dict:
    return {
        "enabled":                cfg.enabled,
        "default_user_rate_bytes": cfg.default_user_rate_bytes,
        "default_user_burst_bytes": cfg.default_user_burst_bytes,
        "global_rate_bytes":      cfg.global_rate_bytes,
        "traffic_classes":        cfg.traffic_classes or [],
        "updated_at":             cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


def _get_qos_manager(request: Request):
    CyberNexus = getattr(request.app.state, 'CyberNexus_app', None)
    if CyberNexus and hasattr(CyberNexus, 'qos_manager'):
        return CyberNexus.qos_manager
    return None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(
    request: Request,
    db: Session = Depends(get_db),
    token: dict = Depends(require_qos),
):
    """Return live QoS module status."""
    cfg = _get_or_create_config(db)
    qos_mgr = _get_qos_manager(request)
    active_buckets = len(qos_mgr.ip_buckets) if qos_mgr else 0

    return {
        "module":         "qos",
        "status":         "active" if cfg.enabled else "disabled",
        "enabled":        cfg.enabled,
        "rate_limit_bps": cfg.default_user_rate_bytes * 8,   # bits/sec
        "burst_bytes":    cfg.default_user_burst_bytes,
        "active_buckets": active_buckets,
    }


@router.get("/config")
async def get_config(
    db: Session = Depends(get_db),
    token: dict = Depends(require_qos),
):
    """Get QoS configuration from DB."""
    cfg = _get_or_create_config(db)
    return _cfg_to_dict(cfg)


@router.put("/config", status_code=status.HTTP_200_OK)
async def update_config(
    request: Request,
    new_cfg: QoSConfigRequest,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin),
):
    """Update QoS config in DB and hot-reload live manager."""
    cfg = _get_or_create_config(db)

    cfg.enabled = new_cfg.enabled
    cfg.default_user_rate_bytes  = new_cfg.default_user_rate_bytes
    cfg.default_user_burst_bytes = new_cfg.default_user_burst_bytes

    db.commit()
    db.refresh(cfg)

    # Hot-reload live QoSManager if running
    qos_mgr = _get_qos_manager(request)
    if qos_mgr:
        qos_mgr.update_limits(
            enabled=cfg.enabled,
            rate_bytes=cfg.default_user_rate_bytes,
            burst_bytes=cfg.default_user_burst_bytes,
        )
        logger.info("Live QoS limits updated in memory")

    return {
        "status":  "success",
        "message": "QoS limits updated",
        "config":  _cfg_to_dict(cfg),
    }


@router.get("/stats")
async def get_stats(
    request: Request,
    token: dict = Depends(require_qos),
):
    """Return live per-IP token-bucket statistics."""
    qos_mgr = _get_qos_manager(request)
    if not qos_mgr:
        return {"active_buckets": 0, "buckets": []}

    buckets = []
    for ip, bucket in qos_mgr.ip_buckets.items():
        buckets.append({
            "ip":               ip,
            "tokens_remaining": round(bucket.tokens, 0),
            "capacity":         bucket.capacity,
            "fill_rate_bps":    bucket.fill_rate * 8,
            "utilization_pct":  round((1 - bucket.tokens / max(bucket.capacity, 1)) * 100, 1),
        })

    return {
        "active_buckets": len(buckets),
        "buckets":        sorted(buckets, key=lambda x: x["utilization_pct"], reverse=True),
    }
