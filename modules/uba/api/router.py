"""
Enterprise NGFW — UBA REST API
================================
Prefix: /api/v1/uba

Endpoints:
  GET    /status                        — Module status + live stats
  GET    /config                        — Read UBA config
  PUT    /config                        — Update UBA thresholds / mode
  GET    /users                         — List all user profiles
  GET    /users/{username}              — Single user profile + risk
  DELETE /users/{username}/reset        — Clear user baseline
  GET    /users/{username}/events       — Events for one user
  GET    /events                        — All events (paginated, filterable)
  GET    /alerts                        — High/critical events only
  POST   /events                        — Manually submit an event for analysis
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, Field

from api.rest.auth import require_admin, make_permission_checker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/uba", tags=["UBA"])

require_uba = make_permission_checker("uba")


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class UBAConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = Field(None, description="monitor|enforce|learning")
    baseline_min_events: Optional[int] = None
    ema_alpha: Optional[float] = Field(None, ge=0.01, le=1.0)
    alert_on_risk_level: Optional[str] = None
    detector_weights: Optional[Dict[str, float]] = None
    thresholds: Optional[Dict[str, float]] = None


class UBAEventSubmit(BaseModel):
    username: str
    source_ip: str = ""
    target_service: str = ""
    bytes_transferred: float = 0.0
    session_duration: float = 0.0
    peer_group: Optional[str] = None
    event_time: Optional[datetime] = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db(request: Request):
    ngfw = getattr(request.app.state, "ngfw_app", None)
    if ngfw and hasattr(ngfw, "db"):
        return ngfw.db
    raise HTTPException(status_code=503, detail="Database not available")


def _get_or_create_uba_config(db):
    from system.database.database import UBAConfig
    with db.session() as session:
        cfg = session.query(UBAConfig).first()
        if cfg is None:
            cfg = UBAConfig()
            session.add(cfg)
            session.commit()
            session.refresh(cfg)
        return cfg


def _config_to_dict(cfg) -> dict:
    return {
        "enabled":               cfg.enabled,
        "mode":                  cfg.mode,
        "baseline_min_events":   cfg.baseline_min_events,
        "max_known_ips":         cfg.max_known_ips,
        "max_known_services":    cfg.max_known_services,
        "ema_alpha":             cfg.ema_alpha,
        "detector_weights":      cfg.detector_weights or {},
        "thresholds":            cfg.thresholds or {},
        "alert_on_risk_level":   cfg.alert_on_risk_level,
        "privileged_services":   cfg.privileged_services or [],
    }


def _profile_to_dict(p) -> dict:
    return {
        "username":              p.username,
        "peer_group":            p.peer_group,
        "risk_score":            p.risk_score,
        "risk_level":            p.risk_level,
        "event_count":           p.event_count,
        "baseline_locked":       p.baseline_locked,
        "known_ips_count":       len(p.known_ips or []),
        "known_services_count":  len(p.known_services or []),
        "avg_daily_bytes":       p.avg_daily_bytes,
        "avg_session_duration":  p.avg_session_duration,
        "typical_hours":         f"{p.typical_hours_start}:00–{p.typical_hours_end}:00",
        "last_seen":             p.last_seen.isoformat() if p.last_seen else None,
        "created_at":            p.created_at.isoformat() if p.created_at else None,
    }


def _get_profiler(request: Request):
    """Return a UserProfiler wired to the live DB+ config."""
    ngfw = getattr(request.app.state, "ngfw_app", None)
    if ngfw is None:
        raise HTTPException(status_code=503, detail="NGFW not initialized")
    db = getattr(ngfw, "db", None)
    from modules.uba.engine.core.user_profiler import UserProfiler
    try:
        cfg = _get_or_create_uba_config(db) if db else None
    except Exception:
        cfg = None
    return UserProfiler(db_manager=db, config=cfg)


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/status")
async def get_status(request: Request, token: dict = Depends(require_uba)):
    """Return live UBA module status."""
    try:
        db = _get_db(request)
        from system.database.database import UBAUserProfile, UBAEvent, UBAConfig
        with db.session() as session:
            profile_count = session.query(UBAUserProfile).count()
            event_count   = session.query(UBAEvent).count()
            high_risk     = session.query(UBAUserProfile).filter(
                UBAUserProfile.risk_level.in_(["high", "critical"])
            ).count()
            cfg = session.query(UBAConfig).first()
            mode    = cfg.mode if cfg else "monitor"
            enabled = cfg.enabled if cfg else True
        return {
            "module":         "uba",
            "status":         "active" if enabled else "disabled",
            "mode":           mode,
            "version":        "2.0.0",
            "profiles_total": profile_count,
            "events_total":   event_count,
            "high_risk_users": high_risk,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/config")
async def get_config(request: Request, token: dict = Depends(require_uba)):
    db = _get_db(request)
    cfg = _get_or_create_uba_config(db)
    return _config_to_dict(cfg)


@router.put("/config")
async def update_config(
    request: Request,
    update: UBAConfigUpdate,
    token: dict = Depends(require_admin),
):
    from system.database.database import UBAConfig
    db = _get_db(request)
    with db.session() as session:
        cfg = session.query(UBAConfig).first()
        if cfg is None:
            cfg = UBAConfig()
            session.add(cfg)

        data = update.dict(exclude_none=True)
        valid_modes = ("monitor", "enforce", "learning")
        if "mode" in data and data["mode"] not in valid_modes:
            raise HTTPException(status_code=422, detail=f"mode must be one of {valid_modes}")

        for field, val in data.items():
            if hasattr(cfg, field):
                if isinstance(val, dict) and isinstance(getattr(cfg, field, None), dict):
                    merged = dict(getattr(cfg, field) or {})
                    merged.update(val)
                    setattr(cfg, field, merged)
                else:
                    setattr(cfg, field, val)

        session.commit()
        session.refresh(cfg)
        return {"status": "success", "config": _config_to_dict(cfg)}


@router.get("/users")
async def list_users(
    request: Request,
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    peer_group: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAUserProfile
    db = _get_db(request)
    with db.session() as session:
        q = session.query(UBAUserProfile)
        if risk_level:
            q = q.filter(UBAUserProfile.risk_level == risk_level)
        if peer_group:
            q = q.filter(UBAUserProfile.peer_group == peer_group)
        total = q.count()
        profiles = q.order_by(UBAUserProfile.risk_score.desc()).offset(offset).limit(limit).all()
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "users": [_profile_to_dict(p) for p in profiles],
        }


@router.get("/users/{username}")
async def get_user(
    request: Request,
    username: str,
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAUserProfile
    db = _get_db(request)
    with db.session() as session:
        p = session.query(UBAUserProfile).filter_by(username=username).first()
        if p is None:
            raise HTTPException(status_code=404, detail=f"No UBA profile for '{username}'")
        result = _profile_to_dict(p)
        result["known_ips"]      = p.known_ips or []
        result["known_services"] = p.known_services or []
        result["hour_histogram"] = p.hour_histogram or {}
        return result


@router.delete("/users/{username}/reset", status_code=status.HTTP_200_OK)
async def reset_user(
    request: Request,
    username: str,
    token: dict = Depends(require_admin),
):
    """Clear a user's behavioral baseline (admin only)."""
    from system.database.database import UBAUserProfile
    db = _get_db(request)
    with db.session() as session:
        p = session.query(UBAUserProfile).filter_by(username=username).first()
        if p is None:
            raise HTTPException(status_code=404, detail=f"No UBA profile for '{username}'")
        session.delete(p)
        session.commit()
    logger.info("UBA profile reset for user: %s", username)
    return {"status": "success", "message": f"Baseline reset for '{username}'"}


@router.get("/users/{username}/events")
async def get_user_events(
    request: Request,
    username: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.session() as session:
        q = (
            session.query(UBAEvent)
            .filter(UBAEvent.username == username)
            .filter(UBAEvent.anomaly_score >= min_score)
            .order_by(UBAEvent.event_time.desc())
        )
        total = q.count()
        events = q.offset(offset).limit(limit).all()
        return {
            "username": username,
            "total": total,
            "events": [e.to_dict() for e in events],
        }


@router.get("/events")
async def get_events(
    request: Request,
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Min anomaly score"),
    risk_level: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.session() as session:
        q = session.query(UBAEvent).filter(UBAEvent.anomaly_score >= min_score)
        if username:
            q = q.filter(UBAEvent.username == username)
        total = q.count()
        events = q.order_by(UBAEvent.event_time.desc()).offset(offset).limit(limit).all()
        return {"total": total, "events": [e.to_dict() for e in events]}


@router.get("/alerts")
async def get_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    token: dict = Depends(require_uba),
):
    """Return high/critical-risk events."""
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.session() as session:
        events = (
            session.query(UBAEvent)
            .filter(UBAEvent.anomaly_score >= 0.5)
            .order_by(UBAEvent.event_time.desc())
            .limit(limit)
            .all()
        )
        return {"total": len(events), "alerts": [e.to_dict() for e in events]}


@router.post("/events", status_code=status.HTTP_200_OK)
async def submit_event(
    request: Request,
    event: UBAEventSubmit,
    token: dict = Depends(require_admin),
):
    """Manually submit a behavioral event for UBA analysis (admin only)."""
    try:
        profiler = _get_profiler(request)
        result = profiler.analyze(
            username=event.username,
            source_ip=event.source_ip,
            target_service=event.target_service,
            bytes_transferred=event.bytes_transferred,
            session_duration=event.session_duration,
            event_time=event.event_time.timestamp() if event.event_time else None,
            peer_group=event.peer_group,
        )
        return {"status": "analyzed", "result": result.to_dict()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
