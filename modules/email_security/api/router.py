"""
Enterprise CyberNexus — Email Security REST API
==========================================
Prefix: /api/v1/email_security

Endpoints:
  GET    /status          — Module live status + stats
  GET    /config          — Read persisted settings (admin/operator)
  PUT    /config          — Write persisted settings (admin only)
  POST   /config/reset    — Reset to defaults (admin only)
  GET    /whitelist       — Return whitelist (admin/operator)
  POST   /whitelist       — Add entry to whitelist (admin only)
  DELETE /whitelist/{entry} — Remove entry from whitelist (admin only)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from api.rest.auth import require_admin, make_permission_checker
logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/email_security",
    tags=["Email Security"],
)

# Operators with "email" rule (or admins) can read
require_email = make_permission_checker("email")


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class EmailConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = Field(None, description="enforce | monitor | learning")
    monitored_ports: Optional[List[int]] = None

    # sub-section overrides — keys match EmailSettings sub-dataclasses
    preprocessing: Optional[Dict[str, Any]] = None
    phishing: Optional[Dict[str, Any]] = None
    url_scanner: Optional[Dict[str, Any]] = None
    attachment_guard: Optional[Dict[str, Any]] = None
    sender_reputation: Optional[Dict[str, Any]] = None
    spam_filter: Optional[Dict[str, Any]] = None
    smtp_commands: Optional[Dict[str, Any]] = None
    thresholds: Optional[Dict[str, Any]] = None
    logging: Optional[Dict[str, Any]] = None


class WhitelistEntry(BaseModel):
    type: str = Field(..., description="email | domain | ip")
    value: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db(request: Request):
    """Return the database manager from the CyberNexus app state."""
    CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
    if CyberNexus and hasattr(CyberNexus, "db"):
        return CyberNexus.db
    raise HTTPException(
        status_code=503,
        detail="Database not available — CyberNexus not fully initialized",
    )


def _get_or_create_config(db):
    """Return the single EmailSecurityConfig row, creating it if absent."""
    from system.database.database import EmailSecurityConfig
    with db.session() as session:
        cfg = session.query(EmailSecurityConfig).first()
        if cfg is None:
            cfg = EmailSecurityConfig()
            session.add(cfg)
            session.commit()
            session.refresh(cfg)
        return cfg


def _config_to_dict(cfg) -> Dict[str, Any]:
    return {
        "enabled":           cfg.enabled,
        "mode":              cfg.mode,
        "monitored_ports":   cfg.monitored_ports or [25, 587, 465, 143, 993, 110, 995],
        "preprocessing":     cfg.preprocessing or {},
        "phishing":          cfg.phishing or {},
        "url_scanner":       cfg.url_scanner or {},
        "attachment_guard":  cfg.attachment_guard or {},
        "sender_reputation": cfg.sender_reputation or {},
        "spam_filter":       cfg.spam_filter or {},
        "smtp_commands":     cfg.smtp_commands or {},
        "thresholds":        cfg.thresholds or {},
        "logging":           cfg.logging or {},
        "whitelist":         cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []},
    }


def _apply_config_to_settings(request: Request, db_dict: Dict[str, Any]):
    """Push updated config into the live EmailInspectorPlugin if running."""
    try:
        CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
        if CyberNexus is None:
            return
        from modules.email_security.engine.core.email_inspector import EmailInspectorPlugin
        pipeline = getattr(CyberNexus, "inspection_pipeline", None)
        if pipeline is None:
            return
        plugin = pipeline.get_plugin("email_ai_inspector")
        if plugin is None:
            return
        plugin.cfg.set_enabled(db_dict.get("enabled", True))
        if "mode" in db_dict and db_dict["mode"]:
            plugin.cfg.set_mode(db_dict["mode"])
        logger.info("📧 EmailInspectorPlugin hot-reloaded with new settings")
    except Exception as exc:
        logger.warning("Email hot-reload skipped: %s", exc)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/status")
async def get_status(request: Request, token: dict = Depends(require_email)):
    """Return live email security module status and counters."""
    try:
        CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
        plugin_stats = {}
        if CyberNexus:
            pipeline = getattr(CyberNexus, "inspection_pipeline", None)
            if pipeline:
                from modules.email_security.engine.core.email_inspector import EmailInspectorPlugin
                plugin = pipeline.get_plugin("email_ai_inspector")
                if plugin:
                    plugin_stats = {
                        "inspected": getattr(plugin, "_inspected_count", 0),
                        "detected":  getattr(plugin, "_detected_count",  0),
                        "blocked":   getattr(plugin, "_blocked_count",   0),
                        "enabled":   plugin.cfg.enabled,
                        "mode":      plugin.cfg.mode,
                    }
        return {
            "module":  "email_security",
            "status":  "active" if plugin_stats else "loaded_no_pipeline",
            "version": "2.0.0",
            "plugin":  plugin_stats,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/config")
async def get_config(request: Request, token: dict = Depends(require_email)):
    """Return the persisted email security configuration."""
    try:
        db = _get_db(request)
        cfg = _get_or_create_config(db)
        return _config_to_dict(cfg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Config read error: {exc}")


@router.put("/config")
async def update_config(
    request: Request,
    update: EmailConfigUpdate,
    token: dict = Depends(require_admin),
):
    """Update email security configuration (admin only)."""
    try:
        from system.database.database import EmailSecurityConfig
        db = _get_db(request)

        with db.session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                cfg = EmailSecurityConfig()
                session.add(cfg)

            data = update.dict(exclude_none=True)

            if "enabled" in data:
                cfg.enabled = data["enabled"]
            if "mode" in data:
                if data["mode"] not in ("enforce", "monitor", "learning"):
                    raise HTTPException(
                        status_code=422,
                        detail="mode must be 'enforce', 'monitor', or 'learning'",
                    )
                cfg.mode = data["mode"]
            if "monitored_ports" in data:
                cfg.monitored_ports = data["monitored_ports"]

            # merge JSON sub-sections
            for section in (
                "preprocessing", "phishing", "url_scanner", "attachment_guard",
                "sender_reputation", "spam_filter", "smtp_commands", "thresholds", "logging",
            ):
                if section in data:
                    current = getattr(cfg, section) or {}
                    current.update(data[section])
                    setattr(cfg, section, current)

            session.commit()
            session.refresh(cfg)
            result = _config_to_dict(cfg)

        _apply_config_to_settings(request, result)
        return {"status": "success", "config": result}

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Config update error: {exc}")


@router.post("/config/reset", status_code=status.HTTP_200_OK)
async def reset_config(request: Request, token: dict = Depends(require_admin)):
    """Reset email security configuration to system defaults (admin only)."""
    try:
        from system.database.database import EmailSecurityConfig
        db = _get_db(request)
        with db.session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg:
                session.delete(cfg)
            session.commit()
        logger.info("📧 Email security config reset to defaults")
        return {"status": "success", "message": "Email security config reset to defaults."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Whitelist Endpoints ───────────────────────────────────────────────────────


@router.get("/whitelist")
async def get_whitelist(request: Request, token: dict = Depends(require_email)):
    """Return the current email whitelist entries."""
    try:
        db = _get_db(request)
        cfg = _get_or_create_config(db)
        return cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/whitelist", status_code=status.HTTP_201_CREATED)
async def add_whitelist_entry(
    request: Request,
    entry: WhitelistEntry,
    token: dict = Depends(require_admin),
):
    """Add an email, domain, or IP to the whitelist (admin only)."""
    if entry.type not in ("email", "domain", "ip"):
        raise HTTPException(status_code=422, detail="type must be 'email', 'domain', or 'ip'")
    try:
        from system.database.database import EmailSecurityConfig
        db = _get_db(request)
        with db.session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                cfg = EmailSecurityConfig()
                session.add(cfg)

            wl = cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []}
            key = entry.type + "s"       # email → emails, domain → domains, ip → ips
            if entry.value not in wl.get(key, []):
                wl.setdefault(key, []).append(entry.value)
            cfg.whitelist = wl
            session.commit()

        return {
            "status": "success",
            "message": f"{entry.type} '{entry.value}' added to whitelist.",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/whitelist/{entry_type}/{value}", status_code=status.HTTP_200_OK)
async def remove_whitelist_entry(
    request: Request,
    entry_type: str,
    value: str,
    token: dict = Depends(require_admin),
):
    """Remove an entry from the whitelist (admin only)."""
    if entry_type not in ("email", "domain", "ip"):
        raise HTTPException(status_code=422, detail="entry_type must be 'email', 'domain', or 'ip'")
    try:
        from system.database.database import EmailSecurityConfig
        db = _get_db(request)
        with db.session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                raise HTTPException(status_code=404, detail="No config found")

            wl  = cfg.whitelist or {}
            key = entry_type + "s"
            lst = wl.get(key, [])
            if value not in lst:
                raise HTTPException(status_code=404, detail=f"'{value}' not in whitelist")
            lst.remove(value)
            wl[key] = lst
            cfg.whitelist = wl
            session.commit()

        return {"status": "success", "message": f"{entry_type} '{value}' removed from whitelist."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
