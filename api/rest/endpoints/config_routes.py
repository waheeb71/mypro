"""
Enterprise NGFW - Configuration Management Endpoints
GET    /api/v1/config                       — Read full config  (admin)
PUT    /api/v1/config                       — Update a key      (admin)
GET    /api/v1/config/modules               — List module state (operator+)
PUT    /api/v1/modules/{name}/toggle        — Enable/disable a module (admin)
"""
import os
import logging
from typing import Any
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel, Field

from api.rest.auth import require_admin, require_operator

router = APIRouter(prefix="/api/v1", tags=["Configuration"])
logger = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ConfigUpdate(BaseModel):
    category: str = Field(..., description="Top-level YAML section (e.g. 'proxy', 'ml')")
    key: str = Field(..., description="Key within the section")
    value: Any = Field(..., description="New value")


class ModuleToggle(BaseModel):
    enabled: bool


# ── Helpers ───────────────────────────────────────────────────────────────────

def _config_path() -> str:
    path = os.getenv("NGFW_CONFIG", "/etc/ngfw/config.yaml")
    if not os.path.exists(path):
        path = Path(__file__).parent.parent.parent.parent / "system" / "config" / "base.yaml"
    return str(path)


def _read_config() -> dict:
    with open(_config_path(), "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_config(data: dict):
    with open(_config_path(), "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


def _hot_reload(request: Request):
    """Trigger config reload on the running engine if available."""
    try:
        ngfw = getattr(request.app.state, "ngfw_app", None)
        if ngfw and hasattr(ngfw, "reload_config"):
            ngfw.reload_config()
    except Exception as e:
        logger.warning(f"Hot-reload skipped: {e}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/config")
async def get_config(request: Request, token: dict = Depends(require_admin)):
    """Return the full system configuration. Admin only."""
    try:
        return _read_config()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config read error: {e}")


@router.put("/config")
async def update_config(request: Request, update: ConfigUpdate, token: dict = Depends(require_admin)):
    """Update a single configuration key and hot-reload the engine. Admin only."""
    try:
        cfg = _read_config()
        cfg.setdefault(update.category, {})
        section = cfg[update.category]
        if isinstance(section, dict) and isinstance(update.value, dict):
            section.setdefault(update.key, {}).update(update.value)
        else:
            cfg[update.category][update.key] = update.value
        _write_config(cfg)
        _hot_reload(request)
        return {"status": "success", "updated": f"{update.category}.{update.key}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config update error: {e}")


@router.get("/config/modules")
async def list_modules(token: dict = Depends(require_operator)):
    """Return the enabled/disabled state of every module. Operator+ only."""
    try:
        cfg = _read_config()
        return cfg.get("modules", {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list modules: {e}")


@router.put("/modules/{module_name}/toggle")
async def toggle_module(
    request: Request,
    module_name: str,
    toggle: ModuleToggle,
    token: dict = Depends(require_admin)
):
    """
    Enable or disable an inspection module dynamically.
    Triggers an immediate hot-reload of the plugin pipeline. Admin only.
    """
    try:
        cfg = _read_config()
        cfg.setdefault("modules", {}).setdefault(module_name, {})
        cfg["modules"][module_name]["enabled"] = toggle.enabled
        _write_config(cfg)

        # Hot-reload inspection pipeline if engine is running
        ngfw = getattr(request.app.state, "ngfw_app", None)
        if ngfw and hasattr(ngfw, "inspection_pipeline"):
            from system.core.module_manager import ModuleManager
            pipeline = ngfw.inspection_pipeline
            for p in list(pipeline._plugins_by_name.keys()):
                pipeline.unregister_plugin(p)
            ModuleManager(cfg, pipeline).load_plugins()
            logger.info(f"Plugin pipeline reloaded after toggling '{module_name}'")

        action = "enabled" if toggle.enabled else "disabled"
        return {"status": "success", "message": f"Module '{module_name}' is now {action}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Toggle failed: {e}")
