"""
CyberNexus NGFW — Config Management API Routes
================================================
Exposes config versioning endpoints:
  GET  /api/v1/config/versions
  GET  /api/v1/config/diff?v1=N&v2=M
  POST /api/v1/config/rollback?version=N
  POST /api/v1/config/reload
  GET  /api/v1/config/current
"""

import logging
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])


@router.get("/current")
async def get_current_config():
    """Return the merged active configuration (base.yaml + features.yaml + ENV)."""
    from system.config.config_manager import ConfigManager
    return ConfigManager.instance().get_all()


@router.get("/versions")
async def list_versions():
    """List all configuration snapshots (latest first)."""
    from system.config.config_manager import ConfigManager
    snapshots = ConfigManager.instance().list_snapshots()
    return {"total": len(snapshots), "versions": snapshots}


@router.get("/diff")
async def diff_versions(
    v1: str = Query(..., description="Version ID A (e.g. 'v3')"),
    v2: str = Query(..., description="Version ID B (e.g. 'v7')"),
):
    """Compare two config versions and return a JSON diff."""
    from system.config.config_manager import ConfigManager
    diff = ConfigManager.instance().diff(v1, v2)
    if "error" in diff:
        raise HTTPException(status_code=404, detail=diff["error"])
    return {"v1": v1, "v2": v2, "diff": diff, "changed_keys": list(diff.keys())}


@router.post("/rollback")
async def rollback_config(version: str = Query(..., description="Version ID to roll back to")):
    """Roll back to a previous configuration version."""
    from system.config.config_manager import ConfigManager
    success = ConfigManager.instance().rollback(version)
    if not success:
        raise HTTPException(status_code=404, detail=f"Version '{version}' not found")
    return {"status": "rolled_back", "version": version}


@router.post("/reload")
async def reload_config():
    """Force hot-reload of base.yaml + features.yaml from disk."""
    from system.config.config_manager import ConfigManager
    diff = ConfigManager.instance().force_reload()
    return {
        "status": "reloaded",
        "changed_keys": list(diff.keys()),
        "changes": diff,
    }


@router.post("/snapshot")
async def take_snapshot():
    """Manually take a config snapshot (useful before making changes)."""
    from system.config.config_manager import ConfigManager
    version_id = ConfigManager.instance().snapshot(source="api")
    return {"status": "created", "version_id": version_id}
