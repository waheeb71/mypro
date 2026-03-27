"""
Enterprise CyberNexus - High Availability (HA) Configuration
GET  /api/v1/ha/status -> Get HA cluster status
PUT  /api/v1/ha/sync   -> Force manual sync
"""
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from api.rest.auth import make_permission_checker

router = APIRouter(prefix="/api/v1/ha", tags=["High Availability"])
logger = logging.getLogger(__name__)

def _get_app(request: Request):
    if not hasattr(request.app.state, "CyberNexus") or not request.app.state.CyberNexus:
        raise HTTPException(status_code=503, detail="CyberNexus Engine not running")
    return request.app.state.CyberNexus

@router.get("/status")
async def get_ha_status(request: Request, token: dict = Depends(make_permission_checker("firewall"))):
    """Retrieve current node role and HA status."""
    app = _get_app(request)
    if not getattr(app, "ha_manager", None):
        return {"enabled": False, "message": "High Availability is disabled"}
        
    manager = app.ha_manager
    return {
        "enabled": True,
        "node_id": manager.node_id,
        "state": manager.state.name,
        "is_master": app.is_ha_master,
        "peer_ip": manager.peer_ip,
        "last_heartbeat": manager.last_heartbeat
    }

@router.post("/sync")
async def force_sync(request: Request, token: dict = Depends(make_permission_checker("firewall"))):
    """Force an immediate state synchronization slice."""
    app = _get_app(request)
    if not app.is_ha_master or not getattr(app, "state_sync", None):
        raise HTTPException(status_code=400, detail="Only Master can force sync, or sync disabled")
        
    await app.state_sync.sync_state()
    return {"status": "success", "message": "Manual HA synchronization triggered"}
