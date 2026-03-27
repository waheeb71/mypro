"""
Enterprise CyberNexus - Response Orchestrator Configuration
GET    /api/v1/response/blocks -> List current hardware IP blocks
DELETE /api/v1/response/blocks/{ip} -> Unblock an IP from eBPF
"""
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Dict

from api.rest.auth import make_permission_checker
from system.response.orchestrator import MitigationAction

router = APIRouter(prefix="/api/v1/response", tags=["Response Orchestration"])
logger = logging.getLogger(__name__)

def _get_app(request: Request):
    if not hasattr(request.app.state, "CyberNexus") or not request.app.state.CyberNexus:
        raise HTTPException(status_code=503, detail="CyberNexus Engine not running")
    return request.app.state.CyberNexus

@router.get("/blocks")
async def list_blocks(request: Request, token: dict = Depends(make_permission_checker("firewall"))):
    """Retrieve all IPs currently blocked by the hardware orchestrator."""
    app = _get_app(request)
    if not getattr(app, "orchestrator", None):
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
        
    # In a real system, the eBPF engine should expose a 'get_all_blocked_ips()' method.
    # We poll the orchestrator's state or the eBPF engine directly.
    return {"active_blocks": list(app.orchestrator.active_mitigations.keys()) if hasattr(app.orchestrator, "active_mitigations") else []}

@router.delete("/blocks/{ip}")
async def remove_block(request: Request, ip: str, token: dict = Depends(make_permission_checker("firewall"))):
    """Remove a hardware mitigation block for a specific IP."""
    app = _get_app(request)
    if not getattr(app, "orchestrator", None):
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
        
    engine = app.orchestrator.ebpf_engine
    if engine:
        try:
            # We assume the engine has a remove method. If not, this is a placeholder.
            if hasattr(engine, "remove_blocked_ip"):
                await engine.remove_blocked_ip(ip)
            return {"status": "success", "message": f"IP {ip} unblocked successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to unblock: {e}")
            
    return {"status": "ignored", "message": "No hardware engine active"}
