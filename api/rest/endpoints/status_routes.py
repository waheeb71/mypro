"""
Enterprise CyberNexus - System Status & Health Endpoints
GET  /api/v1/status          — Full system status  (operator+)
GET  /health                 — Liveness probe (public)
GET  /api/v1/health/liveness — Kubernetes liveness (public)
GET  /api/v1/health/readiness
GET  /api/v1/health/detailed — Component detail (operator+)
GET  /metrics                — Prometheus metrics (public)
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from api.rest.auth import verify_token, require_operator

router = APIRouter(tags=["Health & Status"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class SystemStatus(BaseModel):
    status: str
    uptime_seconds: float
    cpu_usage: float
    memory_usage: float
    active_connections: int
    rules_count: int
    ml_models_loaded: bool
    ha_state: str = Field("UNKNOWN")
    ha_peer: Optional[str] = None
    ha_priority: int = 0


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check():
    """Public liveness heartbeat (no auth). Used by load balancers."""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@router.get("/api/v1/health/liveness")
async def liveness_probe(request: Request):
    """Kubernetes liveness probe (no auth)."""
    try:
        CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
        if CyberNexus and hasattr(CyberNexus, "health_checker"):
            alive = await CyberNexus.health_checker.liveness_probe()
            if not alive:
                return JSONResponse(status_code=503, content={"status": "dead"})
        return {"status": "alive", "timestamp": datetime.utcnow()}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})


@router.get("/api/v1/health/readiness")
async def readiness_probe(request: Request):
    """Kubernetes readiness probe (no auth)."""
    try:
        CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
        if CyberNexus and hasattr(CyberNexus, "health_checker"):
            ready = await CyberNexus.health_checker.readiness_probe()
            if not ready:
                return JSONResponse(status_code=503, content={"status": "not_ready"})
            return {"status": "ready", "timestamp": datetime.utcnow()}
        return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "Health checker missing"})
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})


@router.get("/api/v1/health/detailed")
async def detailed_health(request: Request, token: dict = Depends(verify_token)):
    """Detailed per-component health check (authenticated users)."""
    CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
    if CyberNexus and hasattr(CyberNexus, "health_checker"):
        return await CyberNexus.health_checker.check_all_components()
    return {"overall_status": "unknown", "message": "Health checker not available"}


@router.get("/api/v1/status", response_model=SystemStatus)
async def get_status(request: Request, token: dict = Depends(require_operator)):
    """Full system metrics — operators and admins only."""
    import psutil

    CyberNexus = getattr(request.app.state, "CyberNexus_app", None)
    ha_state, ha_peer, ha_priority, uptime = "MASTER", None, 100, 0.0

    if CyberNexus:
        uptime = CyberNexus.get_uptime() if hasattr(CyberNexus, "get_uptime") else 0.0
        if getattr(CyberNexus, "ha_manager", None):
            ha_state = CyberNexus.ha_manager.state.name
            ha_peer = CyberNexus.ha_manager.peer_ip
            ha_priority = CyberNexus.ha_manager.priority

    return SystemStatus(
        status="operational",
        uptime_seconds=uptime,
        cpu_usage=psutil.cpu_percent(),
        memory_usage=psutil.virtual_memory().percent,
        active_connections=0,
        rules_count=0,
        ml_models_loaded=True,
        ha_state=ha_state,
        ha_peer=ha_peer,
        ha_priority=ha_priority,
    )


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Prometheus metrics scrape endpoint."""
    from system.telemetry.prometheus_metrics import metrics_endpoint
    return await metrics_endpoint()
