"""
Enterprise CyberNexus - ML Core & Predictive AI Configuration
GET  /api/v1/ml-core/config -> Get ML thresholds
PUT  /api/v1/ml-core/config -> Update ML thresholds
"""
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from api.rest.auth import require_admin

router = APIRouter(prefix="/api/v1/ml-core", tags=["ML Core & Predictive AI"])
logger = logging.getLogger(__name__)

class MLConfigUpdate(BaseModel):
    anomaly_contamination: float
    profiler_time_window: int
    policy_learning_rate: float
    deep_model_enabled: bool
    rl_policy_sync_enabled: bool
    correlation_window_sec: int

def _get_app(request: Request):
    if not hasattr(request.app.state, "CyberNexus") or not request.app.state.CyberNexus:
        raise HTTPException(status_code=503, detail="CyberNexus Engine not running")
    return request.app.state.CyberNexus

@router.get("/config")
async def get_ml_config(request: Request, token: dict = Depends(require_admin)):
    """Retrieve current ML Core and Correlation Engine settings."""
    app = _get_app(request)
    ml_config = app.config.get("ml", {})
    
    return {
        "anomaly_contamination": ml_config.get("anomaly_contamination", 0.1),
        "profiler_time_window": ml_config.get("profiler_time_window", 300),
        "policy_learning_rate": ml_config.get("policy_learning_rate", 0.1),
        "deep_model_enabled": bool(ml_config.get("deep_model_path")),
        "rl_policy_sync_enabled": ml_config.get("rl_policy_sync", {}).get("enabled", False),
        "correlation_window_sec": getattr(app.predictive_correlator, "time_window_sec", 300) if getattr(app, "predictive_correlator", None) else 300
    }

@router.put("/config")
async def update_ml_config(request: Request, payload: MLConfigUpdate, token: dict = Depends(require_admin)):
    """Update ML Core settings dynamically."""
    app = _get_app(request)
    
    # Update config dictionary
    if "ml" not in app.config:
        app.config["ml"] = {}
        
    app.config["ml"]["anomaly_contamination"] = payload.anomaly_contamination
    app.config["ml"]["profiler_time_window"] = payload.profiler_time_window
    app.config["ml"]["policy_learning_rate"] = payload.policy_learning_rate
    
    if "rl_policy_sync" not in app.config["ml"]:
        app.config["ml"]["rl_policy_sync"] = {}
    app.config["ml"]["rl_policy_sync"]["enabled"] = payload.rl_policy_sync_enabled
    
    # Apply to running instances if they exist
    if getattr(app, "predictive_correlator", None):
        app.predictive_correlator.time_window_sec = payload.correlation_window_sec
        
    return {"status": "success", "message": "ML Core configuration updated"}
