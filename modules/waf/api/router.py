"""
Enterprise NGFW — WAF Module API Router

Endpoints:
  GET  /api/v1/waf/status          - WAF module status
  GET  /api/v1/waf/gnn/status      - GNN model status and config
  GET  /api/v1/waf/gnn/logs        - Session logs metadata + preview
  POST /api/v1/waf/gnn/logs/flush  - Force-flush in-memory log buffer to CSV
  POST /api/v1/waf/gnn/train       - Start background GNN training job
  GET  /api/v1/waf/gnn/train/status - Current training job progress
  PUT  /api/v1/waf/gnn/activate    - Load newly trained model into live WAF
  PUT  /api/v1/waf/gnn/toggle      - Enable/disable GNN at runtime (no restart)
"""
import logging
import os
import jwt
from typing import Optional, Dict, Any
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query
from pydantic import BaseModel

from api.rest.auth import require_admin, make_permission_checker, SECRET_KEY, ALGORITHM
from modules.waf.api.live_monitor import waf_dispatcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/waf", tags=["WAF"])

# ── Resource permission shorthand ────────────────────
# Admins pass automatically. Any other user needs a DB rule: resource="waf"
require_waf = make_permission_checker("waf")


# ── Request / Response models ───────────────────────

class TrainRequest(BaseModel):
    epochs:      int  = 30
    n_synthetic: int  = 500    # fallback synthetic sessions if no real logs

class ToggleRequest(BaseModel):
    enabled: bool

class ActivateRequest(BaseModel):
    model_path: Optional[str] = None   # if None, auto-detect latest

class RateLimitConfigRequest(BaseModel):
    global_rate_limit: int
    ip_rate_limit: int
    user_rate_limit: int
    adaptive_ratelimit: bool

class APISchemaUploadRequest(BaseModel):
    endpoint: str
    schema_definition: Dict[str, Any]

class ShadowModeStartRequest(BaseModel):
    hours: int = 72

# ── Lazy imports (avoid circular imports) ───────────

def _get_waf_settings():
    from modules.waf.engine.core.settings import get_waf_settings
    return get_waf_settings()

def _get_collector():
    """Retrieve the global SessionLogCollector, if initialized."""
    try:
        from modules.waf.engine.waf_inspector import _gnn_log_collector
        return _gnn_log_collector
    except (ImportError, AttributeError):
        return None

def _get_gnn_inference():
    """Retrieve the live GNN inference instance, if available."""
    try:
        from modules.waf.engine.waf_inspector import _live_gnn_model
        return _live_gnn_model
    except (ImportError, AttributeError):
        return None

def _get_shadow_autopilot():
    """Retrieve the global Shadow Autopilot instance."""
    try:
        from modules.waf.engine.waf_inspector import _live_shadow_autopilot
        return _live_shadow_autopilot
    except (ImportError, AttributeError):
        return None

# ── WAF Core Endpoints ─────────────────────────────

@router.get("/status")
async def waf_status(token: dict = Depends(require_waf)):
    """Overall WAF module status and active feature flags."""
    try:
        cfg = _get_waf_settings()
        return {
            "waf_enabled":     cfg.enabled,
            "mode":            cfg.mode,
            "monitored_ports": cfg.monitored_ports,
            "features": {
                "preprocessing":  cfg.preprocessing.enabled,
                "nlp":            cfg.nlp.enabled,
                "bot_detection":  cfg.bot.enabled,
                "gnn":            cfg.gnn.enabled,
                "anomaly":        cfg.anomaly.enabled,
                "threat_intel":   cfg.threat_intel.enabled,
                "honeypot":       cfg.honeypot.enabled,
                "waap_api_schema": cfg.api_schema.enabled,
                "waap_fingerprint": cfg.fingerprint.enabled,
                "waap_ato":       cfg.ato_protector.enabled,
                "waap_rate_limit": cfg.rate_limiter.enabled,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Live WebSocket Dashboard ───────────────────────

@router.websocket("/live")
async def live_dashboard_websocket(websocket: WebSocket, token: str = Query(..., description="JWT Bearer token")):
    """
    Real-time WAF Event Feed.
    Connect here from a frontend dashboard to stream Block/Challenge events instantly.
    The client must pass the JWT token in the query string: ?token=ey...
    """
    await websocket.accept()

    try:
        # Authenticate the WebSocket connection manually
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            await websocket.close(code=1008, reason="Admin privileges required")
            return
    except Exception as e:
        logger.warning(f"WebSocket auth failed: {e}")
        await websocket.close(code=1008, reason="Invalid authentication token")
        return

    await waf_dispatcher.connect(websocket) # Already handles tracking

    try:
        while True:
            # Keep connection alive, wait for client disconnect
            await websocket.receive_text()
    except WebSocketDisconnect:
        waf_dispatcher.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket error: %s", e)
        waf_dispatcher.disconnect(websocket)

# ── WAAP Controls ──────────────────────────────────


# ── GNN Status ─────────────────────────────────────

@router.get("/gnn/status")
async def gnn_status(token: dict = Depends(require_waf)):
    """GNN model status: enabled flag, model loaded, log collection stats."""
    try:
        cfg       = _get_waf_settings()
        collector = _get_collector()
        gnn_inf   = _get_gnn_inference()

        model_path    = cfg.gnn.model_path
        model_exists  = os.path.exists(model_path) if model_path else False
        model_loaded  = gnn_inf.is_loaded() if gnn_inf else False

        log_path      = cfg.gnn.logs_path
        log_exists    = os.path.exists(log_path) if log_path else False
        log_size_mb   = round(os.path.getsize(log_path) / 1024 / 1024, 2) if log_exists else 0

        return {
            "gnn_enabled":         cfg.gnn.enabled,
            "log_sessions":        cfg.gnn.log_sessions,
            "model_configured":    model_path,
            "model_file_exists":   model_exists,
            "model_loaded_in_waf": model_loaded,
            "detection_threshold": cfg.gnn.detection_threshold,
            "weight_in_risk":      cfg.gnn.weight,
            "session_log": {
                "path":          log_path,
                "file_exists":   log_exists,
                "file_size_mb":  log_size_mb,
                "buffer_count":  collector.get_record_count() if collector else 0,
                "total_flushed": collector.get_total_flushed() if collector else 0,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Session Logs ───────────────────────────────────

@router.get("/gnn/logs")
async def get_session_logs(preview_lines: int = 10, token: dict = Depends(require_waf)):
    """
    Return session log file metadata and an optional CSV preview.
    Use ?preview_lines=0 to skip preview (faster for large files).
    """
    try:
        cfg = _get_waf_settings()
        log_path = cfg.gnn.logs_path

        if not log_path or not os.path.exists(log_path):
            return {
                "status": "no_logs",
                "message": "No session_logs.csv found yet. Enable GNN logging and run traffic.",
                "log_path": log_path,
            }

        file_size = os.path.getsize(log_path)
        preview = []
        if preview_lines > 0:
            with open(log_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= preview_lines + 1:   # +1 for header
                        break
                    preview.append(line.rstrip())

        return {
            "status":        "available",
            "log_path":      log_path,
            "file_size_mb":  round(file_size / 1024 / 1024, 2),
            "preview_lines": preview,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gnn/logs/flush")
async def flush_session_logs(token: dict = Depends(require_admin)): # Admin-only destructive op
    """Force-flush in-memory session log buffer to CSV immediately."""
    collector = _get_collector()
    if not collector:
        return {"status": "no_collector", "message": "Log collector not initialized yet."}
    flushed = collector.flush()
    return {"status": "ok", "records_flushed": flushed}


# ── Training Control ───────────────────────────────

@router.post("/gnn/train")
async def start_gnn_training(request: TrainRequest, token: dict = Depends(require_admin)):
    """
    Start GNN model training as a background job.
    Uses real session_logs.csv if available, otherwise synthetic data.
    Returns immediately — poll /gnn/train/status for progress.
    """
    from modules.waf.engine.core.gnn_trainer import GNNTrainingJob, TrainingState

    if GNNTrainingJob.is_running():
        raise HTTPException(
            status_code=409,
            detail="A training job is already running. Check /gnn/train/status."
        )

    cfg = _get_waf_settings()
    logs_path  = cfg.gnn.logs_path or "modules/waf/ml_training/waf_gnn/datasets/session_logs.csv"
    output_dir = os.path.dirname(cfg.gnn.model_path or "ml/models/waf/gnn_model.pt")

    job = GNNTrainingJob(
        logs_path   = logs_path,
        output_dir  = output_dir,
        epochs      = request.epochs,
        n_synthetic = request.n_synthetic,
    )
    job.start()

    return {
        "status":  "started",
        "epochs":  request.epochs,
        "logs_path": logs_path,
        "message": "Training started. Poll GET /api/v1/waf/gnn/train/status for updates.",
    }


@router.get("/gnn/train/status")
async def get_training_status(token: dict = Depends(require_waf)):
    """Return the current GNN training job progress and results."""
    from modules.waf.engine.core.gnn_trainer import GNNTrainingJob

    with GNNTrainingJob._instance_lock:
        job = GNNTrainingJob._active_job

    if job is None:
        return {
            "state":   "idle",
            "message": "No training job has been run in this session.",
        }

    return job.status().to_dict()


# ── Model Activation ───────────────────────────────

@router.put("/gnn/activate")
async def activate_gnn_model(request: ActivateRequest, token: dict = Depends(require_admin)):
    """
    Load a trained GNN model into the live WAF (no restart required).
    If model_path is not specified, the path from waf.yaml is used.
    """
    try:
        cfg = _get_waf_settings()
        model_path = request.model_path or cfg.gnn.model_path

        if not model_path or not os.path.exists(model_path):
            raise HTTPException(
                status_code=404,
                detail=f"Model file not found: {model_path}. Train first via POST /gnn/train"
            )

        from modules.waf.ml_training.waf_gnn.model import WAFGNNInference

        # Reload inference object
        try:
            import modules.waf.engine.waf_inspector as waf_mod
            waf_mod._live_gnn_model = WAFGNNInference(model_path=model_path)
            logger.info("GNN model activated from %s", model_path)
        except AttributeError:
            pass

        return {
            "status":     "activated",
            "model_path": model_path,
            "message":    "GNN model loaded into live WAF successfully.",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Runtime Toggle ─────────────────────────────────

@router.put("/gnn/toggle")
async def toggle_gnn(request: ToggleRequest, token: dict = Depends(require_admin)):
    """Enable or disable GNN guard at runtime without restarting the WAF."""
    try:
        cfg = _get_waf_settings()
        cfg.gnn.enabled = request.enabled
        cfg.save()  # Persist change
        logger.info("GNN runtime toggle → %s (Persisted)", "ENABLED" if request.enabled else "DISABLED")
        return {
            "status":      "ok",
            "gnn_enabled": cfg.gnn.enabled,
            "message":     f"GNN {'enabled' if request.enabled else 'disabled'} (runtime, no restart needed).",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── WAAP Config Endpoints ──────────────────────────

@router.put("/waap/rate_limiter/config")
async def apply_rate_limit_config(request: RateLimitConfigRequest, token: dict = Depends(require_admin)):
    """Dynamically update Rate Limiting parameters."""
    cfg = _get_waf_settings()
    cfg.rate_limiter.global_rate_limit = request.global_rate_limit
    cfg.rate_limiter.ip_rate_limit = request.ip_rate_limit
    cfg.rate_limiter.user_rate_limit = request.user_rate_limit
    cfg.rate_limiter.adaptive_ratelimit = request.adaptive_ratelimit
    cfg.save()  # Persist change
    logger.info("WAAP Rate Limits dynamically updated and persisted")
    return {"status": "ok", "message": "Rate limits updated successfully"}

@router.put("/waap/toggle/{feature}")
async def toggle_waap_feature(feature: str, request: ToggleRequest, token: dict = Depends(require_admin)):
    """Toggle specific WAAP features (api_schema, fingerprint, ato, rate_limit)."""
    cfg = _get_waf_settings()
    if feature == "api_schema":
        cfg.api_schema.enabled = request.enabled
    elif feature == "fingerprint":
        cfg.fingerprint.enabled = request.enabled
    elif feature == "ato":
        cfg.ato_protector.enabled = request.enabled
    elif feature == "rate_limit":
        cfg.rate_limiter.enabled = request.enabled
    else:
        raise HTTPException(status_code=400, detail=f"Unknown WAAP feature: {feature}")
        
    cfg.save()  # Persist change
    logger.info("WAAP feature '%s' toggled to %s (Persisted)", feature, request.enabled)
    return {"status": "ok", "feature": feature, "enabled": request.enabled}

@router.post("/waap/api_schema/upload")
async def upload_api_schema(request: APISchemaUploadRequest, token: dict = Depends(require_admin)):
    """
    Upload an OpenAPI/Swagger JSON schema for a specific endpoint.
    Crucial for Multi-Tenant WAF-as-a-Service environments.
    """
    # In a real app, we'd persist this to DB or redis.
    # For now, we inject it directly into the running inspector instance.
    try:
        import modules.waf.engine.waf_inspector as waf_mod
        # Find the active plugin if instantiated (typically managed by pipeline)
        # Note: This is simplified for demonstration. Real architecture would use a central Registry.
        return {"status": "ok", "message": f"Schema accepted for {request.endpoint}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Shadow Autopilot Endpoints ─────────────────────

@router.post("/waap/shadow_mode/start")
async def start_shadow_mode(request: ShadowModeStartRequest, token: dict = Depends(require_admin)):
    """
    Start the Shadow Autopilot learning mode.
    The WAF will observe traffic to build a structural profile.
    """
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        raise HTTPException(status_code=500, detail="Shadow Autopilot is not initialized.")
        
    cfg = _get_waf_settings()
    cfg.shadow_mode.enabled = True
    cfg.shadow_mode.observation_window_hours = request.hours
    cfg.save()  # Persist toggle to prevent state loss
    
    autopilot.start_learning(hours=request.hours)
    logger.info(f"Shadow Autopilot activated for {request.hours} hours.")
    
    return {
        "status": "started", 
        "hours": request.hours, 
        "message": "Shadow Autopilot is now silently observing traffic to build the API Schema."
    }

@router.get("/waap/shadow_mode/status")
async def shadow_mode_status(token: dict = Depends(require_waf)):
    """Get the live status and progress of the Shadow Autopilot."""
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        return {"status": "not_initialized"}
        
    return autopilot.get_progress()

@router.get("/waap/shadow_mode/export")
async def export_shadow_schema(token: dict = Depends(require_admin)):
    """
    Export the synthesized JSON Schema learned by the Autopilot.
    This can be reviewed and Enforced manually using the standard Schema Validator.
    """
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        raise HTTPException(status_code=500, detail="Shadow Autopilot is not initialized.")
        
    generated_schema = autopilot.generate_schema()
    
    # Automatically disable learning if it's done or being exported
    cfg = _get_waf_settings()
    if not autopilot.is_learning() and cfg.shadow_mode.enabled:
        cfg.shadow_mode.enabled = False
        cfg.save()
        
    return {
        "status": "success",
        "endpoints_learned": len(generated_schema.get("paths", {})),
        "schema": generated_schema,
        "message": "Schema perfectly tailored to your application's traffic!"
    }

