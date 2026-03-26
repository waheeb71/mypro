import os
import shutil
from pathlib import Path
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from datetime import datetime

from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.predictive_ai.models import PredictiveAIConfig as DBConfig

router = APIRouter(prefix="/api/v1/ai", tags=["ai", "models"])

# Admins always pass. Non-admins need a DB rule with resource="ai".
require_ai = make_permission_checker("ai")

class ConfigSchema(BaseModel):
    is_active: bool = True
    enable_forecaster: bool = True
    alert_on_high_risk: bool = True
    enable_rl_agent: bool = True
    auto_apply_rl_policy: bool = False

    class Config:
        orm_mode = True

@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_ai)):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/config", response_model=ConfigSchema)
async def update_config(
    new_config: ConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)

    for key, value in new_config.dict().items():
        setattr(config, key, value)

    db.commit()
    db.refresh(config)
    return config

# Predefined expected AI models
EXPECTED_MODELS = [
    {
        "id": "anomaly_detector",
        "name": "Network Anomaly Detector",
        "description": "Kernel-level DDoS and Traffic Flood Detection (eBPF)",
        "layer": "Layer 6",
        "supported_extensions": [".pkl", ".joblib", ".onnx"]
    },
    {
        "id": "deep_classifier",
        "name": "Deep Traffic Classifier",
        "description": "Deep Packet Inspection (DPI) & Malware Detection",
        "layer": "Layer 7",
        "supported_extensions": [".onnx"]
    },
    {
        "id": "uba",
        "name": "User Behavior Analytics",
        "description": "Insider Threat and Behavioral Profiling",
        "layer": "Analytics Layer",
        "supported_extensions": [".pkl", ".joblib"]
    },
    {
        "id": "attack_forecaster",
        "name": "Attack Forecaster & Vulnerability Predictor",
        "description": "Time-Series attack prediction (Mitigation Orchestrator)",
        "layer": "Analytics Layer",
        "supported_extensions": [".pkl", ".joblib", ".onnx"]
    },
    {
        "id": "rl_optimizer",
        "name": "RL Policy Optimizer",
        "description": "Reinforcement Learning Agent for dynamic firewall tuning",
        "layer": "Layer 5",
        "supported_extensions": [".pkl", ".onnx"]
    }
]

MODELS_DIR = Path("m:/نسخ المشروع/enterprise_CyberNexus/models")

def _get_model_status(model_id: str) -> Dict[str, Any]:
    """Helper to determine if a model file actually exists and its status"""
    model_path = MODELS_DIR / model_id
    if not model_path.exists() or not model_path.is_dir():
        return {"status": "Waiting for Upload", "filename": None, "last_updated": None}

    # Find the first valid file
    for ext in [".pkl", ".joblib", ".onnx"]:
        for file_path in model_path.glob(f"*{ext}"):
            if file_path.is_file():
                mtime = os.path.getmtime(file_path)
                return {
                    "status": "Loaded",
                    "filename": file_path.name,
                    "last_updated": datetime.fromtimestamp(mtime).isoformat()
                }
                
    return {"status": "Waiting for Upload", "filename": None, "last_updated": None}

@router.get("/models")
async def list_ai_models(token: dict = Depends(require_ai)):
    """List all AI models and their exact deployment status"""
    try:
        models_response = []
        for model in EXPECTED_MODELS:
            status_info = _get_model_status(model["id"])
            models_response.append({
                **model,
                **status_info
            })
        return {"models": models_response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch AI models: {str(e)}")


@router.post("/models/upload/{model_id}")
async def upload_ai_model(
    model_id: str, 
    file: UploadFile = File(...), 
    token: dict = Depends(require_admin)
):
    """Upload a new AI model binary payload securely"""
    try:
        # Validate model_id
        target_model = next((m for m in EXPECTED_MODELS if m["id"] == model_id), None)
        if not target_model:
            raise HTTPException(status_code=400, detail=f"Invalid model ID: {model_id}")
            
        # Validate extension
        filename = file.filename
        ext = os.path.splitext(filename)[1].lower()
        if ext not in target_model["supported_extensions"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported format {ext} for {model_id}. Allowed: {target_model['supported_extensions']}"
            )
            
        # Prepare directory
        target_dir = MODELS_DIR / model_id
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Clear out old models in this directory
        for old_file in target_dir.glob("*.*"):
            old_file.unlink()
            
        # Save new file
        file_path = target_dir / filename
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        return {
            "status": "success", 
            "message": f"Successfully uploaded {filename} to {model_id} engine. Engine will reload model on next evaluation cycle."
        }
        
    except HTTPException:
         raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
