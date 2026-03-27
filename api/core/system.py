from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from pydantic import BaseModel

from system.core.hardware import get_network_interfaces, get_assigned_interfaces, assign_interface_role
from api.rest.auth import require_admin, verify_token
import asyncio
import os
from fastapi import Request

router = APIRouter(prefix="/api/v1/system/interfaces", tags=["system", "interfaces"])

class InterfaceAssignRequest(BaseModel):
    port: str
    role: str

@router.get("", response_model=Dict[str, Any])
async def get_interface_map(token: dict = Depends(verify_token)):
    """
    Get all hardware interfaces and their currently assigned roles
    """
    try:
        hardware_nics = get_network_interfaces()
        assignments = get_assigned_interfaces()
        
        # Merge assigned roles into the hardware list
        for nic_name, nic_details in hardware_nics.items():
            nic_details["assigned_role"] = assignments.get(nic_name, "UNASSIGNED")
            
        return {"interfaces": hardware_nics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/assign")
async def assign_interface(request: InterfaceAssignRequest, token: dict = Depends(require_admin)):
    """
    Assign a security role to a physical hardware interface
    """
    try:
        valid_roles = ["WAN", "LAN", "DMZ", "MGMT", "HA"]
        if request.role.upper() not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of {valid_roles}")
            
        success = assign_interface_role(request.port, request.role)
        if success:
            return {"status": "success", "message": f"Mapped {request.port} to {request.role.upper()}"}
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to assign role: {str(e)}")

@router.get("/daemon/status")
async def daemon_status(request: Request):
    """Get the current status of the Daemon and Engine via internal main state"""
    ctrl = getattr(request.app.state, 'CyberNexus_controller', None)
    return {
        "daemon": "online",
        "engine_running": getattr(ctrl, 'engine_running', True) if ctrl else False
    }

@router.post("/engine/start")
async def start_engine(request: Request, token: dict = Depends(require_admin)):
    """Start the main.py CyberNexus Engine Inspection Components"""
    ctrl = getattr(request.app.state, 'CyberNexus_controller', None)
    if not ctrl:
        raise HTTPException(status_code=500, detail="CyberNexus Controller not found in app state")
        
    if getattr(ctrl, 'engine_running', True):
        return {"status": "success", "message": "Engine is already running."}
    
    try:
        await ctrl.start_firewall_components()
        return {"status": "success", "message": "Firewall Engine started successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/engine/stop")
async def stop_engine(request: Request, token: dict = Depends(require_admin)):
    """Stop the main.py CyberNexus Engine Inspection Components natively"""
    ctrl = getattr(request.app.state, 'CyberNexus_controller', None)
    if not ctrl:
        raise HTTPException(status_code=500, detail="CyberNexus Controller not found in app state")
        
    if not getattr(ctrl, 'engine_running', True):
        return {"status": "success", "message": "Engine is already stopped."}
        
    try:
        await ctrl.stop_firewall_components()
        return {"status": "success", "message": "Engine stopped successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ScriptRequest(BaseModel):
    script_name: str
    args: list[str] = []

@router.post("/scripts")
async def run_system_script(request_body: ScriptRequest, token: dict = Depends(require_admin)):
    """Execute permitted bash scripts from the scripts directory"""
    allowed_scripts = ["update.sh", "install/install.sh", "install/deps.sh"]
    if request_body.script_name not in allowed_scripts:
        raise HTTPException(status_code=403, detail="Script execution forbidden or unrecognized.")
        
    scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts")
    script_path = os.path.join(scripts_dir, request_body.script_name)
    
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Script file not found.")

    try:
        cmd = ["bash", script_path] + request_body.args
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=os.path.dirname(script_path)
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
            return {
                "status": "success" if process.returncode == 0 else "error",
                "message": f"Exit code: {process.returncode}. Output extracted but truncated."
            }
        except asyncio.TimeoutError:
            return {"status": "success", "message": "Script execution started and is running in the background."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
