import psutil
import socket
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from typing import List, Dict, Optional
import os
import yaml
import logging

from api.rest.auth import require_admin, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/interfaces", tags=["interfaces", "networking"])

# --- Models ---
class InterfaceInfo(BaseModel):
    name: str
    mac_address: str
    ip_address: Optional[str]
    is_up: bool
    speed: int
    mtu: int
    role: str # WAN, LAN, DMZ, MGMT, UNASSIGNED

class AssignRoleRequest(BaseModel):
    interface_name: str
    role: str

from system.core.path_manager import CONFIG_DIR

# Config path
CONFIG_PATH = CONFIG_DIR / "base.yaml"

def get_persisted_roles() -> Dict[str, str]:
    """Read interface roles from configuration"""
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if config and "interfaces" in config:
                    return config["interfaces"]
    except Exception as e:
        logger.error(f"Failed to read roles from config: {e}")
    return {}

def save_persisted_roles(roles: Dict[str, str]):
    """Save interface roles to configuration"""
    try:
        config = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}

        config["interfaces"] = roles

        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        logger.info(f"Successfully saved interface roles to {CONFIG_PATH}")
    except Exception as e:
        logger.error(f"Failed to save roles to config: {e}")
        raise HTTPException(status_code=500, detail="Failed to persist configuration.")

@router.get("", response_model=List[InterfaceInfo])
async def list_interfaces(token: dict = Depends(require_admin)):
    """Discover local hardware interfaces and their assigned roles"""
    adapters = []
    
    try:
        # Cross-platform interface discovery using psutil
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        saved_roles = get_persisted_roles()
        
        for if_name, addrs in net_if_addrs.items():
            # Skip loopback
            if if_name == 'lo' or if_name.startswith('Loopback'):
                continue
                
            mac = "Unknown"
            ip = None
            
            for snic in addrs:
                # AF_LINK holds the MAC address
                if snic.family == psutil.AF_LINK or (hasattr(socket, 'AF_PACKET') and snic.family == socket.AF_PACKET):
                    mac = snic.address
                # AF_INET holds the IPv4 address
                elif snic.family == socket.AF_INET:
                    ip = snic.address

            stats = net_if_stats.get(if_name)
            is_up = stats.isup if stats else False
            speed = stats.speed if stats else 0
            mtu = stats.mtu if stats else 1500
            
            # Determine role
            role = saved_roles.get(if_name, "UNASSIGNED")
            
            adapters.append(InterfaceInfo(
                name=if_name,
                mac_address=mac,
                ip_address=ip,
                is_up=is_up,
                speed=speed,
                mtu=mtu,
                role=role
            ))
            
        return adapters
    except Exception as e:
        logger.error(f"Error fetching interfaces: {e}")
        raise HTTPException(status_code=500, detail="Error fetching hardware interface map.")


@router.post("/assign", status_code=status.HTTP_200_OK)
async def assign_interface_role(request: AssignRoleRequest, token: dict = Depends(require_admin)):
    """Assign a firewall zone/role to a physical networking interface"""
    valid_roles = ["WAN", "LAN", "DMZ", "MGMT", "HA", "UNASSIGNED"]
    
    if request.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of {valid_roles}")
        
    net_if_addrs = psutil.net_if_addrs()
    if request.interface_name not in net_if_addrs and request.interface_name != 'lo':
        raise HTTPException(status_code=404, detail="Interface not found on the system.")
        
    roles = get_persisted_roles()
    roles[request.interface_name] = request.role
    save_persisted_roles(roles)
    
    return {
        "status": "success", 
        "message": f"Assigned role {request.role} to interface {request.interface_name}",
        "interface": request.interface_name,
        "role": request.role
    }
