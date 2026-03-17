"""
Enterprise NGFW - VPN REST API
================================
Prefix: /api/v1/vpn

Endpoints:
  GET  /status          - WireGuard interface status
  GET  /config          - VPN Server configuration
  PUT  /config          - Update VPN Server configuration
  GET  /peers           - List all VPN peers (from DB)
  POST /peers           - Add a new VPN peer (saves to DB)
  DELETE /peers/{pubkey} - Remove a VPN peer (removes from DB)
  POST /keys/generate   - Generate a new keypair
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import List, Optional
import logging
from sqlalchemy.orm import Session

from api.rest.auth import require_admin, make_permission_checker
from system.database.database import get_db, VPNConfig, VPNPeer
from modules.vpn.engine.wireguard import PeerConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/vpn", tags=["VPN"])

# Admins always pass. Non-admins need a DB rule with resource="vpn".
require_vpn = make_permission_checker("vpn")

# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class VPNPeerRequest(BaseModel):
    name: str = Field("", description="Friendly name for the peer")
    public_key: str = Field(..., description="WireGuard Public Key")
    allowed_ips: List[str] = Field(..., description="List of allowed IP addresses/CIDRs")
    endpoint: Optional[str] = Field(None, description="Optional peer endpoint IP:PORT")
    preshared_key: Optional[str] = Field(None, description="Optional preshared key")
    persistent_keepalive: int = Field(25, description="Keepalive interval in seconds")

class VPNConfigRequest(BaseModel):
    enabled: bool
    interface: str = "wg0"
    listen_port: int = 51820
    server_ip: str = "10.10.0.1/24"
    dns: Optional[str] = None
    mtu: int = 1420

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_vpn_manager(request: Request):
    ngfw = getattr(request.app.state, 'ngfw_app', None)
    if ngfw and ngfw.vpn_enabled and ngfw.vpn_manager:
        return ngfw.vpn_manager
    return None

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_vpn_status(request: Request, token: dict = Depends(require_vpn)):
    """Get WireGuard VPN interface status"""
    vpn_mgr = _get_vpn_manager(request)
    if not vpn_mgr:
        raise HTTPException(status_code=503, detail="VPN functionality is not enabled or available.")
        
    status_text = vpn_mgr.get_status()
    return {"status": status_text, "interface": vpn_mgr.interface}

@router.get("/config")
async def get_vpn_config(db: Session = Depends(get_db), token: dict = Depends(require_vpn)):
    """Get persistent VPN configuration from DB"""
    config = db.query(VPNConfig).first()
    if not config:
        return {"enabled": False, "message": "No VPN configuration found in database."}
    
    return {
        "enabled": config.enabled,
        "interface": config.interface,
        "listen_port": config.listen_port,
        "server_ip": config.server_ip,
        "public_key": config.public_key,
        "dns": config.dns,
        "mtu": config.mtu
    }

@router.put("/config")
async def update_vpn_config(
    request: Request, 
    cfg_data: VPNConfigRequest, 
    db: Session = Depends(get_db), 
    token: dict = Depends(require_admin)
):
    """Update VPN configuration and re-initialize if needed"""
    config = db.query(VPNConfig).first()
    if not config:
        config = VPNConfig()
        db.add(config)
    
    config.enabled = cfg_data.enabled
    config.interface = cfg_data.interface
    config.listen_port = cfg_data.listen_port
    config.server_ip = cfg_data.server_ip
    config.dns = cfg_data.dns or ""
    config.mtu = cfg_data.mtu
    
    db.commit()
    
    # Note: Full re-initialization usually requires engine restart or manual trigger
    # for networking changes.
    return {"message": "VPN configuration updated. Restart may be required for some changes."}

@router.get("/peers")
async def list_vpn_peers(db: Session = Depends(get_db), token: dict = Depends(require_vpn)):
    """List all configured VPN peers from database"""
    peers = db.query(VPNPeer).all()
    return {"peers": [p.to_dict() for p in peers]}

@router.post("/peers", status_code=status.HTTP_201_CREATED)
async def add_vpn_peer(
    request: Request, 
    peer_data: VPNPeerRequest, 
    db: Session = Depends(get_db), 
    token: dict = Depends(require_admin)
):
    """Add a new WireGuard VPN peer and persist to DB"""
    vpn_mgr = _get_vpn_manager(request)
    if not vpn_mgr:
        raise HTTPException(status_code=503, detail="VPN functionality is not enabled")
    
    # 1. Add to live manager
    peer_config = PeerConfig(
        public_key=peer_data.public_key,
        allowed_ips=peer_data.allowed_ips,
        endpoint=peer_data.endpoint,
        preshared_key=peer_data.preshared_key,
        persistent_keepalive=peer_data.persistent_keepalive
    )
    
    success = vpn_mgr.add_peer(peer_config)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add VPN peer to WireGuard interface.")
    
    # 2. Persist to DB
    existing = db.query(VPNPeer).filter_by(public_key=peer_data.public_key).first()
    if not existing:
        new_peer = VPNPeer(
            name=peer_data.name,
            public_key=peer_data.public_key,
            allowed_ips=peer_data.allowed_ips,
            endpoint=peer_data.endpoint or "",
            preshared_key=peer_data.preshared_key or "",
            persistent_keepalive=peer_data.persistent_keepalive
        )
        db.add(new_peer)
    else:
        existing.name = peer_data.name
        existing.allowed_ips = peer_data.allowed_ips
        existing.endpoint = peer_data.endpoint or ""
        existing.preshared_key = peer_data.preshared_key or ""
        existing.persistent_keepalive = peer_data.persistent_keepalive
        existing.enabled = True
        
    db.commit()
    return {"message": "Peer added and persisted successfully", "public_key": peer_data.public_key}

@router.delete("/peers/{public_key:path}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_vpn_peer(
    request: Request, 
    public_key: str, 
    db: Session = Depends(get_db), 
    token: dict = Depends(require_admin)
):
    """Remove a WireGuard VPN peer from live interface and DB"""
    vpn_mgr = _get_vpn_manager(request)
    # Even if vpn_mgr is down, we allow removing from DB
    
    # 1. Remove from live manager if active
    if vpn_mgr:
        vpn_mgr.remove_peer(public_key)
    
    # 2. Remove from DB
    peer = db.query(VPNPeer).filter_by(public_key=public_key).first()
    if peer:
        db.delete(peer)
        db.commit()
    
    return None

@router.post("/keys/generate")
async def generate_keys(request: Request, token: dict = Depends(require_admin)):
    """Generate a new WireGuard keypair"""
    vpn_mgr = _get_vpn_manager(request)
    if not vpn_mgr:
        # Fallback to a temporary manager just for keygen if needed
        from modules.vpn.engine.wireguard import WireGuardManager
        temp_mgr = WireGuardManager()
        priv, pub = temp_mgr.generate_keys()
        return {"private_key": priv, "public_key": pub}
        
    priv, pub = vpn_mgr.generate_keys()
    return {"private_key": priv, "public_key": pub}
