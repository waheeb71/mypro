"""
Enterprise NGFW - Networking Control Endpoints  (Admin only)
POST /api/v1/system/networking/transparent-proxy — Enable/disable IPTables NAT rules
GET  /api/v1/system/networking/status            — Show current networking state
"""
import os
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel

from api.rest.auth import require_admin

router = APIRouter(prefix="/api/v1/system/networking", tags=["Networking"])
logger = logging.getLogger(__name__)


class TransparentProxyToggle(BaseModel):
    enable: bool


def _load_config() -> dict:
    import yaml
    config_path = os.getenv("NGFW_CONFIG", "/etc/ngfw/config.yaml")
    if not os.path.exists(config_path):
        config_path = Path(__file__).parent.parent.parent.parent / "system" / "config" / "base.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@router.get("/status")
async def networking_status(token: dict = Depends(require_admin)):
    """
    Return current transparent proxy state (IPTables chains presence).
    Admin only.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["iptables", "-t", "nat", "-L", "NGFW_REDIRECT", "--line-numbers"],
            capture_output=True, text=True
        )
        active = result.returncode == 0
        return {
            "transparent_proxy_active": active,
            "iptables_chain": result.stdout if active else None,
            "error": result.stderr if not active else None
        }
    except FileNotFoundError:
        return {"transparent_proxy_active": False, "note": "iptables not available on this platform"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/transparent-proxy")
async def toggle_transparent_proxy(
    request: Request,
    payload: TransparentProxyToggle,
    token: dict = Depends(require_admin)
):
    """
    Enable or disable Linux IPTables transparent NAT interception.
    Works the same as the old setup-transparent-proxy.sh.
    Admin only.
    """
    try:
        from system.networking.transparent_proxy import TransparentProxyManager
        config = _load_config()
        mgr = TransparentProxyManager(config)

        if payload.enable:
            mgr.enable_ip_forwarding()
            mgr.clear_existing_rules()
            mgr.setup_transparent_rules()
            msg = "Transparent proxy networking ENABLED (IPTables NAT rules applied)."
        else:
            mgr.teardown()
            msg = "Transparent proxy networking DISABLED (IPTables NAT rules cleared)."

        return {"status": "success", "message": msg}

    except Exception as e:
        logger.error(f"Networking toggle error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
