import asyncio
from fastapi import APIRouter, Depends, Query, Request
from typing import List, Dict, Any

from api.rest.auth import require_admin, verify_token
# Import the actual global buffer instance directly from core.log_manager
from system.core.log_manager import global_memory_handler

router = APIRouter(prefix="/api/v1/system/logs", tags=["system", "logs"])

@router.get("", response_model=Dict[str, Any])
async def get_system_logs(
    request: Request,
    limit: int = Query(500, description="Number of recent logs to fetch"),
    token: dict = Depends(require_admin)
):
    """
    Fetch the last N lines of terminal stdout logs emitted by the Python root logger.
    """
    try:
        logs = global_memory_handler.get_recent_logs(limit=limit)
        return {
            "status": "success",
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
