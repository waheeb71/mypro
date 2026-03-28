from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import StreamingResponse
import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from modules.log_manager.engine.log_controller import LogControllerManager, global_memory_handler

router = APIRouter(prefix="/api/log_manager", tags=["Log Manager"])

@router.get("/logs/stream")
async def stream_logs():
    """Streams logs in real-time as Server-Sent Events (SSE)."""
    async def log_generator():
        async for log_entry in global_memory_handler.subscribe():
            yield f"data: {json.dumps(log_entry)}\n\n"
            
    return StreamingResponse(log_generator(), media_type="text/event-stream")

class ClearLogsRequest(BaseModel):
    file_name: Optional[str] = None

@router.get("/logs/search")
async def search_logs(
    level: Optional[str] = Query(None, description="Log level filter: INFO, WARNING, ERROR"),
    keyword: Optional[str] = Query(None, description="Keyword filter"),
    file_name: Optional[str] = Query(None, description="Specific log file filter"),
    limit: int = Query(200, description="Max result count")
):
    """Searches and parses content from actual .log/.json files on disk."""
    controller = LogControllerManager.get_instance()
    results = controller.search_logs(file_name=file_name, level=level, keyword=keyword, limit=limit)
    return {
        "status": "success",
        "count": len(results),
        "data": results
    }

@router.post("/logs/clear")
async def clear_logs(request: ClearLogsRequest):
    """Truncates log files (warning: unrecoverable)."""
    controller = LogControllerManager.get_instance()
    cleared = controller.clear_logs(request.file_name)
    return {
        "status": "success",
        "cleared_files": cleared
    }

@router.get("/logs/stats")
async def get_log_stats():
    """Retrieve statistics about log usage and file sizes."""
    controller = LogControllerManager.get_instance()
    return {
        "status": "success",
        "data": controller.get_stats()
    }

@router.get("/logs/files")
async def list_log_files():
    """Get a list of all existing log files."""
    controller = LogControllerManager.get_instance()
    return {
        "status": "success",
        "data": controller.list_log_files()
    }

@router.get("/events/search")
async def search_events(
    src_ip: Optional[str] = Query(None, description="Source IP to filter by"),
    verdict: Optional[str] = Query(None, description="Verdict filter (allow, drop, etc.)"),
    limit: int = Query(100, description="Max results")
):
    """Search structured security events (Visitor Tracking / SIEM)."""
    controller = LogControllerManager.get_instance()
    results = await controller.query_events(src_ip=src_ip, verdict=verdict, limit=limit)
    return {
        "status": "success",
        "count": len(results),
        "data": results
    }

@router.get("/visitors")
async def get_visitors(limit: int = 50):
    """Simplified Visitor Tracking view."""
    controller = LogControllerManager.get_instance()
    # In this context, visitors are unique source IPs with their latest activity
    results = await controller.query_events(limit=limit)
    return {
        "status": "success",
        "data": results
    }
