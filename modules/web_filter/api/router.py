from fastapi import APIRouter, Depends
from api.rest.auth import require_admin, make_permission_checker

router = APIRouter(prefix="/api/v1/web_filter", tags=["web_filter"])

# Admins pass automatically. Others need DB rule: resource="web_filter"
require_web_filter = make_permission_checker("web_filter")

@router.get("/status")
async def get_status(token: dict = Depends(require_web_filter)):
    return {"status": "active", "module": "web_filter"}
