from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from system.database.database import get_db
from api.rest.auth import require_admin, make_permission_checker
from modules.proxy.models import ProxyConfig as DBConfig

router = APIRouter(prefix="/api/v1/proxy", tags=["proxy"])

# Admins pass automatically. Others need DB rule: resource="proxy"
require_proxy = make_permission_checker("proxy")

class ConfigSchema(BaseModel):
    is_active: bool = True
    mode: str = "transparent_proxy"
    listen_port: int = 8443
    http_port: int = 8080
    max_connections: int = 10000
    buffer_size: int = 65536
    strict_cert_validation: bool = True

    class Config:
        orm_mode = True

@router.get("/status")
async def get_status(token: dict = Depends(require_proxy)):
    return {"status": "active", "module": "proxy"}

@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_proxy)):
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
