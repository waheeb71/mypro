"""
Enterprise CyberNexus - User & Rules Management Endpoints  (Admin only)
GET    /api/v1/users             — List users
POST   /api/v1/users             — Create user
DELETE /api/v1/users/{username}  — Remove user
GET    /api/v1/users/{username}/rules  — List user rules
POST   /api/v1/users/{username}/rules  — Add resource rule
DELETE /api/v1/users/{username}/rules/{rule_id} — Remove rule
"""
import logging
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel, Field
from typing import Optional

from api.rest.auth import require_admin, _hash_password
from system.database.database import User, Rule

router = APIRouter(prefix="/api/v1/users", tags=["User Management"])
logger = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = Field("operator", description="'admin', 'operator', or 'viewer'")


class RuleCreate(BaseModel):
    resource: str = Field(..., description="Resource name: 'firewall', 'vpn', 'waf', 'qos', etc.")
    description: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db(request: Request):
    if not hasattr(request.app.state, "CyberNexus") or not request.app.state.CyberNexus:
        raise HTTPException(status_code=503, detail="CyberNexus not initialized")
    return request.app.state.CyberNexus.db


# ── User CRUD ─────────────────────────────────────────────────────────────────

@router.get("/")
async def list_users(request: Request, token: dict = Depends(require_admin)):
    """Return all users (admin only)."""
    with _db(request).session() as session:
        users = session.query(User).all()
        return [{"id": u.id, "username": u.username, "role": u.role, "last_login": u.last_login} for u in users]


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(request: Request, payload: UserCreate, token: dict = Depends(require_admin)):
    """Create a new system user (admin only)."""
    VALID_ROLES = {"admin", "operator", "viewer"}
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {VALID_ROLES}")

    db = _db(request)
    with db.session() as session:
        existing = session.query(User).filter(User.username == payload.username).first()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")
        user = User(
            username=payload.username,
            password_hash=_hash_password(payload.password),
            role=payload.role
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"status": "created", "username": user.username, "role": user.role}


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(request: Request, username: str, token: dict = Depends(require_admin)):
    """Delete a user (admin only). Cannot delete yourself."""
    if token.get("sub") == username:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    db = _db(request)
    with db.session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        session.delete(user)
        session.commit()


# ── Rules (Resource-Level Permissions) ────────────────────────────────────────

@router.get("/{username}/rules")
async def list_user_rules(request: Request, username: str, token: dict = Depends(require_admin)):
    """
    List all resource access rules assigned to a user.
    Rules are checked by make_permission_checker() in auth.py.
    """
    db = _db(request)
    with db.session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        rules = session.query(Rule).filter(Rule.user_id == user.id).all()
        return [{"id": r.id, "resource": r.resource, "enabled": r.enabled, "description": getattr(r, "description", "")} for r in rules]


@router.post("/{username}/rules", status_code=status.HTTP_201_CREATED)
async def add_user_rule(request: Request, username: str, rule: RuleCreate, token: dict = Depends(require_admin)):
    """Grant a user access to a specific resource/module (admin only)."""
    db = _db(request)
    with db.session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        existing = session.query(Rule).filter(Rule.user_id == user.id, Rule.resource == rule.resource).first()
        if existing:
            existing.enabled = True
            session.commit()
            return {"status": "updated", "resource": rule.resource, "enabled": True}
        new_rule = Rule(user_id=user.id, resource=rule.resource, enabled=True)
        session.add(new_rule)
        session.commit()
        session.refresh(new_rule)
        return {"status": "created", "id": new_rule.id, "resource": rule.resource}


@router.delete("/{username}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_rule(request: Request, username: str, rule_id: int, token: dict = Depends(require_admin)):
    """Revoke a resource rule from a user (admin only)."""
    db = _db(request)
    with db.session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        rule = session.query(Rule).filter(Rule.id == rule_id, Rule.user_id == user.id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        session.delete(rule)
        session.commit()
