"""
Enterprise NGFW - Authentication & Authorization Layer
Handles JWT token creation, verification, and role-based access control (RBAC).
"""
import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, List

import bcrypt
import jwt
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ==================== JWT Configuration ====================
_env_secret = os.getenv("NGFW_SECRET_KEY", "")

SECRET_KEY = _env_secret if _env_secret else secrets.token_hex(32)
if not _env_secret:
    logger.warning("⚠️ NGFW_SECRET_KEY not set! Using auto-generated key. Set for production.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("NGFW_TOKEN_EXPIRE_MINUTES", "30"))
# ==================== Pydantic Models ====================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str = ""
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class LoginRequest(BaseModel):
    username: str
    password: str
# ==================== Password Utilities ====================
def _hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash"""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ==================== Token Utilities ====================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==================== FastAPI Security Dependencies ====================

security = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token — any valid authenticated user."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


def require_admin(token_data: dict = Depends(verify_token)) -> dict:
    """Require 'admin' role. Admins bypass all resource-level permission checks."""
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return token_data


def require_operator(token_data: dict = Depends(verify_token)) -> dict:
    """Require 'admin' or 'operator' role."""
    if token_data.get("role") not in ("admin", "operator"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator or Admin privileges required")
    return token_data


def make_permission_checker(resource: str):
    """
    Factory that returns a FastAPI dependency verifying a user has the given resource rule.
    Admins bypass all checks.
    Usage:  token = Depends(make_permission_checker("firewall"))
    """
    def check(request: Request, token_data: dict = Depends(verify_token)) -> dict:
        role = token_data.get("role", "")
        if role == "admin":
            return token_data

        # Read allowed resources from DB
        try:
            db = request.app.state.ngfw.db
            with db.session() as session:
                from system.database.database import Rule, User
                user = session.query(User).filter(User.username == token_data["sub"]).first()
                if user:
                    rules = session.query(Rule).filter(
                        Rule.user_id == user.id,
                        Rule.resource == resource,
                        Rule.enabled == True
                    ).first()
                    if rules:
                        return token_data
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access to '{resource}' requires an explicit permission rule for your account."
        )

    return check
