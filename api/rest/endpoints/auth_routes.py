"""
Enterprise CyberNexus - Authentication Endpoints
POST   /api/v1/auth/login   — Login and get JWT token
POST   /api/v1/auth/refresh — Refresh token
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel

from api.rest.auth import (
    Token, LoginRequest, _verify_password, create_access_token,
    verify_token, ACCESS_TOKEN_EXPIRE_MINUTES
)
from system.database.database import User

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
async def login(request: Request, login_data: LoginRequest):
    """Authenticate user and return a JWT access token."""
    db = _get_db(request)
    with db.session() as session:
        user = session.query(User).filter(User.username == login_data.username).first()
        if not user or not _verify_password(login_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        user.last_login = datetime.utcnow()
        session.commit()
        return Token(
            access_token=access_token,
            token_type="bearer",
            role=user.role,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(token_data: dict = Depends(verify_token)):
    """Issue a fresh token for an already-authenticated user."""
    new_token = create_access_token(
        data={"sub": token_data["sub"], "role": token_data["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return Token(
        access_token=new_token,
        token_type="bearer",
        role=token_data["role"],
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.get("/me")
async def get_current_user(token_data: dict = Depends(verify_token)):
    """Return the profile of the currently authenticated user."""
    return {"username": token_data["sub"], "role": token_data["role"]}


def _get_db(request: Request):
    if not hasattr(request.app.state, "CyberNexus") or not request.app.state.CyberNexus:
        raise HTTPException(status_code=503, detail="CyberNexus not initialized")
    return request.app.state.CyberNexus.db
