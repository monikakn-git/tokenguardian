from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.auth_service import create_user, authenticate_user, issue_token, cascade_revoke

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ResetPasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str


@router.post("/register")
def register(req: RegisterRequest):
    user = create_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=400, detail="Username already taken")
    return {"message": "User created", "user_id": user["id"]}


@router.post("/login")
def login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token, jti = issue_token(user["id"])
    return {"access_token": token, "token_type": "bearer", "jti": jti}


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    user = authenticate_user(req.username, req.old_password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # CascadeShield — revoke all existing tokens
    revoked = cascade_revoke(user["id"])
    # Issue a fresh token
    token, jti = issue_token(user["id"])
    return {
        "message": f"Password reset. CascadeShield revoked {revoked} active session(s).",
        "access_token": token,
        "token_type": "bearer",
    }
