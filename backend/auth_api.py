from __future__ import annotations

import re
from typing import Dict

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from backend.auth import current_user
from backend.db import create_session, create_user, delete_session, get_user_by_login, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[\u4e00-\u9fa5A-Za-z0-9_-]{2,32}$")


class LoginPayload(BaseModel):
    login: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=6, max_length=128)
    remember: bool = True


class RegisterPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str = Field("", max_length=128)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field("", max_length=128)


def _public_user(user: Dict[str, object]) -> Dict[str, object]:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "display_name": user["display_name"],
        "role": user.get("role", ""),
        "organization": user.get("organization", ""),
        "bio": user.get("bio", ""),
        "created_at": user.get("created_at", ""),
    }


def _validate_password(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码至少需要 8 位")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="密码需要同时包含字母和数字")


@router.post("/register")
def register(payload: RegisterPayload):
    username = payload.username.strip()
    email = (payload.email or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="用户名只能包含中文、字母、数字、下划线或短横线，长度 2-32 位")
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    if not email:
        email = f"{username}@local.invalid"
    if payload.confirm_password and payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="两次输入的密码不一致")
    _validate_password(payload.password)
    try:
        user = create_user(username, email, payload.password, username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = create_session(int(user["id"]))
    return {"token": token, "user": _public_user(user)}


@router.post("/login")
def login(payload: LoginPayload):
    login_name = payload.login.strip().lower()
    user = get_user_by_login(login_name)
    if user is None or not verify_password(payload.password, str(user["password_hash"])):
        raise HTTPException(status_code=401, detail="账号或密码错误")
    token = create_session(int(user["id"]))
    user.pop("password_hash", None)
    return {"token": token, "user": _public_user(user)}


@router.get("/me")
def me(user: Dict[str, object] = Depends(current_user)):
    return {"user": _public_user(user)}


@router.post("/logout")
def logout(authorization: str = Header("")):
    _, _, token = authorization.partition(" ")
    if token:
        delete_session(token.strip())
    return {"ok": True}
