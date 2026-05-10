from __future__ import annotations

from typing import Dict, Optional

from fastapi import Header, HTTPException

from backend.db import get_user_by_token


def _extract_token(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()


def current_user(authorization: Optional[str] = Header(None)) -> Dict[str, object]:
    token = _extract_token(authorization)
    user = get_user_by_token(token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail="请先登录")
    return user


def optional_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, object]]:
    token = _extract_token(authorization)
    return get_user_by_token(token) if token else None
