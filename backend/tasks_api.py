from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.auth import current_user
from backend.db import get_profile, get_task, list_tasks, update_profile

router = APIRouter(prefix="/api", tags=["tasks"])


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    organization: Optional[str] = None
    bio: Optional[str] = None


@router.get("/tasks")
def tasks(module: Optional[str] = None, user: Dict[str, Any] = Depends(current_user)):
    return {"tasks": list_tasks(module, user_id=int(user["id"]))}


@router.get("/tasks/{task_id}")
def task_detail(task_id: str, user: Dict[str, Any] = Depends(current_user)):
    task = get_task(task_id, user_id=int(user["id"]))
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@router.get("/profile")
def profile(user: Dict[str, Any] = Depends(current_user)):
    return get_profile(int(user["id"]))


@router.put("/profile")
def save_profile(payload: ProfileUpdate, user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    return update_profile(int(user["id"]), payload.model_dump(exclude_none=True))
