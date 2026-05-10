from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.db import update_task_report

load_dotenv()

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportRequest(BaseModel):
    scene: str = Field(..., min_length=1)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    task_id: str = ""


def _compact(value: Any, max_items: int = 40) -> Any:
    if isinstance(value, dict):
        return {key: _compact(item, max_items=max_items) for key, item in value.items()}
    if isinstance(value, list):
        trimmed = value[:max_items]
        return [_compact(item, max_items=max_items) for item in trimmed]
    return value


def _build_prompt(scene: str, evidence: Dict[str, Any]) -> List[Dict[str, str]]:
    compact_evidence = _compact(evidence)
    evidence_text = json.dumps(compact_evidence, ensure_ascii=False, indent=2)
    system = (
        "你是机器人网络安全审计专家。请基于用户提供的检测证据生成中文 AI 检测报告。"
        "报告要专业、可交付、不要编造证据。"
    )
    user = (
        f"检测场景：{scene}\n\n"
        f"检测证据 JSON：\n{evidence_text}\n\n"
        "请按以下结构输出 Markdown：\n"
        "1. 结论摘要\n"
        "2. 关键风险发现\n"
        "3. 证据解读\n"
        "4. 处置建议\n"
        "5. 后续排查清单\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


@router.post("/generate")
def generate_report(payload: ReportRequest) -> Dict[str, str]:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置 DEEPSEEK_API_KEY")

    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    temperature = float(os.getenv("DEEPSEEK_TEMPERATURE", "0.2"))
    max_tokens = int(os.getenv("DEEPSEEK_MAX_TOKENS", "1800"))
    timeout = int(os.getenv("DEEPSEEK_TIMEOUT", "120"))

    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": _build_prompt(payload.scene, payload.evidence),
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"AI 报告服务请求失败: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"AI 报告服务返回错误: {response.status_code} {response.text[-500:]}",
        )

    data = response.json()
    try:
        content = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="AI 报告服务响应格式异常") from exc

    if payload.task_id:
        update_task_report(payload.task_id, content)

    return {
        "scene": payload.scene,
        "model": model,
        "report": content,
        "task_id": payload.task_id,
    }
