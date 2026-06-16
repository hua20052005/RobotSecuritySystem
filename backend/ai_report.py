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

# 直连 Session：忽略系统/环境变量里的代理（如 HTTP_PROXY=127.0.0.1:7890），
# 避免代理软件未运行时调用 AI 报告服务被甩到本地代理端口而超时。
_HTTP = requests.Session()
_HTTP.trust_env = False


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
        "报告要专业、可交付、不要编造证据。\n"
        "严格遵守以下输出规范：\n"
        "- 直接输出报告正文，第一行即为标题，禁止任何开场白、寒暄或结束语"
        "（例如“好的”“作为……专家”“以下是……”“希望对您有帮助”等一律不要）；\n"
        "- 不要用代码块（```）把整篇报告包裹起来；\n"
        "- 各章节使用 Markdown 二级标题（以 `## ` 开头）；\n"
        "- 表格必须使用标准 GFM 紧凑格式，表头与各数据行之间、数据行与数据行之间"
        "都不得插入空行。"
    )
    user = (
        f"检测场景：{scene}\n\n"
        f"检测证据 JSON：\n{evidence_text}\n\n"
        "请按以下结构输出 Markdown，每节使用 `## ` 标题：\n"
        "## 1. 结论摘要\n"
        "## 2. 关键风险发现\n"
        "## 3. 证据解读\n"
        "## 4. 处置建议\n"
        "## 5. 后续排查清单\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _clean_report(text: str) -> str:
    """清洗模型输出：去掉代码围栏、开场白寒暄，以及 GFM 表格行间的空行。

    即使 prompt 已明确要求，模型仍可能偶发地加客套话或在表格里插空行，
    这里做确定性兜底，保证前端 Markdown 渲染干净、表格不断行。
    """
    text = text.strip()

    # 1) 去掉整篇被 ```markdown ... ``` 包裹的代码围栏
    if text.startswith("```"):
        lines0 = text.split("\n")
        lines0 = lines0[1:]  # 丢掉开头的 ``` 行
        if lines0 and lines0[-1].strip().startswith("```"):
            lines0 = lines0[:-1]
        text = "\n".join(lines0).strip()

    lines = text.split("\n")

    # 2) 去掉正文前的寒暄开场白：定位第一个 Markdown 标题（# 开头），
    #    若其之前存在明显的客套/分隔线内容，则整体裁掉
    heading_idx = next(
        (i for i, ln in enumerate(lines) if ln.lstrip().startswith("#")), None
    )
    if heading_idx and heading_idx > 0:
        preamble = "\n".join(lines[:heading_idx])
        if any(token in preamble for token in ("好的", "作为", "以下是", "报告", "---", "***")):
            lines = lines[heading_idx:]

    # 3) 删除表格行之间的空行（前后均为 | 开头的行时，中间空行会断表）
    cleaned: List[str] = []
    for i, ln in enumerate(lines):
        if ln.strip() == "":
            prev = cleaned[-1].lstrip() if cleaned else ""
            nxt = ""
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    nxt = lines[j].lstrip()
                    break
            if prev.startswith("|") and nxt.startswith("|"):
                continue
        cleaned.append(ln)

    return "\n".join(cleaned).strip()


@router.post("/generate")
def generate_report(payload: ReportRequest) -> Dict[str, str]:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置 DEEPSEEK_API_KEY")

    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    temperature = float(os.getenv("DEEPSEEK_TEMPERATURE", "0.2"))
    max_tokens = int(os.getenv("DEEPSEEK_MAX_TOKENS", "3000"))
    timeout = int(os.getenv("DEEPSEEK_TIMEOUT", "120"))

    try:
        response = _HTTP.post(
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

    content = _clean_report(content)

    if payload.task_id:
        update_task_report(payload.task_id, content)

    return {
        "scene": payload.scene,
        "model": model,
        "report": content,
        "task_id": payload.task_id,
    }
