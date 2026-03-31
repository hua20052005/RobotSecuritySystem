from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict

import requests

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
except Exception:  # pragma: no cover
    A4 = None
    pdfmetrics = None
    UnicodeCIDFont = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None
    getSampleStyleSheet = None

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE_PATH = PROJECT_ROOT / ".env"


def _load_env_file_fallback(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            os.environ[key] = value


def _ensure_env_loaded() -> None:
    if load_dotenv is not None:
        try:
            load_dotenv(dotenv_path=ENV_FILE_PATH, override=True)
            return
        except Exception:
            pass

    _load_env_file_fallback(ENV_FILE_PATH)


def get_deepseek_defaults() -> Dict[str, str]:
    _ensure_env_loaded()
    return {
        "api_key": os.getenv("DEEPSEEK_API_KEY", ""),
        "base_url": os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        "model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        "temperature": os.getenv("DEEPSEEK_TEMPERATURE", "0.2"),
        "max_tokens": os.getenv("DEEPSEEK_MAX_TOKENS", "1800"),
        "timeout": os.getenv("DEEPSEEK_TIMEOUT", "120"),
    }


def _safe_float(value: str, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _safe_int(value: str, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def get_deepseek_runtime_config() -> Dict[str, Any]:
    defaults = get_deepseek_defaults()
    return {
        "api_key": defaults.get("api_key", "").strip(),
        "base_url": defaults.get("base_url", "https://api.deepseek.com").strip() or "https://api.deepseek.com",
        "model": defaults.get("model", "deepseek-chat").strip() or "deepseek-chat",
        "temperature": _safe_float(defaults.get("temperature", "0.2"), 0.2),
        "max_tokens": _safe_int(defaults.get("max_tokens", "1800"), 1800),
        "timeout": _safe_int(defaults.get("timeout", "120"), 120),
    }


def _build_prompt(scene_name: str, evidence: Dict[str, Any]) -> str:
    evidence_text = json.dumps(evidence, ensure_ascii=False, indent=2, default=str)
    return (
        f"你是一名机器人网络安全高级分析师。请对场景“{scene_name}”输出一份中文 Markdown 报告。\n"
        "必须基于给定证据，不得编造不存在的数据，并标注结论依据。\n\n"
        "请严格按以下结构输出（一级/二级标题保持一致）：\n"
        "## AI研判结果\n"
        "- 给出整体风险等级（低/中/高/严重）与核心判断。\n"
        "- 给出 3~5 条最关键结论。\n\n"
        "## 异常证据链\n"
        "- 按时间或因果顺序组织，覆盖触发条件、关键异常包/事件、分值变化与规则命中。\n"
        "- 每条证据需包含“证据来源字段”。\n\n"
        "## 原始流量内容\n"
        "### 异常时序图\n"
        "- 解释异常峰值区间、持续时长、与基线差异。\n"
        "### 指令详情\n"
        "- 提炼可疑协议、端口、目标、raw_hex_head/规则命中等关键指令线索。\n"
        "### 漏洞分析\n"
        "- 结合证据推断可能漏洞类型、攻击路径、利用前提与不确定性。\n"
        "### 危害预测价值\n"
        "- 说明“为漏洞验证提供精准指导”的可执行建议，至少 5 条。\n"
        "- 给出下一步验证优先级（P0/P1/P2）。\n\n"
        "补充要求：\n"
        "- 输出末尾追加“## 置信度与局限性”。\n"
        "- 若证据不足，明确写出缺口与建议补采集字段。\n\n"
        "以下是证据 JSON：\n"
        f"{evidence_text}"
    )


def generate_security_report(
    scene_name: str,
    evidence: Dict[str, Any],
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
) -> str:
    if not api_key.strip():
        raise ValueError("未配置 DeepSeek API Key，请在项目根目录 .env 中填写 DEEPSEEK_API_KEY。")

    endpoint = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "你是严谨的网络安全分析助手，输出必须结构化、可追溯、可执行。",
            },
            {
                "role": "user",
                "content": _build_prompt(scene_name, evidence),
            },
        ],
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "stream": False,
    }

    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=max(10, int(timeout)))
    except requests.RequestException as exc:
        raise RuntimeError(f"调用 DeepSeek 失败: {exc}") from exc

    if resp.status_code != 200:
        detail = resp.text[:500]
        raise RuntimeError(f"DeepSeek 返回异常状态码 {resp.status_code}: {detail}")

    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("DeepSeek 响应中没有 choices 字段。")

    content = choices[0].get("message", {}).get("content", "")
    if not content.strip():
        raise RuntimeError("DeepSeek 返回内容为空。")
    return content.strip()


def markdown_to_plain_text(markdown_text: str) -> str:
    text = markdown_text
    text = re.sub(r"```[\s\S]*?```", "", text)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*+]\s+", "- ", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def build_report_html(title: str, markdown_report: str) -> str:
    plain = markdown_to_plain_text(markdown_report)
    escaped = (
        plain.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br>")
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title>"
        "<style>body{font-family:'Microsoft YaHei',sans-serif;line-height:1.65;padding:24px;color:#0f172a;}"
        "h1{font-size:28px;margin:0 0 16px;}"
        "</style></head><body>"
        f"<h1>{title}</h1><div>{escaped}</div></body></html>"
    )


def build_report_pdf_bytes(title: str, markdown_report: str) -> bytes:
    if not all([A4, pdfmetrics, UnicodeCIDFont, Paragraph, SimpleDocTemplate, Spacer, getSampleStyleSheet]):
        raise RuntimeError("未安装 reportlab，无法导出 PDF。请先安装依赖后重试。")

    from io import BytesIO

    plain = markdown_to_plain_text(markdown_report)
    buffer = BytesIO()

    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        font_name = "STSong-Light"
    except Exception:
        font_name = "Helvetica"

    styles = getSampleStyleSheet()
    title_style = styles["Heading1"]
    body_style = styles["BodyText"]
    title_style.fontName = font_name
    body_style.fontName = font_name
    body_style.leading = 18

    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    story = [Paragraph(title, title_style), Spacer(1, 12)]

    for line in plain.splitlines():
        safe_line = (
            line.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .strip()
        )
        if not safe_line:
            story.append(Spacer(1, 8))
            continue
        story.append(Paragraph(safe_line, body_style))

    doc.build(story)
    return buffer.getvalue()
