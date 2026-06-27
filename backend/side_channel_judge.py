"""侧信道异常的"二次判断"模块（分组研判版）。

第一段(side_channel_api 的 IsolationForest)只负责**排序召回**：把可疑的包按
异常分排出来，捞前 N 个候选。它不擅长回答"这到底是不是真异常"——所以它会把
SSDP/mDNS/DNS 这类少数派背景流量也标红。

本模块是第二段**精判**，但不逐包调 LLM，而是**分组研判**：
  1) 聚合：把候选包按 (源IP → 目的IP) 聚成若干"流分组"，端口/包数/熵等汇总成概览。
     几十上百个包通常坍缩成十几个分组，端口扫描会坍缩成"一个源打很多端口"的一组。
  2) 规则层（确定、可复现）：高置信度的背景流量(多播/广播/链路本地)判 benign，
     明显的扫描模式(一个流触达很多端口)判 risk。
  3) LLM 层：把**所有分组的概览**一次性交给 LLM"大致看一遍"，给出总体结论，并对
     规则未决的分组逐组判定。temperature=0 保证可复现。一次分析仅 1 次 LLM 调用。
  4) 汇总：任一分组判为 risk → 整个文件判定"有风险"(实现"单包异常→报整体")。

只提升 precision，不改变 recall——召回仍取决于第一段排序，候选里没有的东西这里
永远看不到。所以前端应把 anomaly_limit 给得大方些。
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.side_channel_api import _ip_scope, _service_name

load_dotenv()

router = APIRouter(prefix="/api/side-channel", tags=["side-channel"])

# 直连 Session：忽略系统代理，避免代理未运行时请求被甩到本地端口超时（与 ai_report 一致）。
_HTTP = requests.Session()
_HTTP.trust_env = False

# 扫描判定阈值：一个 (源→目的) 流触达多少个不同端口才算扫描。
_SCAN_PORT_THRESHOLD = 10
_SCAN_HINT_THRESHOLD = 5
# 一次最多送多少个分组给 LLM（分组通常很少，做个上限防极端情况）。
_MAX_GROUPS_TO_LLM = 40


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class JudgeCandidate(BaseModel):
    # 数值字段用 Any 接收再在代码里强转，避免前端传来空串/None 时 pydantic 校验失败。
    idx: Any = 0
    src: str = ""
    dst: str = ""
    port: Any = 0
    size: Any = 0
    interval: Any = 0
    entropy: Any = 0
    anomaly_score: Any = 0
    timestamp: Any = 0
    raw_hex_head: str = ""


class JudgeRequest(BaseModel):
    candidates: List[JudgeCandidate] = Field(default_factory=list)
    target_ip: Optional[str] = None
    scene: str = "机器人侧信道流量异常二次判断"
    use_llm: bool = True


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def _f(value: Any) -> float:
    try:
        text = str(value).strip()
        return float(text) if text else 0.0
    except (TypeError, ValueError):
        return 0.0


def _i(value: Any) -> int:
    try:
        text = str(value).strip()
        return int(float(text)) if text else 0
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# 聚合：候选包 → (源→目的) 流分组
# --------------------------------------------------------------------------- #
def _group_candidates(cands: List[JudgeCandidate], target_ip: Optional[str]) -> List[Dict[str, Any]]:
    groups: Dict[tuple, Dict[str, Any]] = {}
    for c in cands:
        key = (c.src, c.dst)
        g = groups.get(key)
        if g is None:
            g = {
                "src": c.src,
                "dst": c.dst,
                "scope": _ip_scope(c.dst),
                "count": 0,
                "_ports": set(),
                "size_min": None,
                "size_max": None,
                "entropy_max": 0.0,
                "interval_max": 0.0,
                "is_target": bool(target_ip and c.dst == target_ip),
            }
            groups[key] = g
        port = _i(c.port)
        size = _i(c.size)
        entropy = _f(c.entropy)
        interval = _f(c.interval)
        g["count"] += 1
        if port > 0:
            g["_ports"].add(port)
        g["size_min"] = size if g["size_min"] is None else min(g["size_min"], size)
        g["size_max"] = size if g["size_max"] is None else max(g["size_max"], size)
        g["entropy_max"] = max(g["entropy_max"], entropy)
        g["interval_max"] = max(g["interval_max"], interval)

    result: List[Dict[str, Any]] = []
    for g in groups.values():
        ports = sorted(g.pop("_ports"))
        services = sorted({_service_name(p) for p in ports} - {"unknown"})
        g["ports"] = ports
        g["port_count"] = len(ports)
        g["services"] = services
        g["hints"] = _group_hints(g)
        result.append(g)

    # 按"可疑程度"粗排：端口扇出大的、命中目标 IP 的、包多的排前面
    result.sort(key=lambda x: (-x["port_count"], -int(x["is_target"]), -x["count"]))
    return result


def _group_hints(g: Dict[str, Any]) -> List[str]:
    hints: List[str] = []
    if g["is_target"]:
        hints.append("指向可疑目标IP")
    if g["port_count"] >= _SCAN_HINT_THRESHOLD:
        hints.append(f"触达{g['port_count']}个端口")
    if g["scope"] == "public":
        hints.append("目的为公网")
    if g["entropy_max"] >= 7.0:
        hints.append("高熵载荷")
    if g["size_max"] is not None and g["size_max"] <= 80:
        hints.append("均为小包")
    if 53 in g["ports"]:
        hints.append("DNS查询")
    return hints


# --------------------------------------------------------------------------- #
# 规则层（只在几乎确定时下结论，否则返回 None 交给 LLM）
# --------------------------------------------------------------------------- #
def _rule_judge_group(g: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    dst = g["dst"]
    scope = g["scope"]
    ports = g["ports"]

    # —— 白名单：高置信度背景流量 → benign —— #
    if dst == "239.255.255.250" or 1900 in ports:
        return _verdict(False, "rule", "SSDP 设备发现多播，局域网正常广播", 0.97)
    if dst == "224.0.0.251" or 5353 in ports:
        return _verdict(False, "rule", "mDNS 本地名称解析多播，正常", 0.97)
    if scope == "multicast":
        return _verdict(False, "rule", f"多播地址 {dst}，通常为发现/广播类正常流量", 0.9)
    if scope == "link-local":
        return _verdict(False, "rule", f"链路本地地址 {dst}，本地自动配置流量", 0.85)
    if scope in ("loopback", "unspecified"):
        return _verdict(False, "rule", f"{scope} 地址，非外部威胁", 0.8)
    if dst.endswith(".255"):
        return _verdict(False, "rule", "广播地址，正常局域网广播", 0.82)

    # —— 黑名单：高置信度恶意模式 → risk —— #
    if g["port_count"] >= _SCAN_PORT_THRESHOLD:
        return _verdict(
            True, "rule",
            f"源 {g['src']} 对 {dst} 触达 {g['port_count']} 个不同端口，呈端口扫描特征",
            0.85,
        )

    return None  # 规则拿不准 → 交给 LLM


def _verdict(is_risk: bool, source: str, reason: str, confidence: float) -> Dict[str, Any]:
    return {
        "is_risk": bool(is_risk),
        "verdict_source": source,   # rule | llm | default
        "reason": reason,
        "confidence": round(float(confidence), 3),
    }


# --------------------------------------------------------------------------- #
# LLM 层（一次性研判所有分组）
# --------------------------------------------------------------------------- #
def _deepseek_config() -> Optional[Dict[str, Any]]:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        return None
    return {
        "api_key": api_key,
        "base_url": os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
        "model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        "timeout": int(os.getenv("DEEPSEEK_TIMEOUT", "120")),
    }


def _group_for_llm(gid: int, g: Dict[str, Any], rule_status: str) -> Dict[str, Any]:
    return {
        "gid": gid,
        "src": g["src"],
        "dst": g["dst"],
        "dst_scope": g["scope"],
        "packets": g["count"],
        "ports": g["ports"][:20],
        "port_count": g["port_count"],
        "services": g["services"][:6],
        "size_range": [g["size_min"], g["size_max"]],
        "entropy_max": round(g["entropy_max"], 2),
        "rule_status": rule_status,   # benign | risk | undecided
        "hints": g["hints"],
    }


def _extract_json_object(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start:end + 1]
    return json.loads(text)


_LLM_SYSTEM = (
    "你是机器人网络安全分析助手。你会收到一份“可疑流量分组概览”——初筛模型标记出的异常包"
    "已按 (源IP→目的IP) 聚合成若干组，并附规则预判(rule_status)与上下文线索(hints)。"
    "请你整体研判，不要逐包纠结：\n"
    "- 综合所有分组给出一句总体结论(是否存在真实安全风险)；\n"
    "- 对 rule_status 为 \"undecided\" 的分组，逐组判定 is_risk(true=风险/false=正常背景)；\n"
    "- SSDP/mDNS/正常DNS查询/普通网页访问等为正常背景(false)；端口扫描、陌生源注入控制流、"
    "针对可疑目标IP的反复试探、异常小包高频探测等为风险(true)；\n"
    "- 只依据给出的信息，不要编造；拿不准时倾向 false 并调低 confidence。\n"
    "严格只输出一个 JSON 对象，格式：\n"
    '{"overall_risk": <bool>, "assessment": "<不超过120字中文总体结论>", '
    '"groups": [{"gid": <int>, "is_risk": <bool>, "reason": "<不超过40字>", "confidence": <0~1小数>}]}\n'
    "不要输出 JSON 以外的任何文字，不要用代码块包裹。"
)


def _llm_assess(payload: List[Dict[str, Any]], scene: str, target_ip: Optional[str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    user = (
        f"场景：{scene}\n"
        f"可疑目标IP：{target_ip or '无'}\n"
        f"分组概览(JSON)：\n{json.dumps(payload, ensure_ascii=False)}"
    )
    response = _HTTP.post(
        f"{cfg['base_url']}/chat/completions",
        headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"},
        json={
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": _LLM_SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        },
        timeout=cfg["timeout"],
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    parsed = _extract_json_object(content)

    verdicts: Dict[int, Dict[str, Any]] = {}
    for item in parsed.get("groups", []) if isinstance(parsed, dict) else []:
        if isinstance(item, dict) and "gid" in item:
            verdicts[_i(item.get("gid"))] = _verdict(
                bool(item.get("is_risk")),
                "llm",
                str(item.get("reason") or "").strip()[:60] or "（无理由）",
                _f(item.get("confidence")),
            )
    return {
        "overall_risk": bool(parsed.get("overall_risk")) if isinstance(parsed, dict) else False,
        "assessment": (str(parsed.get("assessment")).strip()[:200] if isinstance(parsed, dict) and parsed.get("assessment") else ""),
        "verdicts": verdicts,
    }


def _fallback_assessment(groups: List[Dict[str, Any]]) -> str:
    risk = [g for g in groups if g["verdict"]["is_risk"]]
    if not risk:
        return "未发现明确风险分组，候选均为常见背景流量（多播/DNS/网页等），判定为正常。"
    top = risk[0]
    return (
        f"发现 {len(risk)} 个风险分组，最可疑为 {top['src']} → {top['dst']}"
        f"（{top['verdict']['reason']}）。建议重点核查。"
    )


# --------------------------------------------------------------------------- #
# 接口
# --------------------------------------------------------------------------- #
@router.post("/judge")
def judge_candidates(payload: JudgeRequest) -> Dict[str, Any]:
    cands = payload.candidates
    if not cands:
        return {
            "overall_risk": False,
            "assessment": "无异常候选包，无需二次判断。",
            "groups": [],
            "summary": {
                "total_candidates": 0, "total_groups": 0,
                "risk_groups": 0, "benign_groups": 0,
                "risk_packets": 0, "benign_packets": 0,
                "rule_decided_groups": 0, "llm_decided_groups": 0,
                "overall_risk": False,
            },
            "llm": {"used": False, "model": None, "error": None},
        }

    target_ip = (payload.target_ip or "").strip() or None
    groups = _group_candidates(cands, target_ip)

    # 规则层
    pending: List[int] = []
    for gid, g in enumerate(groups):
        rule_result = _rule_judge_group(g)
        if rule_result is not None:
            g["verdict"] = rule_result
        else:
            g["verdict"] = None
            pending.append(gid)

    llm_meta: Dict[str, Any] = {"used": False, "model": None, "error": None}
    llm_overall: Optional[bool] = None
    llm_assessment = ""

    # LLM 层：一次性把所有分组概览交给 LLM 研判（含 rule_status 作为上下文）
    if payload.use_llm:
        cfg = _deepseek_config()
        if cfg is None:
            llm_meta["error"] = "未配置 DEEPSEEK_API_KEY，规则未决项给保守默认值"
        else:
            llm_meta["model"] = cfg["model"]
            try:
                llm_payload = []
                for gid, g in enumerate(groups[:_MAX_GROUPS_TO_LLM]):
                    status = "undecided" if g["verdict"] is None else ("risk" if g["verdict"]["is_risk"] else "benign")
                    llm_payload.append(_group_for_llm(gid, g, status))
                assessment = _llm_assess(llm_payload, payload.scene, target_ip, cfg)
                for gid in pending:
                    if gid in assessment["verdicts"]:
                        groups[gid]["verdict"] = assessment["verdicts"][gid]
                llm_overall = assessment["overall_risk"]
                llm_assessment = assessment["assessment"]
                llm_meta["used"] = True
            except Exception as exc:  # noqa: BLE001 — LLM 失败不应整体 500，降级到默认值
                llm_meta["error"] = f"{type(exc).__name__}: {exc}"

    # 兜底：仍未决的分组给保守默认值并如实标注
    for g in groups:
        if g["verdict"] is None:
            g["verdict"] = _verdict(False, "default", "未进入二次判断，建议人工复核", 0.3)

    # 组装输出分组
    out_groups: List[Dict[str, Any]] = []
    for g in groups:
        v = g["verdict"]
        out_groups.append({
            "src": g["src"],
            "dst": g["dst"],
            "scope": g["scope"],
            "packets": g["count"],
            "port_count": g["port_count"],
            "ports": ", ".join(str(p) for p in g["ports"][:12]) + ("…" if g["port_count"] > 12 else ""),
            "services": ", ".join(g["services"][:6]) or "-",
            "hints": ", ".join(g["hints"]) or "-",
            "is_risk": v["is_risk"],
            "verdict_source": v["verdict_source"],
            "reason": v["reason"],
            "confidence": v["confidence"],
        })

    # 整体结论：以分组判定为准（任一 risk → 有风险），与 LLM 总体结论取并集兜底
    risk_groups = [g for g in out_groups if g["is_risk"]]
    overall_risk = bool(risk_groups) or bool(llm_overall)

    assessment_text = llm_assessment or _fallback_assessment(groups)

    risk_packets = sum(g["packets"] for g in out_groups if g["is_risk"])
    return {
        "overall_risk": overall_risk,
        "assessment": assessment_text,
        "groups": out_groups,
        "summary": {
            "total_candidates": len(cands),
            "total_groups": len(out_groups),
            "risk_groups": len(risk_groups),
            "benign_groups": len(out_groups) - len(risk_groups),
            "risk_packets": risk_packets,
            "benign_packets": len(cands) - risk_packets,
            "rule_decided_groups": sum(1 for g in out_groups if g["verdict_source"] == "rule"),
            "llm_decided_groups": sum(1 for g in out_groups if g["verdict_source"] == "llm"),
            "overall_risk": overall_risk,
        },
        "llm": llm_meta,
    }
