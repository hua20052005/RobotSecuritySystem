from __future__ import annotations

import json
import ipaddress
import socket
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import requests
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest

from backend.auth import optional_user
from backend.db import create_task
from core.feature_eng import pcap_to_dataframe

router = APIRouter(prefix="/api/side-channel", tags=["side-channel"])

FEATURE_DEFS: List[Dict[str, str]] = [
    {
        "key": "dst_ip_num",
        "label": "Destination IP (numeric)",
        "description": "Numeric mapping of destination IPs to highlight outliers by target clustering.",
    },
    {
        "key": "port",
        "label": "Destination Port",
        "description": "Service surface view; unusual ports or spikes often indicate scans or payload delivery.",
    },
    {
        "key": "size",
        "label": "Packet Size",
        "description": "Packet length sequence; useful with interval/entropy for side-channel modeling.",
    },
    {
        "key": "entropy",
        "label": "Payload Entropy",
        "description": "Higher entropy often maps to encrypted/compressed flows; lower values indicate cleartext patterns.",
    },
    {
        "key": "src_ip_num",
        "label": "Source IP (numeric)",
        "description": "Numeric mapping of source IPs to observe distribution, spoofing, or coordination.",
    },
    {
        "key": "interval",
        "label": "Send Interval",
        "description": "Time delta between packets from the same source; burst or jitter changes show anomalies.",
    },
]

DEFAULT_FEATURES = ["size", "interval", "port"]
ALLOWED_FEATURES = {item["key"] for item in FEATURE_DEFS}

# Optional public-IP lookup is intentionally isolated from the main analysis path.
_HTTP = requests.Session()
_HTTP.trust_env = False
IP_LOOKUP_LIMIT = 100
IPWHOIS_LOOKUP_LIMIT = 30
IP_API_FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting,query"

PORT_SERVICE_OVERRIDES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    502: "Modbus/TCP",
    554: "RTSP",
    1883: "MQTT",
    4840: "OPC UA",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    7400: "DDS/RTPS",
    7401: "DDS/RTPS",
    7402: "DDS/RTPS",
    8080: "HTTP alternate",
    8883: "MQTT over TLS",
    9090: "ROS bridge/WebSocket",
    11311: "ROS master",
}


class PublicLookupItem(BaseModel):
    ip: str
    scope: Optional[str] = None
    count: int = 0
    observed_as_src: int = 0
    observed_as_dst: int = 0
    ports: str = "-"


class PublicLookupRequest(BaseModel):
    items: List[PublicLookupItem] = Field(default_factory=list)


def _parse_features(raw: Optional[str]) -> List[str]:
    if not raw:
        return DEFAULT_FEATURES[:]

    raw = raw.strip()
    if not raw:
        return DEFAULT_FEATURES[:]

    if raw.startswith("["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="features must be valid JSON array")
        if not isinstance(data, list):
            raise HTTPException(status_code=400, detail="features must be a JSON array")
        features = [str(item).strip() for item in data if str(item).strip()]
    else:
        features = [item.strip() for item in raw.split(",") if item.strip()]

    if not features:
        return DEFAULT_FEATURES[:]

    invalid = [item for item in features if item not in ALLOWED_FEATURES]
    if invalid:
        raise HTTPException(status_code=400, detail=f"unsupported features: {', '.join(invalid)}")
    return features


def _ip_scope(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if parsed.is_private:
        return "private"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_reserved:
        return "reserved"
    if parsed.is_unspecified:
        return "unspecified"
    return "public"


def _ip_long(ip: str) -> Optional[int]:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    return int(parsed)


def _format_location(*parts: object) -> str:
    values = []
    for part in parts:
        text = str(part or "").strip()
        if text and text != "-":
            values.append(text)
    return " ".join(values) if values else "-"


def _service_name(port: object) -> str:
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return "unknown"
    if port_int <= 0:
        return "unknown"
    if port_int in PORT_SERVICE_OVERRIDES:
        return PORT_SERVICE_OVERRIDES[port_int]
    for proto in ("tcp", "udp"):
        try:
            return socket.getservbyport(port_int, proto).upper()
        except OSError:
            continue
    return "unknown"


def _ptr_lookup(ip: str) -> Optional[str]:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _lookup_ipwhois_ips(ips: List[str]) -> tuple[Dict[str, Dict[str, object]], Optional[str]]:
    lookup: Dict[str, Dict[str, object]] = {}
    error: Optional[str] = None
    for ip in ips[:IPWHOIS_LOOKUP_LIMIT]:
        try:
            response = _HTTP.get(f"http://ipwho.is/{ip}", timeout=4)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                lookup[ip] = data
        except requests.RequestException as exc:
            error = f"{type(exc).__name__}: {exc}"
        except ValueError as exc:
            error = f"invalid ipwho.is response: {exc}"
    return lookup, error


def _lookup_public_ips(ips: List[str]) -> tuple[Dict[str, Dict[str, object]], Dict[str, object]]:
    lookup: Dict[str, Dict[str, object]] = {}
    meta: Dict[str, object] = {
        "provider": "ip-api.com batch + ipwho.is + DNS PTR",
        "queried": 0,
        "limit": IP_LOOKUP_LIMIT,
        "error": None,
        "sources": ["ip-api.com", "ipwho.is", "PTR"],
    }

    public_ips = [ip for ip in ips if _ip_scope(ip) == "public"][:IP_LOOKUP_LIMIT]
    meta["queried"] = len(public_ips)
    if not public_ips:
        return lookup, meta

    try:
        response = _HTTP.post(
            "http://ip-api.com/batch",
            params={"fields": IP_API_FIELDS, "lang": "zh-CN"},
            json=public_ips,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("query"):
                    lookup[str(item["query"])] = item
    except requests.RequestException as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
    except ValueError as exc:
        meta["error"] = f"invalid lookup response: {exc}"

    ipwhois_lookup, ipwhois_error = _lookup_ipwhois_ips(public_ips)
    if ipwhois_error and not meta["error"]:
        meta["error"] = ipwhois_error

    for ip in public_ips:
        lookup.setdefault(ip, {})
        lookup[ip]["ptr"] = _ptr_lookup(ip)
        lookup[ip]["ipwhois"] = ipwhois_lookup.get(ip, {})

    return lookup, meta


def _format_location(*parts: object) -> str:
    values = []
    for part in parts:
        text = str(part or "").strip()
        if text and text != "-":
            values.append(text)
    return " ".join(values) if values else "-"


def _build_public_lookup_rows(items: List[PublicLookupItem]) -> Dict[str, object]:
    columns = [
        "ip",
        "ip_long",
        "scope",
        "count",
        "observed_as_src",
        "observed_as_dst",
        "ports",
        "ptr",
        "best_location",
        "ip_api_location",
        "ipwhois_location",
        "isp",
        "org",
        "asn",
        "risk_tags",
        "lookup_status",
    ]

    public_items = [item for item in items if _ip_scope(item.ip) == "public"]
    public_ips = [item.ip for item in public_items]
    lookup, meta = _lookup_public_ips(public_ips)

    rows: List[Dict[str, object]] = []
    for item in public_items:
        info = lookup.get(item.ip, {})
        ipwhois = info.get("ipwhois") if isinstance(info.get("ipwhois"), dict) else {}
        risk_tags = []
        if info.get("hosting"):
            risk_tags.append("hosting/datacenter")
        if info.get("proxy"):
            risk_tags.append("proxy/vpn/tor")
        if info.get("mobile"):
            risk_tags.append("mobile")

        ip_api_location = _format_location(info.get("country"), info.get("regionName"), info.get("city"))
        ipwhois_location = _format_location(ipwhois.get("country"), ipwhois.get("region"), ipwhois.get("city"))
        best_location = ip_api_location if ip_api_location != "-" else ipwhois_location

        status = info.get("status")
        if status == "success" or ipwhois.get("success") or info.get("ptr"):
            lookup_status = "success"
        elif status == "fail":
            lookup_status = str(info.get("message") or "fail")
        elif meta.get("error"):
            lookup_status = "lookup-error"
        else:
            lookup_status = "no-data"

        connection = ipwhois.get("connection") if isinstance(ipwhois.get("connection"), dict) else {}
        rows.append(
            {
                "ip": item.ip,
                "ip_long": _ip_long(item.ip) or "-",
                "scope": item.scope or _ip_scope(item.ip),
                "count": item.count,
                "observed_as_src": item.observed_as_src,
                "observed_as_dst": item.observed_as_dst,
                "ports": item.ports or "-",
                "ptr": info.get("ptr") or "-",
                "best_location": best_location,
                "ip_api_location": ip_api_location,
                "ipwhois_location": ipwhois_location,
                "isp": info.get("isp") or ipwhois.get("isp") or "-",
                "org": info.get("org") or connection.get("org") or "-",
                "asn": info.get("as") or connection.get("asn") or info.get("asname") or "-",
                "risk_tags": ", ".join(risk_tags) or "-",
                "lookup_status": lookup_status,
            }
        )

    return {"columns": columns, "rows": rows, "total": len(rows), "lookup": meta}


def _build_ip_port_profiles(df: pd.DataFrame) -> Dict[str, object]:
    columns = ["ip", "scope", "count", "observed_as_src", "observed_as_dst", "ports"]
    if df.empty:
        return {"columns": columns, "rows": [], "total": 0}

    profiles: Dict[str, Dict[str, object]] = {}

    def ensure(ip: str) -> Dict[str, object]:
        entry = profiles.setdefault(
            ip,
            {
                "ip": ip,
                "scope": _ip_scope(ip),
                "observed_as_src": 0,
                "observed_as_dst": 0,
                "_ports": set(),
            },
        )
        return entry

    for row in df[["src", "dst", "port"]].fillna("").to_dict("records"):
        src = str(row.get("src") or "").strip()
        dst = str(row.get("dst") or "").strip()
        port_raw = row.get("port")
        try:
            port = int(float(port_raw)) if str(port_raw).strip() else 0
        except (TypeError, ValueError):
            port = 0

        if src:
            ensure(src)["observed_as_src"] = int(ensure(src)["observed_as_src"]) + 1
        if dst:
            dst_entry = ensure(dst)
            dst_entry["observed_as_dst"] = int(dst_entry["observed_as_dst"]) + 1
            if port > 0:
                dst_entry["_ports"].add(port)

    ordered_ips = sorted(
        profiles,
        key=lambda ip: (
            -(int(profiles[ip]["observed_as_src"]) + int(profiles[ip]["observed_as_dst"])),
            ip,
        ),
    )

    rows: List[Dict[str, object]] = []
    for ip in ordered_ips:
        entry = profiles[ip]
        ports = sorted(entry["_ports"])
        rows.append(
            {
                "ip": ip,
                "scope": entry["scope"],
                "count": int(entry["observed_as_src"]) + int(entry["observed_as_dst"]),
                "observed_as_src": entry["observed_as_src"],
                "observed_as_dst": entry["observed_as_dst"],
                "ports": ", ".join(str(port) for port in ports) or "-",
            }
        )

    return {"columns": columns, "rows": rows, "total": len(rows)}


def _build_port_profiles(df: pd.DataFrame) -> Dict[str, object]:
    columns = ["port", "service", "count", "src_ips", "dst_ips"]
    if df.empty or "port" not in df.columns:
        return {"columns": columns, "rows": [], "total": 0}

    port_rows: List[Dict[str, object]] = []
    grouped = df.copy()
    grouped["port"] = grouped["port"].fillna(0)
    grouped["port"] = grouped["port"].apply(lambda value: int(float(value)) if str(value).strip() else 0)

    for port_value, group in grouped.groupby("port", dropna=False):
        port_int = int(port_value) if str(port_value).strip() else 0
        if port_int <= 0:
            continue
        src_ips = group["src"].fillna("").astype(str).str.strip()
        dst_ips = group["dst"].fillna("").astype(str).str.strip()
        unique_src = sorted(ip for ip in src_ips.unique().tolist() if ip)
        unique_dst = sorted(ip for ip in dst_ips.unique().tolist() if ip)
        port_rows.append(
            {
                "port": port_int,
                "service": _service_name(port_int),
                "count": int(len(group)),
                "src_ips": ", ".join(unique_src[:10]) or "-",
                "dst_ips": ", ".join(unique_dst[:10]) or "-",
            }
        )

    port_rows.sort(key=lambda row: (-int(row["count"]), int(row["port"])))
    return {"columns": columns, "rows": port_rows, "total": len(port_rows)}


def _build_table(df: pd.DataFrame, limit: int) -> Dict[str, object]:
    table_cols = [
        col
        for col in [
            "idx",
            "src",
            "dst",
            "port",
            "size",
            "interval",
            "entropy",
            "anomaly_score",
            "src_ip_num",
            "dst_ip_num",
            "timestamp",
            "raw_hex_head",
        ]
        if col in df.columns
    ]
    if not table_cols:
        return {"columns": [], "rows": [], "total": int(len(df)), "limit": int(limit)}

    trimmed = df[table_cols].head(limit).copy()
    trimmed = trimmed.fillna("")
    if "anomaly_score" in trimmed.columns:
        trimmed["anomaly_score"] = trimmed["anomaly_score"].round(6)
    return {
        "columns": table_cols,
        "rows": trimmed.to_dict("records"),
        "total": int(len(df)),
        "limit": int(limit),
    }


@router.get("/features")
def list_features() -> Dict[str, object]:
    return {
        "defaults": DEFAULT_FEATURES,
        "features": FEATURE_DEFS,
    }


@router.post("/public-lookup")
def lookup_public_ips(payload: PublicLookupRequest) -> Dict[str, object]:
    return _build_public_lookup_rows(payload.items)


@router.post("/analyze")
async def analyze_side_channel(
    file: UploadFile = File(...),
    features: Optional[str] = Form(None),
    contamination: float = Form(0.06),
    target_ip: Optional[str] = Form(None),
    max_points: int = Form(5000),
    anomaly_limit: int = Form(200),
    user: Optional[Dict[str, object]] = Depends(optional_user),
) -> Dict[str, object]:
    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=400, detail="only .pcap or .pcapng is supported")

    if contamination <= 0 or contamination >= 0.5:
        raise HTTPException(status_code=400, detail="contamination must be between 0 and 0.5")

    max_points = max(200, min(int(max_points), 20000))
    anomaly_limit = max(50, min(int(anomaly_limit), 1000))

    feature_list = _parse_features(features)

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty upload")

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        temp_path = Path(tmp.name)

    try:
        df = pcap_to_dataframe(str(temp_path))
    finally:
        temp_path.unlink(missing_ok=True)

    if df.empty:
        run_id = uuid.uuid4().hex[:10]
        result = {
            "run_id": run_id,
            "summary": {"total": 0, "abnormal": 0, "ratio": 0.0, "avg_score": 0.0},
            "features": {"x": None, "y": None},
            "scatter": {"points": [], "sampled": False, "total_points": 0},
            "histogram": {"bins": [], "counts": []},
            "anomalies": {"columns": [], "rows": [], "total": 0, "limit": anomaly_limit},
            "target_hits": {"columns": [], "rows": [], "total": 0, "limit": anomaly_limit},
            "ip_port_profiles": _build_ip_port_profiles(df),
            "port_profiles": _build_port_profiles(df),
        }
        create_task(
            task_id=run_id,
            module="side-channel",
            title=f"侧信道分析 - {file.filename or run_id}",
            parameters={"filename": file.filename, "features": feature_list, "contamination": contamination, "target_ip": target_ip},
            summary=result["summary"],
            result=result,
            files={},
            user_id=int(user["id"]) if user else None,
        )
        return result

    model = IsolationForest(contamination=contamination, random_state=42)
    df = df.copy()
    df["anomaly_label"] = model.fit_predict(df[feature_list])
    df["anomaly_score"] = model.decision_function(df[feature_list])

    anomalies = df[df["anomaly_label"] == -1].copy()
    anomalies.sort_values(by="anomaly_score", inplace=True)

    total = int(len(df))
    abnormal = int(len(anomalies))
    ratio = float(abnormal / total) if total else 0.0
    avg_score = float(df["anomaly_score"].mean()) if total else 0.0

    x_axis = feature_list[0]
    y_axis = feature_list[1] if len(feature_list) > 1 else "idx"
    if y_axis not in df.columns:
        df["idx"] = df.index
        y_axis = "idx"

    if total > max_points:
        sampled = df.sample(n=max_points, random_state=42)
        sampled_flag = True
    else:
        sampled = df
        sampled_flag = False

    scatter_points = sampled[[x_axis, y_axis, "anomaly_score"]].copy()
    scatter_payload = scatter_points.round(6).values.tolist()

    scores = df["anomaly_score"].astype(float).values
    counts, edges = np.histogram(scores, bins=28)
    centers = ((edges[:-1] + edges[1:]) / 2.0).tolist()

    target_ip = (target_ip or "").strip() or None
    if target_ip:
        target_hits = anomalies[anomalies.get("dst", "") == target_ip].copy()
    else:
        target_hits = anomalies.iloc[0:0].copy()

    run_id = uuid.uuid4().hex[:10]
    result = {
        "run_id": run_id,
        "summary": {
            "total": total,
            "abnormal": abnormal,
            "ratio": ratio,
            "avg_score": avg_score,
        },
        "features": {"x": x_axis, "y": y_axis},
        "scatter": {
            "points": scatter_payload,
            "sampled": sampled_flag,
            "total_points": total,
        },
        "histogram": {
            "bins": centers,
            "counts": counts.tolist(),
        },
        "anomalies": _build_table(anomalies, anomaly_limit),
        "target_hits": _build_table(target_hits, anomaly_limit),
        "ip_port_profiles": _build_ip_port_profiles(df),
        "port_profiles": _build_port_profiles(df),
    }
    create_task(
        task_id=run_id,
        module="side-channel",
        title=f"侧信道分析 - {file.filename or run_id}",
        parameters={"filename": file.filename, "features": feature_list, "contamination": contamination, "target_ip": target_ip},
        summary=result["summary"],
        result=result,
        files={},
        user_id=int(user["id"]) if user else None,
    )
    return result
