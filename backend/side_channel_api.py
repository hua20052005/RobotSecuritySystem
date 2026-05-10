from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
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
