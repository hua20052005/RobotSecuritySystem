"""ET-BERT 双粒度流量检测 API"""

from __future__ import annotations

import logging
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

PACKET_LABELS = {
    0: "正常",
    1: "指令码异常",
    2: "参数值异常",
    3: "格式违规",
}
FLOW_LABELS = {
    0: "正常流",
    1: "注入流异常",
    2: "速率泛洪",
    3: "方向振荡",
    4: "指令码扫描",
}
MODEL_DEFS = {
    "packet": {
        "labels_num": 4,
        "labels": PACKET_LABELS,
        "type": "packet",
    },
    "flow": {
        "labels_num": 5,
        "labels": FLOW_LABELS,
        "type": "flow",
    },
}


def _service():
    # PyTorch is optional and expensive; loading it during app import can take down
    # every unrelated detector when the local binary runtime is incompatible.
    from backend.etbert_api.etbert_service import etbert

    return etbert

RUN_DIR = Path(__file__).resolve().parents[2] / "data" / "etbert_runs"
RUN_DIR.mkdir(parents=True, exist_ok=True)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _run_isolated(operation: str, model_key: str, input_path: Path, max_packets: int):
    output_path = RUN_DIR / f"{input_path.stem}_{operation}.json"
    cmd = [
        sys.executable,
        "-m",
        "backend.etbert_api.worker",
        operation,
        model_key,
        str(input_path),
        str(max_packets),
        str(output_path),
    ]
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    proc = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        creationflags=creationflags,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        raise RuntimeError(
            f"ET-BERT worker exited with code {proc.returncode}"
            + (f": {detail}" if detail else "")
        )
    if not output_path.exists():
        raise RuntimeError("ET-BERT worker did not produce a result file")
    return json.loads(output_path.read_text(encoding="utf-8"))


def detect_path(input_path: Path, model_key: str, max_packets: int):
    if model_key not in MODEL_DEFS:
        raise ValueError(f"unsupported ET-BERT model: {model_key}")
    weight_path = PROJECT_ROOT / "ET-BERT-main" / "models" / f"{model_key}_finetune.bin"
    if not weight_path.exists():
        from backend.payload_fallback import detect_with_ensemble

        return detect_with_ensemble(input_path, max_packets)
    run_id = uuid.uuid4().hex[:10]
    result = _run_isolated("detect", model_key, input_path, max_packets)
    low_conf = [row for row in result["predictions"] if row["confidence"] < 50]
    return {
        "run_id": run_id,
        "model": model_key,
        "model_type": MODEL_DEFS[model_key]["type"],
        "total_samples": result["total_samples"],
        "summary": result["summary"],
        "abnormal_ratio": result["abnormal_ratio"],
        "low_confidence_count": len(low_conf),
        "low_confidence_samples": low_conf[:10],
        "proto_stats": result["proto_stats"],
        "predictions": result["predictions"][:100],
    }

app = FastAPI(title="ET-BERT Detection API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "etbert-api"}


@app.get("/models")
def list_models():
    """列出可用的微调模型"""
    result = {}
    for key, cfg in MODEL_DEFS.items():
        result[key] = {
            "type": cfg["type"],
            "labels": cfg["labels"],
            "labels_num": cfg["labels_num"],
        }
    return {"models": result}


@app.post("/detect/packet")
async def detect_packet(
    file: UploadFile = File(...),
    max_packets: int = Form(5000),
):
    """包级检测：逐包 7 分类"""
    return await _run_detect(file, "packet", max_packets)


@app.post("/detect/flow")
async def detect_flow(
    file: UploadFile = File(...),
    max_packets: int = Form(5000),
):
    """流级检测：32 包窗口 5 分类"""
    return await _run_detect(file, "flow", max_packets)


@app.post("/report/packet")
async def report_packet(
    file: UploadFile = File(...),
    max_packets: int = Form(5000),
):
    """包级检测报告：每包一行，含序号、协议、异常概率"""
    return await _run_report(file, "packet", max_packets)


@app.post("/report/flow")
async def report_flow(
    file: UploadFile = File(...),
    max_packets: int = Form(5000),
):
    """流级检测报告：每包一行，窗口异常概率标注到窗口内每条包"""
    return await _run_report(file, "flow", max_packets)


async def _run_report(file: UploadFile, model_key: str, max_packets: int):
    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(400, "仅支持 .pcap / .pcapng")
    run_id = uuid.uuid4().hex[:10]
    input_path = RUN_DIR / f"{run_id}{suffix}"
    input_path.write_bytes(await file.read())
    try:
        report = _run_isolated("report", model_key, input_path, max_packets)
    except Exception as exc:
        logger.exception("ET-BERT report failed")
        raise HTTPException(500, f"报告生成失败: {exc}")
    return {
        "run_id": run_id,
        "model": model_key,
        "total_packets": len(report),
        "report": report,
    }


async def _run_detect(file: UploadFile, model_key: str, max_packets: int):
    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(400, "仅支持 .pcap / .pcapng")

    run_id = uuid.uuid4().hex[:10]
    input_path = RUN_DIR / f"{run_id}{suffix}"
    input_path.write_bytes(await file.read())

    try:
        return detect_path(input_path, model_key, max_packets)
    except Exception as exc:
        logger.exception("ET-BERT detect failed")
        raise HTTPException(500, f"检测失败: {exc}")


def preload_models():
    """供主应用 startup 调用，预加载模型到内存"""
    import sys as _sys
    if os.getenv("ROBOT_ETBERT_PRELOAD", "0") != "1":
        return
    etbert = _service()
    for key in ("packet", "flow"):
        try:
            etbert.load_model(key)
            _sys.stdout.write(f"[ET-BERT] {key} model loaded\n")
            _sys.stdout.flush()
        except Exception as exc:
            _sys.stderr.write(f"[ET-BERT] {key} model load failed: {exc}\n")
            _sys.stderr.flush()
