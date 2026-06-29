"""ET-BERT 双粒度流量检测 API"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.etbert_api.etbert_service import etbert, MODEL_DEFS, logger

RUN_DIR = Path(__file__).resolve().parents[2] / "data" / "etbert_runs"
RUN_DIR.mkdir(parents=True, exist_ok=True)

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


async def _run_detect(file: UploadFile, model_key: str, max_packets: int):
    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(400, "仅支持 .pcap / .pcapng")

    run_id = uuid.uuid4().hex[:10]
    input_path = RUN_DIR / f"{run_id}{suffix}"
    input_path.write_bytes(await file.read())

    try:
        result = etbert.detect_pcap(model_key, str(input_path), max_packets)
    except Exception as exc:
        logger.exception("ET-BERT detect failed")
        raise HTTPException(500, f"检测失败: {exc}")

    # 低置信度告警
    low_conf = [r for r in result.predictions if r["confidence"] < 50]

    return {
        "run_id": run_id,
        "model": model_key,
        "model_type": MODEL_DEFS[model_key]["type"],
        "total_samples": result.total_samples,
        "summary": result.summary,
        "abnormal_ratio": result.abnormal_ratio,
        "low_confidence_count": len(low_conf),
        "low_confidence_samples": low_conf[:10],
        "proto_stats": result.proto_stats,
        "predictions": result.predictions[:100],
    }


def preload_models():
    """供主应用 startup 调用，预加载模型到内存"""
    import sys as _sys
    for key in ("packet", "flow"):
        try:
            etbert.load_model(key)
            _sys.stdout.write(f"[ET-BERT] {key} model loaded\n")
            _sys.stdout.flush()
        except Exception as exc:
            _sys.stderr.write(f"[ET-BERT] {key} model load failed: {exc}\n")
            _sys.stderr.flush()
