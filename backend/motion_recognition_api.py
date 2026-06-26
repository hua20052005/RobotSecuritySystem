from __future__ import annotations

import json
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from backend.auth import optional_user
from backend.db import create_task

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RECOGNIZER_ROOT = PROJECT_ROOT / "backend" / "motion_recognition"
MODEL_PATH = PROJECT_ROOT / "models" / "motion_recognition" / "motion_model.pkl"
PAPB_ROOT = PROJECT_ROOT / "motion" / "motion"
PAPB_MODEL = PAPB_ROOT / "papb_trained_model.json"
PAPB_DATASET = PAPB_ROOT / "papb_synthetic_sequences.json"

if str(RECOGNIZER_ROOT) not in sys.path:
    sys.path.insert(0, str(RECOGNIZER_ROOT))
if str(PAPB_ROOT) not in sys.path:
    sys.path.insert(0, str(PAPB_ROOT))

from papb_validator import PapbValidator  # noqa: E402
from robot_traffic_action.motion import (  # noqa: E402
    load_motion_model,
    predict_action_sequence,
    predict_motion_pcap,
)

router = APIRouter(prefix="/api/motion-recognition", tags=["motion-recognition"])

_MODEL_CACHE = None
_PAPB_CACHE = None


def _load_recognition_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        if not MODEL_PATH.exists():
            raise HTTPException(status_code=500, detail=f"motion model not found: {MODEL_PATH}")
        _MODEL_CACHE = load_motion_model(MODEL_PATH)
    return _MODEL_CACHE


def _load_papb_validator() -> PapbValidator | None:
    global _PAPB_CACHE
    if _PAPB_CACHE is not None:
        return _PAPB_CACHE
    source = PAPB_MODEL if PAPB_MODEL.exists() else PAPB_DATASET
    if not source.exists():
        return None
    _PAPB_CACHE = PapbValidator.from_json(source, require_terminal=False)
    return _PAPB_CACHE


def _parse_transcript(value: Optional[str]) -> list[str] | None:
    if not value:
        return None
    normalized = value.replace("->", ",").replace("\n", ",").replace("\r", ",")
    labels = [item.strip() for item in normalized.split(",") if item.strip()]
    return labels or None


def _action_labels(sequence_result: Dict[str, object]) -> list[str]:
    labels = []
    for action in sequence_result.get("actions", []) or []:
        label = str(action.get("label", "")).strip()
        if label:
            labels.append(label)
    return labels


@router.get("/health")
def health() -> Dict[str, object]:
    return {
        "status": "ok",
        "model_exists": MODEL_PATH.exists(),
        "model_path": str(MODEL_PATH),
        "papb_model_exists": PAPB_MODEL.exists(),
        "papb_dataset_exists": PAPB_DATASET.exists(),
    }


@router.post("/recognize")
async def recognize_motion_file(
    file: UploadFile = File(...),
    mode: str = Form("sequence"),
    method: str = Form("dp"),
    transcript: Optional[str] = Form(None),
    validate_flow: bool = Form(True),
    min_segment_s: float = Form(0.25),
    max_segment_s: Optional[float] = Form(None),
    step_s: float = Form(0.5),
    segment_penalty: float = Form(0.02),
    user: Optional[Dict[str, object]] = Depends(optional_user),
) -> Dict[str, object]:
    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail="only .pcap/.pcapng/.cap files are supported")

    mode = mode.strip().lower()
    method = method.strip().lower()
    if mode not in {"single", "sequence"}:
        raise HTTPException(status_code=400, detail="mode must be single or sequence")
    if method not in {"dp", "activity", "scan", "scripted"}:
        raise HTTPException(status_code=400, detail="method must be dp/activity/scan/scripted")

    run_id = uuid.uuid4().hex[:10]
    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        pcap_path = Path(tmp.name)

    try:
        model = _load_recognition_model()
        if mode == "single":
            recognition = predict_motion_pcap(model, pcap_path)
            labels = [str(recognition.get("label", ""))] if recognition.get("label") else []
        else:
            recognition = predict_action_sequence(
                model,
                pcap_path,
                method=method,
                transcript=_parse_transcript(transcript),
                min_segment_s=float(min_segment_s),
                max_segment_s=max_segment_s,
                step_s=float(step_s),
                segment_penalty=float(segment_penalty),
            )
            labels = _action_labels(recognition)
    finally:
        pcap_path.unlink(missing_ok=True)

    papb_result = None
    if validate_flow and labels:
        validator = _load_papb_validator()
        if validator is not None:
            papb_result = validator.validate_sequence(labels, require_terminal=False)

    summary = {
        "mode": mode,
        "method": method if mode == "sequence" else "single",
        "label_count": len(labels),
        "labels": labels,
        "flow_status": (papb_result or {}).get("status") if papb_result else None,
        "flow_valid": (papb_result or {}).get("valid") if papb_result else None,
    }
    result = {
        "run_id": run_id,
        "filename": file.filename,
        "summary": summary,
        "recognition": recognition,
        "actions": labels,
        "flow_validation": papb_result,
        "model_path": str(MODEL_PATH),
    }
    create_task(
        task_id=run_id,
        module="motion-recognition",
        title=f"motion recognition - {file.filename or run_id}",
        parameters={
            "mode": mode,
            "method": method,
            "transcript": transcript,
            "validate_flow": validate_flow,
            "min_segment_s": min_segment_s,
            "max_segment_s": max_segment_s,
            "step_s": step_s,
            "segment_penalty": segment_penalty,
        },
        summary=summary,
        result=result,
        files={},
        user_id=int(user["id"]) if isinstance(user, dict) else None,
    )
    return result
