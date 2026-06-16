from __future__ import annotations

import csv
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.auth import optional_user
from backend.ai_report import router as ai_report_router
from backend.auth_api import router as auth_router
from backend.db import create_task, init_db
from backend.motion_api import router as motion_router
from backend.papb_api import router as papb_router
from backend.side_channel_api import router as side_channel_router
from backend.tasks_api import router as tasks_router

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_ROOT = PROJECT_ROOT / "payload-detection"
SCRIPT_PATH = PAYLOAD_ROOT / "scripts" / "detect_from_pcap.py"
DEFAULT_ENSEMBLE = PAYLOAD_ROOT / "models" / "ensemble_classifier_improved.pkl"
RUN_DIR = PAYLOAD_ROOT / "data" / "api_runs"
RUN_DIR.mkdir(parents=True, exist_ok=True)

RUN_FILES: Dict[str, Dict[str, Path]] = {}

app = FastAPI(title="Payload Detection Backend", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(side_channel_router)
app.include_router(auth_router)
app.include_router(ai_report_router)
app.include_router(motion_router)
app.include_router(papb_router)
app.include_router(tasks_router)
init_db()


def _read_csv_preview(csv_path: Path, max_rows: int = 200) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(row)
    return rows


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "service": "payload-backend",
    }


@app.post("/detect-file")
async def detect_file(
    file: UploadFile = File(...),
    limit: Optional[int] = Form(None),
    verbose: bool = Form(False),
    user: Optional[Dict[str, object]] = Depends(optional_user),
) -> Dict[str, object]:
    if not SCRIPT_PATH.exists():
        raise HTTPException(status_code=500, detail=f"检测脚本不存在: {SCRIPT_PATH}")

    suffix = Path(file.filename or "upload.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=400, detail="仅支持 .pcap 或 .pcapng 文件")

    run_id = uuid.uuid4().hex[:10]
    input_path = RUN_DIR / f"{run_id}{suffix}"
    output_csv = RUN_DIR / f"{run_id}_results.csv"
    output_summary = RUN_DIR / f"{run_id}_summary.json"

    content = await file.read()
    input_path.write_bytes(content)

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        str(input_path),
        "--output",
        str(output_csv),
        "--summary-output",
        str(output_summary),
        "--ensemble",
        str(DEFAULT_ENSEMBLE),
    ]
    if limit is not None and limit > 0:
        cmd.extend(["--limit", str(limit)])
    if verbose:
        cmd.append("--verbose")

    proc = subprocess.run(
        cmd,
        cwd=str(PAYLOAD_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    stderr_text = proc.stderr or ""
    stdout_text = proc.stdout or ""

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "payload 检测失败",
                "stderr": stderr_text[-2000:],
                "stdout": stdout_text[-2000:],
            },
        )

    if not output_csv.exists() or not output_summary.exists():
        raise HTTPException(status_code=500, detail="检测输出文件缺失")

    with output_summary.open("r", encoding="utf-8") as f:
        summary = json.load(f)

    preview = _read_csv_preview(output_csv)
    RUN_FILES[run_id] = {
        "csv": output_csv,
        "summary": output_summary,
    }

    result = {
        "run_id": run_id,
        "summary": summary,
        "preview": preview,
        "download_csv_url": f"/download/{run_id}/csv",
        "download_summary_url": f"/download/{run_id}/summary",
        "stdout_tail": stdout_text.splitlines()[-30:],
    }
    create_task(
        task_id=run_id,
        module="payload",
        title=f"载荷检测 - {file.filename or run_id}",
        parameters={"filename": file.filename, "limit": limit, "verbose": verbose},
        summary=summary if isinstance(summary, dict) else {"summary": summary},
        result=result,
        files={"csv": str(output_csv), "summary": str(output_summary)},
        user_id=int(user["id"]) if user else None,
    )
    return result


@app.get("/download/{run_id}/{kind}")
def download_result(run_id: str, kind: str):
    item = RUN_FILES.get(run_id)
    if item is None:
        raise HTTPException(status_code=404, detail="run_id 不存在")

    if kind == "csv":
        target = item["csv"]
        return FileResponse(path=str(target), media_type="text/csv", filename=target.name)

    if kind == "summary":
        target = item["summary"]
        return FileResponse(path=str(target), media_type="application/json", filename=target.name)

    raise HTTPException(status_code=400, detail="kind 仅支持 csv 或 summary")
