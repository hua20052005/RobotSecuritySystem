from __future__ import annotations

import csv
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import FileResponse

from backend.auth import optional_user
from backend.db import create_task

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MOTION_ROOT = PROJECT_ROOT / "motion" / "motion"
SCRIPT_PATH = MOTION_ROOT / "model_motion_sequences.py"
RUN_DIR = MOTION_ROOT / "api_runs"
RUN_DIR.mkdir(parents=True, exist_ok=True)

RUN_FILES: Dict[str, Dict[str, Path]] = {}

router = APIRouter(prefix="/api/motion", tags=["motion"])


def _read_csv_preview(csv_path: Path, max_rows: int = 200) -> List[Dict[str, str]]:
    if not csv_path.exists():
        return []
    rows: List[Dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(row)
    return rows


def _summarize(report: Dict[str, object]) -> Dict[str, object]:
    template_summary = report.get("template_summary") or []
    transition_scores = report.get("task_transition_scores") or []
    invalid_transitions = [
        item for item in transition_scores
        if not bool(item.get("transition_is_valid", True))
    ]
    anomaly_transitions = [
        item for item in transition_scores
        if bool(item.get("transition_is_anomaly", False))
    ]
    return {
        "window_ms": report.get("window_ms"),
        "clusters": report.get("clusters"),
        "mean_within_action_similarity": report.get("mean_within_action_similarity"),
        "mean_between_action_similarity": report.get("mean_between_action_similarity"),
        "separability_score": report.get("separability_score"),
        "nearest_neighbor_accuracy": report.get("nearest_neighbor_accuracy"),
        "leave_one_out_template_accuracy": report.get("leave_one_out_template_accuracy"),
        "action_count": len(report.get("temporal_consistency_score") or {}),
        "template_summary": template_summary,
        "transition_count": len(transition_scores),
        "invalid_transition_count": len(invalid_transitions),
        "transition_anomaly_count": len(anomaly_transitions),
    }


@router.post("/analyze")
def analyze_motion(
    window_ms: Annotated[int, Form()] = 100,
    clusters: Annotated[int, Form()] = 8,
    max_templates_per_action: Annotated[int, Form()] = 2,
    min_template_support: Annotated[int, Form()] = 2,
    template_diversity_threshold: Annotated[float, Form()] = 0.85,
    task_sequences: Annotated[Optional[str], Form()] = None,
    include_ports: Annotated[str, Form()] = "",
    exclude_ports: Annotated[str, Form()] = "22",
    user: Optional[Dict[str, object]] = Depends(optional_user),
) -> Dict[str, object]:
    if not SCRIPT_PATH.exists():
        raise HTTPException(status_code=500, detail=f"时序建模脚本不存在: {SCRIPT_PATH}")

    window_ms = max(20, min(int(window_ms), 5000))
    clusters = max(2, min(int(clusters), 26))
    max_templates_per_action = max(1, min(int(max_templates_per_action), 8))
    min_template_support = max(1, min(int(min_template_support), 20))

    task_arg = ""
    task_sequences = (task_sequences or "").strip()
    if task_sequences:
        task_path = MOTION_ROOT / task_sequences
        if not task_path.exists():
            raise HTTPException(status_code=400, detail=f"任务序列文件不存在: {task_sequences}")
        task_arg = str(task_path)

    run_id = uuid.uuid4().hex[:10]
    out_dir = RUN_DIR / run_id

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--root",
        str(MOTION_ROOT),
        "--out",
        str(out_dir),
        "--window-ms",
        str(window_ms),
        "--clusters",
        str(clusters),
        "--max-templates-per-action",
        str(max_templates_per_action),
        "--min-template-support",
        str(min_template_support),
        "--template-diversity-threshold",
        str(template_diversity_threshold),
        "--include-ports",
        include_ports,
        "--exclude-ports",
        exclude_ports,
    ]
    if task_arg:
        cmd.extend(["--task-sequences", task_arg])

    proc = subprocess.run(
        cmd,
        cwd=str(MOTION_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "运动时序建模失败",
                "stderr": (proc.stderr or "")[-3000:],
                "stdout": (proc.stdout or "")[-3000:],
            },
        )

    report_path = out_dir / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=500, detail="时序建模输出 report.json 缺失")

    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    files = {
        "report": report_path,
        "markdown": out_dir / "REPORT.md",
        "templates": out_dir / "template_scores.csv",
        "summary": out_dir / "template_summary.csv",
        "transitions": out_dir / "task_transition_scores.csv",
        "sequences": out_dir / "sample_sequences.csv",
        "image": out_dir / "symbol_sequences.png",
    }
    RUN_FILES[run_id] = files

    result = {
        "run_id": run_id,
        "summary": _summarize(report),
        "temporal_consistency_score": report.get("temporal_consistency_score", {}),
        "between_action_similarity": report.get("between_action_similarity", []),
        "template_summary": report.get("template_summary", []),
        "transition_graph_rows": report.get("transition_graph_rows", []),
        "transition_preview": _read_csv_preview(files["transitions"], max_rows=100),
        "sequence_preview": _read_csv_preview(files["sequences"], max_rows=100),
        "stdout_tail": (proc.stdout or "").splitlines()[-30:],
        "download_report_url": f"/api/motion/download/{run_id}/report",
        "download_markdown_url": f"/api/motion/download/{run_id}/markdown",
        "download_transitions_url": f"/api/motion/download/{run_id}/transitions",
        "download_image_url": f"/api/motion/download/{run_id}/image",
    }
    create_task(
        task_id=run_id,
        module="motion",
        title=f"运动时序建模 - {run_id}",
        parameters={
            "window_ms": window_ms,
            "clusters": clusters,
            "max_templates_per_action": max_templates_per_action,
            "min_template_support": min_template_support,
            "template_diversity_threshold": template_diversity_threshold,
            "task_sequences": task_sequences,
            "include_ports": include_ports,
            "exclude_ports": exclude_ports,
        },
        summary=result["summary"],
        result=result,
        files={key: str(value) for key, value in files.items()},
        user_id=int(user["id"]) if isinstance(user, dict) else None,
    )
    return result


@router.get("/download/{run_id}/{kind}")
def download_motion_result(run_id: str, kind: str):
    files = RUN_FILES.get(run_id)
    if files is None:
        raise HTTPException(status_code=404, detail="run_id 不存在或服务已重启")

    if kind not in files:
        raise HTTPException(status_code=400, detail="不支持的下载类型")

    target = files[kind]
    if not target.exists():
        raise HTTPException(status_code=404, detail="文件不存在")

    media_types = {
        "report": "application/json",
        "markdown": "text/markdown",
        "templates": "text/csv",
        "summary": "text/csv",
        "transitions": "text/csv",
        "sequences": "text/csv",
        "image": "image/png",
    }
    return FileResponse(
        path=str(target),
        media_type=media_types.get(kind, "application/octet-stream"),
        filename=target.name,
    )
