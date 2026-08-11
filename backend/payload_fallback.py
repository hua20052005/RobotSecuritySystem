from __future__ import annotations

import csv
import io
import json
import runpy
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_ROOT = PROJECT_ROOT / "payload-detection"
SCRIPT_PATH = PAYLOAD_ROOT / "scripts" / "detect_from_pcap.py"
ENSEMBLE_PATH = PAYLOAD_ROOT / "models" / "ensemble_classifier_improved.pkl"

LEVEL_NAMES = {
    "SAFE": "正常",
    "LOW": "低风险异常",
    "MEDIUM": "可疑载荷",
    "HIGH": "高危载荷",
    "CRITICAL": "严重载荷",
}


def run_payload_detector(
    input_path: Path,
    output_csv: Path,
    output_summary: Path,
    ensemble_path: Path,
    limit: int | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[str]:
    args = [
        str(SCRIPT_PATH),
        str(input_path),
        "--output",
        str(output_csv),
        "--summary-output",
        str(output_summary),
        "--ensemble",
        str(ensemble_path),
    ]
    if limit is not None and limit > 0:
        args.extend(["--limit", str(limit)])
    if verbose:
        args.append("--verbose")

    if not getattr(sys, "frozen", False):
        return subprocess.run(
            [sys.executable, *args],
            cwd=str(PAYLOAD_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    previous_argv = sys.argv
    try:
        sys.argv = args
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=stdout_buffer.getvalue(),
            stderr=stderr_buffer.getvalue(),
        )
    except Exception as exc:
        return subprocess.CompletedProcess(
            args,
            1,
            stdout=stdout_buffer.getvalue(),
            stderr=f"{stderr_buffer.getvalue()}\n{type(exc).__name__}: {exc}".strip(),
        )
    finally:
        sys.argv = previous_argv


def detect_with_ensemble(input_path: Path, max_packets: int) -> dict[str, object]:
    if not SCRIPT_PATH.exists() or not ENSEMBLE_PATH.exists():
        raise RuntimeError("ET-BERT 权重和 ensemble 回退模型均不可用")

    with tempfile.TemporaryDirectory(prefix="payload-live-") as temp_dir:
        output_csv = Path(temp_dir) / "result.csv"
        output_summary = Path(temp_dir) / "summary.json"
        proc = run_payload_detector(
            input_path=input_path,
            output_csv=output_csv,
            output_summary=output_summary,
            ensemble_path=ENSEMBLE_PATH,
            limit=max(1, int(max_packets)),
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
            raise RuntimeError(f"ensemble worker exited with code {proc.returncode}: {detail}")
        summary = json.loads(output_summary.read_text(encoding="utf-8"))
        with output_csv.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))

    predictions = []
    category_counts: Counter[str] = Counter()
    for row in rows[:100]:
        level = str(row.get("threat_level") or "SAFE").upper()
        name = LEVEL_NAMES.get(level, level)
        confidence = float(row.get("confidence") or 0.0) * 100.0
        category_counts[name] += 1
        predictions.append(
            {
                "packet_index": int(row.get("packet_index") or 0),
                "pred_name": name,
                "confidence": confidence,
                "all_probs": {name: confidence},
                "protocol": row.get("protocol") or "unknown",
                "final_score": float(row.get("final_score") or 0.0),
            }
        )
    full_distribution = {
        LEVEL_NAMES.get(str(level).upper(), str(level)): int(count)
        for level, count in (summary.get("threat_level_distribution") or {}).items()
    }
    return {
        "run_id": uuid.uuid4().hex[:10],
        "model": "ensemble_fallback",
        "model_type": "packet",
        "engine": "ensemble_fallback",
        "fallback_reason": "ET-BERT fine-tuned weight is not installed",
        "total_samples": int(summary.get("processed_packets") or len(rows)),
        "summary": full_distribution or dict(category_counts),
        "abnormal_ratio": float(summary.get("non_safe_ratio") or 0.0) * 100.0,
        "low_confidence_count": sum(item["confidence"] < 50 for item in predictions),
        "low_confidence_samples": [
            item for item in predictions if item["confidence"] < 50
        ][:10],
        "proto_stats": {
            "protocol_distribution": summary.get("protocol_distribution") or {},
            "payload_size_distribution": {},
            "top_ports": {},
        },
        "predictions": predictions,
        "ensemble_summary": summary,
    }
