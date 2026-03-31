from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

import requests
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BACKEND_URL = "http://127.0.0.1:8010"


def _health_ok(base_url: str, timeout: float = 1.5) -> bool:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/health", timeout=timeout)
        return resp.status_code == 200
    except requests.RequestException:
        return False


@st.cache_resource(show_spinner=False)
def ensure_payload_backend(base_url: str = DEFAULT_BACKEND_URL) -> Dict[str, str]:
    if _health_ok(base_url):
        return {
            "status": "running",
            "message": "Payload 后端已在运行。",
            "backend_url": base_url,
        }

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.payload_api.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8010",
    ]

    try:
        subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Payload 后端启动失败: {e}",
            "backend_url": base_url,
        }

    for _ in range(20):
        if _health_ok(base_url):
            return {
                "status": "started",
                "message": "Payload 后端已自动启动。",
                "backend_url": base_url,
            }
        time.sleep(0.5)

    return {
        "status": "timeout",
        "message": "Payload 后端启动超时，请检查依赖或端口占用。",
        "backend_url": base_url,
    }
