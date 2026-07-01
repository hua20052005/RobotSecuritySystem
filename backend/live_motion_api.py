from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.motion_recognition_api import (
    MODEL_PATH,
    _action_labels,
    _load_papb_validator,
    _load_recognition_model,
)
from robot_traffic_action.motion import predict_action_sequence

router = APIRouter(prefix="/api/motion-recognition/live", tags=["motion-recognition-live"])

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:@-]+$")
ALLOWED_SCENARIOS = {"general", "patrol", "interaction", "performance"}


class LiveStartRequest(BaseModel):
    host: str = "192.168.2.1"
    username: str = "ysc"
    interface: str = "p2p0"
    sudo_password: str = ""
    capture_seconds: float = Field(default=8.0, ge=2.0, le=60.0)
    scenario: str = "general"
    method: str = "command"


@dataclass(frozen=True)
class LiveConfig:
    host: str
    username: str
    interface: str
    sudo_password: str
    capture_seconds: float
    scenario: str
    method: str

    def public(self) -> Dict[str, object]:
        value = asdict(self)
        value.pop("sudo_password", None)
        return value


class LiveMotionManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None
        self._config: Optional[LiveConfig] = None
        self._started_at: Optional[float] = None
        self._state: Dict[str, object] = self._empty_state()

    @staticmethod
    def _empty_state() -> Dict[str, object]:
        return {
            "running": False,
            "phase": "idle",
            "message": "实时监测尚未启动",
            "window_count": 0,
            "packet_bytes": 0,
            "actions": [],
            "latest_result": None,
            "latest_error": None,
            "started_at": None,
            "updated_at": time.time(),
            "config": None,
        }

    def start(self, config: LiveConfig) -> Dict[str, object]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise HTTPException(status_code=409, detail="实时监测已经在运行")
            if shutil.which("ssh") is None:
                raise HTTPException(status_code=500, detail="未找到 ssh 命令，请先安装 OpenSSH 客户端")

            self._config = config
            self._stop_event.clear()
            self._started_at = time.time()
            self._state = self._empty_state()
            self._state.update(
                {
                    "running": True,
                    "phase": "connecting",
                    "message": "正在连接机器狗",
                    "started_at": self._started_at,
                    "config": config.public(),
                }
            )
            self._thread = threading.Thread(target=self._run, name="live-motion-monitor", daemon=True)
            self._thread.start()
            return self.status()

    def stop(self) -> Dict[str, object]:
        self._stop_event.set()
        with self._lock:
            process = self._process
        if process and process.poll() is None:
            process.terminate()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5)
        with self._lock:
            self._state["running"] = False
            self._state["phase"] = "stopped"
            self._state["message"] = "实时监测已停止"
            self._state["updated_at"] = time.time()
        return self.status()

    def status(self) -> Dict[str, object]:
        with self._lock:
            result = dict(self._state)
            result["actions"] = list(self._state.get("actions", []))
            return result

    def _set_state(self, **values: object) -> None:
        with self._lock:
            self._state.update(values)
            self._state["updated_at"] = time.time()

    def _run(self) -> None:
        assert self._config is not None
        config = self._config
        try:
            _load_recognition_model()
            while not self._stop_event.is_set():
                self._set_state(phase="capturing", message="正在旁路抓取流量窗口")
                pcap_path = self._capture_window(config)
                if pcap_path is None:
                    continue
                try:
                    self._set_state(phase="analyzing", message="正在识别动作并校验流程")
                    self._analyze_window(pcap_path, config)
                finally:
                    pcap_path.unlink(missing_ok=True)
        except Exception as exc:
            self._set_state(
                phase="error",
                message="实时监测发生错误",
                latest_error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            self._set_state(running=False)
            with self._lock:
                self._process = None

    def _capture_window(self, config: LiveConfig) -> Optional[Path]:
        target = f"{config.username}@{config.host}"
        capture_seconds = f"{config.capture_seconds:.3f}"
        remote_command = (
            f"sudo -S -p '' timeout -s INT {capture_seconds} "
            f"tcpdump -U -ni {config.interface} -w - 'not tcp port 22'"
        )
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        pcap_path = Path(tmp.name)
        tmp.close()

        with pcap_path.open("wb") as output:
            process = subprocess.Popen(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=6",
                    target,
                    remote_command,
                ],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.PIPE,
            )
            with self._lock:
                self._process = process
            password_input = (config.sudo_password + "\n").encode("utf-8") if config.sudo_password else b"\n"
            _, stderr = process.communicate(input=password_input)

        with self._lock:
            self._process = None
        if self._stop_event.is_set():
            pcap_path.unlink(missing_ok=True)
            return None

        size = pcap_path.stat().st_size
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        if process.returncode not in {0, 124, 130} or size <= 24:
            pcap_path.unlink(missing_ok=True)
            detail = stderr_text[-800:] or f"ssh/tcpdump exited with code {process.returncode}"
            raise RuntimeError(detail)
        self._set_state(packet_bytes=int(self._state.get("packet_bytes", 0)) + size)
        return pcap_path

    def _analyze_window(self, pcap_path: Path, config: LiveConfig) -> None:
        model = _load_recognition_model()
        recognition = predict_action_sequence(model, pcap_path, method=config.method)
        window_labels = _action_labels(recognition)

        with self._lock:
            actions = list(self._state.get("actions", []))
        for label in window_labels:
            if not actions or actions[-1] != label:
                actions.append(label)
        actions = actions[-100:]

        papb_result = None
        validator = _load_papb_validator()
        if validator is not None and actions:
            papb_result = validator.validate_sequence(
                actions,
                require_terminal=False,
                scenario=config.scenario,
            )

        run_id = f"live-{uuid.uuid4().hex[:10]}"
        summary = {
            "mode": "sequence",
            "method": config.method,
            "label_count": len(actions),
            "labels": actions,
            "window_labels": window_labels,
            "scenario": config.scenario,
            "flow_status": (papb_result or {}).get("status") if papb_result else None,
            "flow_valid": (papb_result or {}).get("valid") if papb_result else None,
        }
        result = {
            "run_id": run_id,
            "filename": "live-capture.pcap",
            "summary": summary,
            "recognition": recognition,
            "actions": actions,
            "flow_validation": papb_result,
            "model_path": str(MODEL_PATH),
            "live": True,
        }
        self._set_state(
            phase="capturing",
            message="窗口分析完成，继续监测",
            window_count=int(self._state.get("window_count", 0)) + 1,
            actions=actions,
            latest_result=result,
            latest_error=None,
        )


def _safe(value: str, field: str) -> str:
    value = value.strip()
    if not value or not SAFE_NAME.fullmatch(value):
        raise HTTPException(status_code=400, detail=f"{field} 包含不安全字符")
    return value


MANAGER = LiveMotionManager()


@router.get("/status")
def live_status() -> Dict[str, object]:
    return MANAGER.status()


@router.post("/start")
def live_start(payload: LiveStartRequest) -> Dict[str, object]:
    scenario = payload.scenario.strip().lower()
    if scenario not in ALLOWED_SCENARIOS:
        raise HTTPException(status_code=400, detail="不支持的任务场景")
    if payload.method != "command":
        raise HTTPException(status_code=400, detail="实时监测当前仅支持 command 识别方式")
    config = LiveConfig(
        host=_safe(payload.host, "host"),
        username=_safe(payload.username, "username"),
        interface=_safe(payload.interface, "interface"),
        sudo_password=payload.sudo_password,
        capture_seconds=float(payload.capture_seconds),
        scenario=scenario,
        method=payload.method,
    )
    return MANAGER.start(config)


@router.post("/stop")
def live_stop() -> Dict[str, object]:
    return MANAGER.stop()
