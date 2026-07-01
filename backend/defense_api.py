from __future__ import annotations

import re
import shlex
import threading
from typing import Dict, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

try:
    import paramiko
except ImportError:
    paramiko = None


router = APIRouter(prefix="/api/defense", tags=["defense-control"])

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:@-]+$")
ROBOT_ROOT = "/opt/robot_security"
SYSTEM_ROOT = f"{ROBOT_ROOT}/github_RobotSecuritySystem"
PYTHON = f"{ROBOT_ROOT}/.venv/bin/python"
LOG_ROOT = f"{ROBOT_ROOT}/logs"

PROCESS_PATTERNS = {
    # Bracketed expressions match the target process without matching pgrep/pkill itself.
    "etbert_api": "[u]vicorn backend.etbert_api.main:app",
    "payload_bridge": "[e]tbert_payload_bridge.py",
    "side_bridge": "[s]ide_channel_realtime_bridge.py",
    "proxy": "[u]dp_defense_proxy.py",
}
LOG_FILES = {
    "transparent": f"{LOG_ROOT}/udp_proxy_only.log",
    "defense": f"{LOG_ROOT}/udp_defense_proxy.log",
    "detection": "/tmp/robot_detection_results.jsonl",
    "services": f"{LOG_ROOT}/etbert_api.log",
}
REQUIRED_FILES = {
    "proxy": f"{ROBOT_ROOT}/udp_defense_proxy.py",
    "payload_bridge": f"{ROBOT_ROOT}/etbert_payload_bridge.py",
    "side_bridge": f"{ROBOT_ROOT}/side_channel_realtime_bridge.py",
    "command_sender": f"{ROBOT_ROOT}/send_robot_udp_command.py",
    "etbert_app": f"{SYSTEM_ROOT}/backend/etbert_api/main.py",
    "python": PYTHON,
}


class DefenseConnection(BaseModel):
    host: str = "192.168.2.1"
    username: str = "ysc"
    ssh_password: str = ""


class TestCommandRequest(DefenseConnection):
    command: Literal["HEARTBEAT", "STAND_UP", "STAND_DOWN"] = "HEARTBEAT"
    count: int = Field(default=1, ge=1, le=3)
    safety_confirmed: bool = False


class LogRequest(DefenseConnection):
    log: Literal["transparent", "defense", "detection", "services"] = "defense"
    lines: int = Field(default=80, ge=10, le=300)


_LOCK = threading.Lock()


def _safe(value: str, field: str) -> str:
    value = value.strip()
    if not value or not SAFE_NAME.fullmatch(value):
        raise HTTPException(status_code=400, detail=f"{field} 包含不安全字符")
    return value


def _connect(payload: DefenseConnection):
    if paramiko is None:
        raise HTTPException(status_code=500, detail="缺少 paramiko，无法使用 SSH 密码连接机器狗")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=_safe(payload.host, "host"),
            username=_safe(payload.username, "username"),
            password=payload.ssh_password,
            look_for_keys=False,
            allow_agent=False,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
        )
    except Exception as exc:
        client.close()
        raise HTTPException(status_code=502, detail=f"SSH 连接失败：{exc}") from exc
    return client


def _run(client, command: str, timeout: int = 15) -> Dict[str, object]:
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"远程命令执行失败：{exc}") from exc
    return {"ok": code == 0, "code": code, "stdout": output, "stderr": error}


def _require_ok(result: Dict[str, object], message: str) -> None:
    if not result["ok"]:
        detail = result["stderr"] or result["stdout"] or message
        raise HTTPException(status_code=500, detail=f"{message}：{detail}")


def _tail(client, *paths: str, lines: int = 40) -> str:
    joined = " ".join(shlex.quote(path) for path in paths)
    result = _run(client, f"tail -n {lines} {joined} 2>/dev/null || true")
    return str(result["stdout"]).strip()


def _background_bash(command: str, log_path: str) -> str:
    # Each exec_command call opens a separate SSH session, equivalent to a new terminal window.
    shell_command = (
        f"source {ROBOT_ROOT}/.venv/bin/activate && "
        f"{command}"
    )
    return (
        f"nohup /bin/bash -lc {shlex.quote(shell_command)} "
        f">{shlex.quote(log_path)} 2>&1 </dev/null &"
    )


def _wait_for(client, condition: str, timeout_seconds: int, message: str, *log_paths: str) -> None:
    command = (
        f"i=0; while [ $i -lt {timeout_seconds} ]; do "
        f"if {condition}; then exit 0; fi; "
        "i=$((i+1)); sleep 1; "
        "done; exit 1"
    )
    result = _run(client, command, timeout=timeout_seconds + 8)
    if result["ok"]:
        return
    log_text = _tail(client, *log_paths) if log_paths else ""
    detail = f"{message}（等待 {timeout_seconds} 秒仍未就绪）"
    if log_text:
        detail += f"\n\n远程日志：\n{log_text}"
    raise HTTPException(status_code=500, detail=detail)


def _stop_command() -> str:
    commands = [f"pkill -f {shlex.quote(pattern)} >/dev/null 2>&1 || true" for pattern in PROCESS_PATTERNS.values()]
    commands.extend(
        [
            "rm -f /tmp/robot_packet_stream.jsonl /tmp/robot_detection_results.jsonl",
            "rm -f /tmp/proxy_only_packet_stream.jsonl /tmp/proxy_only_detection_results.jsonl",
        ]
    )
    return "; ".join(commands)


def _status(client) -> Dict[str, object]:
    services: Dict[str, bool] = {}
    for name, pattern in PROCESS_PATTERNS.items():
        result = _run(client, f"pgrep -f {shlex.quote(pattern)} >/dev/null")
        services[name] = bool(result["ok"])
    port_result = _run(
        client,
        "printf 'udp43894='; ss -lun 2>/dev/null | grep -c ':43894 ' || true; "
        "printf 'tcp8010='; ss -ltn 2>/dev/null | grep -c ':8010 ' || true",
    )
    ports = {"udp_43894": False, "tcp_8010": False}
    for line in str(port_result["stdout"]).splitlines():
        key, _, value = line.partition("=")
        if key == "udp43894":
            ports["udp_43894"] = value.strip() not in {"", "0"}
        elif key == "tcp8010":
            ports["tcp_8010"] = value.strip() not in {"", "0"}
    proxy_command = ""
    if services["proxy"]:
        result = _run(client, f"pgrep -af {shlex.quote(PROCESS_PATTERNS['proxy'])} | head -n 1")
        proxy_command = str(result["stdout"])
    mode = "stopped"
    if services["proxy"]:
        mode = "transparent" if "--transparent-forward" in proxy_command else "defense"
    required = ("etbert_api", "payload_bridge", "side_bridge", "proxy")
    readiness = "stopped"
    if mode == "transparent":
        readiness = "complete" if ports["udp_43894"] else "degraded"
    elif mode == "defense":
        readiness = "complete" if all(services[name] for name in required) and ports["udp_43894"] else "degraded"
    return {
        "services": services,
        "ports": ports,
        "mode": mode,
        "readiness": readiness,
    }


def _check_files(client) -> Dict[str, bool]:
    files: Dict[str, bool] = {}
    for name, path in REQUIRED_FILES.items():
        files[name] = bool(_run(client, f"test -f {shlex.quote(path)} -o -x {shlex.quote(path)}")["ok"])
    return files


@router.post("/check")
def check_environment(payload: DefenseConnection) -> Dict[str, object]:
    with _LOCK:
        client = _connect(payload)
        try:
            return {
                "connected": True,
                "files": _check_files(client),
                **_status(client),
            }
        finally:
            client.close()


@router.post("/start-transparent")
def start_transparent(payload: DefenseConnection) -> Dict[str, object]:
    with _LOCK:
        client = _connect(payload)
        try:
            files = _check_files(client)
            if not files["proxy"] or not files["python"]:
                raise HTTPException(status_code=409, detail="机器狗缺少 udp_defense_proxy.py 或虚拟环境 Python")
            _run(client, _stop_command())
            _run(
                client,
                f"mkdir -p {LOG_ROOT}; : > {LOG_FILES['transparent']}; "
                f": > {LOG_ROOT}/transparent_console.log",
            )
            command = (
                f"nohup env DEFENSE_ENABLE_SOURCE_ACL=0 DEFENSE_ROBOT_SYSTEM_ROOT={SYSTEM_ROOT} "
                f"{PYTHON} {ROBOT_ROOT}/udp_defense_proxy.py "
                "--listen-host 0.0.0.0 --listen-port 43894 "
                "--forward-host 127.0.0.1 --forward-port 43893 "
                "--packet-stream-file /tmp/proxy_only_packet_stream.jsonl "
                "--detection-results-file /tmp/proxy_only_detection_results.jsonl "
                "--external-result-wait-ms 0 --transparent-forward "
                "--disable-payload-model --disable-external-results --disable-safe-stop "
                f"--log-file {LOG_FILES['transparent']} "
                f"--pcap-file {LOG_ROOT}/udp_proxy_only_drop.pcap "
                f">>{LOG_ROOT}/transparent_console.log 2>&1 </dev/null &"
            )
            _require_ok(_run(client, command), "透明转发启动失败")
            _run(client, "sleep 1")
            status = _status(client)
            if not status["services"]["proxy"] or not status["ports"]["udp_43894"]:
                log = _run(client, f"tail -n 40 {LOG_ROOT}/transparent_console.log 2>/dev/null || true")
                raise HTTPException(status_code=500, detail=f"透明转发进程未就绪：{log['stdout']}")
            return {"message": "透明转发模式已启动", **status}
        finally:
            client.close()


@router.post("/start-full")
def start_full_defense(payload: DefenseConnection) -> Dict[str, object]:
    with _LOCK:
        client = _connect(payload)
        try:
            files = _check_files(client)
            required = ("proxy", "payload_bridge", "side_bridge", "etbert_app", "python")
            missing = [name for name in required if not files[name]]
            if missing:
                raise HTTPException(status_code=409, detail=f"机器狗缺少防御组件：{', '.join(missing)}")

            _run(client, _stop_command())
            _require_ok(_run(client, f"mkdir -p {LOG_ROOT} {ROBOT_ROOT}/tmp/robot_payload_batches"), "创建运行目录失败")
            _require_ok(
                _run(
                    client,
                    f": > {LOG_ROOT}/etbert_api.log; "
                    f": > {LOG_ROOT}/payload_bridge.log; "
                    f": > {LOG_ROOT}/side_bridge.log; "
                    f": > {LOG_ROOT}/proxy_console.log; "
                    f": > {LOG_FILES['defense']}",
                ),
                "清理本轮实验日志失败",
            )

            _wait_for(
                client,
                "! ss -lun 2>/dev/null | grep -q ':43894 ' && ! ss -ltn 2>/dev/null | grep -q ':8010 '",
                8,
                "阶段 1/5：旧实验端口未能释放",
            )

            etbert_log = f"{LOG_ROOT}/etbert_api.log"
            etbert_command = _background_bash(
                f"cd {SYSTEM_ROOT} && "
                "python -m uvicorn backend.etbert_api.main:app "
                "--host 127.0.0.1 --port 8010",
                etbert_log,
            )
            _require_ok(_run(client, etbert_command), "阶段 2/5：ET-BERT API 启动命令失败")
            _wait_for(
                client,
                "curl -fsS --max-time 2 http://127.0.0.1:8010/health >/dev/null 2>&1",
                120,
                "阶段 2/5：ET-BERT API 健康检查失败",
                etbert_log,
            )

            payload_log = f"{LOG_ROOT}/payload_bridge.log"
            payload_command = _background_bash(
                f"cd {ROBOT_ROOT} && python etbert_payload_bridge.py "
                "--packet-stream-file /tmp/robot_packet_stream.jsonl "
                "--detection-results-file /tmp/robot_detection_results.jsonl "
                "--etbert-base-url http://127.0.0.1:8010 --mode both "
                f"--work-dir {ROBOT_ROOT}/tmp/robot_payload_batches",
                payload_log,
            )
            _require_ok(_run(client, payload_command), "阶段 3/5：载荷检测桥接启动命令失败")
            _wait_for(
                client,
                f"pgrep -f {shlex.quote(PROCESS_PATTERNS['payload_bridge'])} >/dev/null",
                8,
                "阶段 3/5：载荷检测桥接退出",
                payload_log,
            )

            side_log = f"{LOG_ROOT}/side_bridge.log"
            side_command = _background_bash(
                f"cd {ROBOT_ROOT} && python side_channel_realtime_bridge.py "
                "--packet-stream-file /tmp/robot_packet_stream.jsonl "
                "--detection-results-file /tmp/robot_detection_results.jsonl",
                side_log,
            )
            _require_ok(_run(client, side_command), "阶段 4/5：侧信道检测桥接启动命令失败")
            _wait_for(
                client,
                f"pgrep -f {shlex.quote(PROCESS_PATTERNS['side_bridge'])} >/dev/null",
                8,
                "阶段 4/5：侧信道检测桥接退出",
                side_log,
            )

            proxy_log = f"{LOG_ROOT}/proxy_console.log"
            proxy_command = _background_bash(
                f"cd {ROBOT_ROOT} && "
                "DEFENSE_ENABLE_SOURCE_ACL=0 "
                f"DEFENSE_ROBOT_SYSTEM_ROOT={SYSTEM_ROOT} python udp_defense_proxy.py "
                "--listen-host 0.0.0.0 --listen-port 43894 "
                "--forward-host 127.0.0.1 --forward-port 43893 "
                "--packet-stream-file /tmp/robot_packet_stream.jsonl "
                "--detection-results-file /tmp/robot_detection_results.jsonl "
                "--external-result-wait-ms 80 "
                f"--log-file {LOG_FILES['defense']} "
                f"--pcap-file {LOG_ROOT}/udp_defense_proxy_drop.pcap",
                proxy_log,
            )
            _require_ok(_run(client, proxy_command), "阶段 5/5：UDP 防御代理启动命令失败")
            _wait_for(
                client,
                "ss -lun 2>/dev/null | grep -q ':43894 '",
                10,
                "阶段 5/5：UDP 防御代理未监听 43894",
                proxy_log,
                LOG_FILES["defense"],
            )

            status = _status(client)
            required_services = ["etbert_api", "payload_bridge", "side_bridge", "proxy"]
            failed = [name for name in required_services if not status["services"][name]]
            if failed or not status["ports"]["udp_43894"]:
                logs = _tail(
                    client,
                    etbert_log,
                    payload_log,
                    side_log,
                    proxy_log,
                    lines=20,
                )
                raise HTTPException(status_code=500, detail=f"最终状态检查失败：{', '.join(failed)}\n{logs}")
            return {"message": "完整防御链已启动", **status}
        except HTTPException:
            _run(client, _stop_command())
            raise
        finally:
            client.close()


@router.post("/stop")
def stop_defense(payload: DefenseConnection) -> Dict[str, object]:
    with _LOCK:
        client = _connect(payload)
        try:
            _run(client, _stop_command())
            return {"message": "实验进程已停止", **_status(client)}
        finally:
            client.close()


@router.post("/send-test")
def send_test_command(payload: TestCommandRequest) -> Dict[str, object]:
    if payload.command != "HEARTBEAT" and not payload.safety_confirmed:
        raise HTTPException(status_code=400, detail="实体动作前必须确认场地安全")
    with _LOCK:
        client = _connect(payload)
        try:
            if not _check_files(client)["command_sender"]:
                raise HTTPException(status_code=409, detail="机器狗缺少 send_robot_udp_command.py")
            command = (
                f"{PYTHON} {ROBOT_ROOT}/send_robot_udp_command.py "
                f"--host 127.0.0.1 --port 43894 --cmd {payload.command} --count {payload.count}"
            )
            result = _run(client, command, timeout=20)
            _require_ok(result, "测试指令发送失败")
            return {
                "message": f"{payload.command} 已发送到防御入口 43894",
                "command": payload.command,
                "count": payload.count,
                "output": result["stdout"],
            }
        finally:
            client.close()


@router.post("/logs")
def read_logs(payload: LogRequest) -> Dict[str, object]:
    with _LOCK:
        client = _connect(payload)
        try:
            if payload.log == "services":
                paths = [
                    f"{LOG_ROOT}/etbert_api.log",
                    f"{LOG_ROOT}/payload_bridge.log",
                    f"{LOG_ROOT}/side_bridge.log",
                    f"{LOG_ROOT}/proxy_console.log",
                ]
                joined = " ".join(shlex.quote(path) for path in paths)
                result = _run(client, f"tail -n {payload.lines} {joined} 2>/dev/null || true")
                return {"log": payload.log, "path": ", ".join(paths), "content": result["stdout"]}
            path = LOG_FILES[payload.log]
            result = _run(client, f"tail -n {payload.lines} {shlex.quote(path)} 2>/dev/null || true")
            return {"log": payload.log, "path": path, "content": result["stdout"]}
        finally:
            client.close()
