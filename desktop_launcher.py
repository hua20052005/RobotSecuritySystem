from __future__ import annotations

import ctypes
import logging
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn
from fastapi.responses import FileResponse


HOST = "127.0.0.1"
PORT = 8010
APP_NAME = "RoboGuard"


def runtime_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def user_root() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    target = base / APP_NAME
    target.mkdir(parents=True, exist_ok=True)
    return target


def configure_logging() -> Path:
    log_path = user_root() / "roboguard.log"
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        encoding="utf-8",
    )
    return log_path


def message_box(title: str, message: str, error: bool = False) -> None:
    flags = 0x10 if error else 0x40
    ctypes.windll.user32.MessageBoxW(None, message, title, flags)


def port_available() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((HOST, PORT)) != 0


def find_browser() -> Path | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    return next((path for path in candidates if path.is_file()), None)


def wait_for_server(timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex((HOST, PORT)) == 0:
                return True
        time.sleep(0.2)
    return False


def attach_frontend(app, web_root: Path) -> None:
    index_path = web_root / "index.html"
    if not index_path.is_file():
        raise FileNotFoundError(f"Frontend build not found: {index_path}")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        requested = (web_root / full_path).resolve()
        try:
            requested.relative_to(web_root.resolve())
        except ValueError:
            return FileResponse(index_path)
        if requested.is_file():
            return FileResponse(requested)
        return FileResponse(index_path)


def launch_browser(server: uvicorn.Server) -> None:
    if not wait_for_server():
        message_box(APP_NAME, "本地服务启动超时，请查看运行日志。", error=True)
        server.should_exit = True
        return

    url = f"http://{HOST}:{PORT}"
    browser = find_browser()
    if browser is None:
        webbrowser.open(url)
        return

    profile = user_root() / "browser-profile"
    profile.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [
            str(browser),
            f"--app={url}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--disable-extensions",
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    process.wait()
    server.should_exit = True


def main() -> int:
    multiprocessing.freeze_support()
    log_path = configure_logging()
    if not port_available():
        message_box(
            APP_NAME,
            f"端口 {PORT} 已被占用。请先关闭正在运行的 RoboGuard 或后端服务。",
            error=True,
        )
        return 2

    try:
        from backend.payload_api.main import app

        attach_frontend(app, runtime_root() / "web" / "dist")
        config = uvicorn.Config(
            app,
            host=HOST,
            port=PORT,
            log_level="info",
            access_log=False,
            log_config=None,
        )
        server = uvicorn.Server(config)
        threading.Thread(
            target=launch_browser,
            args=(server,),
            name="roboguard-browser",
            daemon=True,
        ).start()
        server.run()
        return 0
    except Exception as exc:
        logging.exception("RoboGuard startup failed")
        message_box(
            APP_NAME,
            f"RoboGuard 启动失败：{type(exc).__name__}: {exc}\n\n日志：{log_path}",
            error=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
