from __future__ import annotations

import os
import socket
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.append(str(ROOT / ".venv" / "Lib" / "site-packages"))

import uvicorn


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def choose_port(candidates: tuple[int, ...] = (8010, 8011, 8012, 8013)) -> int:
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("No available backend port found in 8010-8013.")


if __name__ == "__main__":
    load_dotenv()
    port = choose_port()
    if port != 8010:
        print(f"Port 8010 is busy, using {port} instead.")
        print(f"When starting the frontend manually, run: $env:VITE_API_BASE_URL='http://127.0.0.1:{port}'; npm run dev")

    uvicorn.run(
        "backend.payload_api.main:app",
        host="127.0.0.1",
        port=port,
    )
