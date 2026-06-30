from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.append(str(ROOT / ".venv" / "Lib" / "site-packages"))

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "backend.payload_api.main:app",
        host="127.0.0.1",
        port=8010,
    )
