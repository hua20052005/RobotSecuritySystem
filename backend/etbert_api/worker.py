"""Isolated ET-BERT worker.

PyTorch/model binary failures must not terminate the main RobotSec API process.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / ".venv" / "Lib" / "site-packages"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("detect", "report"))
    parser.add_argument("model_key", choices=("packet", "flow"))
    parser.add_argument("pcap_path")
    parser.add_argument("max_packets", type=int)
    parser.add_argument("output_path")
    args = parser.parse_args()

    from backend.etbert_api.etbert_service import etbert

    if args.operation == "detect":
        payload = asdict(etbert.detect_pcap(args.model_key, args.pcap_path, args.max_packets))
    else:
        payload = etbert.generate_report(args.model_key, args.pcap_path, args.max_packets)

    Path(args.output_path).write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
