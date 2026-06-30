from __future__ import annotations

import csv
import json
import pickle
import socket
import struct
from math import ceil
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

from .model import (
    ActionModel,
    load_dataset,
    predict_pcap as predict_signal_pcap,
    save_model as save_signal_model,
    train_action_model,
)
from .pcap_signal import LengthMode, Protocol, iter_pcaps


DEFAULT_FEATURE_COLUMNS = [
    "pkt_count",
    "byte_count",
    "up_pkt_count",
    "down_pkt_count",
    "up_bytes",
    "down_bytes",
    "tcp_count",
    "udp_count",
    "small_count",
    "large_count",
    "mean_len",
    "std_len",
    "mean_iat_ms",
    "std_iat_ms",
    "byte_rate",
    "direction_balance",
    "len_cv",
    "iat_cv",
    "small_ratio",
    "large_ratio",
]

MSG_TYPES = (1, 2, 3, 4, 5, 6)
MSG_TYPE_FEATURE_COLUMNS = [
    *(f"msg_type_{msg_type:02x}_count" for msg_type in MSG_TYPES),
    *(f"msg_type_{msg_type:02x}_ratio" for msg_type in MSG_TYPES),
    "valid_payload_count",
    "valid_payload_ratio",
    "payload_byte_count",
]

PROTOCOL_FEATURE_COLUMNS = DEFAULT_FEATURE_COLUMNS + MSG_TYPE_FEATURE_COLUMNS

VALID_SUBTYPES = {0x09}
VALID_MSGTYPES = set(MSG_TYPES)
EXPECTED_PAYLOAD_LENGTHS = {
    0x01: {212, 52},
    0x02: {108},
    0x03: {108},
    0x04: {16},
    0x05: {60},
    0x06: {380},
}
PAYLOAD_PAD_LEN = 380

SEQUENCE_TRANSCRIPT_PRESETS = {
    "seq1": ["stand", "step", "hello", "stand"],
    "seq2": ["stand", "moonwalk", "twistBody"],
    "seq3": ["stand", "stand", "step", "walk"],
    "seq4": ["stand", "twistBody", "step"],
    "seq5": ["stand", "step", "backflip"],
    "seq6": ["stand", "twistBody", "step", "stand"],
    "seq7": ["stand", "moonwalk", "walk", "walk", "twistBody"],
}

ACTION_ALIASES = {
    "站立": "stand",
    "趴下": "stand",
    "蹲下": "stand",
    "起立": "stand",
    "前进": "step",
    "向前": "step",
    "移动": "step",
    "打招呼": "hello",
    "招手": "hello",
    "太空步": "moonwalk",
    "扭身体": "twistBody",
    "扭身": "twistBody",
    "扭身跳": "twistJump",
    "后空翻": "backflip",
    "后退": "walk",
    "向左移动": "walk",
    "左移": "walk",
    "stand": "stand",
    "down": "stand",
    "lie": "stand",
    "sit": "stand",
    "squat": "stand",
    "step": "step",
    "forward": "step",
    "hello": "hello",
    "moonwalk": "moonwalk",
    "twistbody": "twistBody",
    "twist_body": "twistBody",
    "twistjump": "twistJump",
    "twist_jump": "twistJump",
    "backflip": "backflip",
    "walk": "walk",
    "backward": "walk",
    "left": "walk",
}

MOVEMENT_ACTION_LABEL = "move"
MOVEMENT_ACTION_ALIASES = frozenset(
    {"back", "backward", "forword", "forward", "right", "left"}
)
CANONICAL_ACTION_ALIASES = {
    "step": "moonwalk",
}


def canonical_action_label(label: object) -> str:
    value = str(label).strip()
    if value.lower() in MOVEMENT_ACTION_ALIASES:
        return MOVEMENT_ACTION_LABEL
    return CANONICAL_ACTION_ALIASES.get(value.lower(), value)


def _canonical_probabilities(proba: dict[str, float]) -> dict[str, float]:
    merged: defaultdict[str, float] = defaultdict(float)
    for label, probability in proba.items():
        merged[canonical_action_label(label)] += float(probability)
    return dict(sorted(merged.items()))


def _canonicalize_prediction(
    result: dict[str, object] | None,
    *,
    label_key: str,
) -> dict[str, object] | None:
    if result is None or not result.get(label_key):
        return result
    raw_label = str(result[label_key])
    canonical_label = canonical_action_label(raw_label)
    if canonical_label != raw_label:
        result[f"raw_{label_key}"] = raw_label

    raw_proba = result.get("proba")
    if isinstance(raw_proba, dict):
        canonical_proba = _canonical_probabilities(raw_proba)
        if canonical_proba:
            canonical_label, confidence = max(
                canonical_proba.items(),
                key=lambda item: item[1],
            )
            result["proba"] = canonical_proba
            result["confidence"] = float(confidence)

    if canonical_label != raw_label:
        result.setdefault(f"raw_{label_key}", raw_label)
    result[label_key] = canonical_label
    return result


def _canonicalize_sequence_result(result: dict[str, object]) -> dict[str, object]:
    raw_actions = result.get("actions")
    if not isinstance(raw_actions, list):
        return result

    actions: list[dict[str, object]] = []
    for raw_item in raw_actions:
        if not isinstance(raw_item, dict):
            continue
        item = dict(raw_item)
        _canonicalize_prediction(item, label_key="label")
        if item.get("label") != MOVEMENT_ACTION_LABEL:
            actions.append(item)
            continue

        raw_label = str(item.get("raw_label") or item["label"])
        if actions and actions[-1].get("label") == MOVEMENT_ACTION_LABEL:
            previous = actions[-1]
            raw_labels = list(previous.get("raw_labels") or [])
            for value in (previous.get("raw_label"), raw_label):
                if value and value not in raw_labels:
                    raw_labels.append(str(value))
            previous["raw_labels"] = raw_labels
            if item.get("t_end_s") is not None:
                previous["t_end_s"] = item["t_end_s"]
            if previous.get("t_start_s") is not None and previous.get("t_end_s") is not None:
                previous["duration_s"] = float(previous["t_end_s"]) - float(previous["t_start_s"])
            continue

        item["raw_labels"] = [raw_label]
        actions.append(item)

    result["actions"] = actions
    return result


@dataclass(frozen=True)
class MotionTemplate:
    label: str
    sequence: str
    sample: str
    rank: int
    length: int
    action_avg_length: float
    support: int
    mean_similarity: float


@dataclass
class MotionModel:
    centroids: np.ndarray
    mean: np.ndarray
    std: np.ndarray
    templates: dict[str, list[MotionTemplate]]
    thresholds: dict[str, float]
    feature_columns: list[str]
    local_ips: set[str]
    window_ms: int
    include_ports: set[int] | None
    exclude_ports: set[int]
    clean_mode: str = "none"
    control_flows: set[tuple[int, int]] | None = None
    signal_model: ActionModel | None = None
    amnar_model: object | None = None
    amnar_labels: list[str] | None = None
    amnar_durations: dict[str, list[float]] | None = None
    amnar_window_model: object | None = None
    traffic_model: object | None = None
    amnar_window_s: float = 2.5
    amnar_window_step_s: float = 1.0
    controller_command_map: dict[str, str] | None = None


def read_pcap_packets(path: str | Path):
    """Yield timestamp, captured/original length, and raw bytes for classic pcap files."""
    with Path(path).open("rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"M<\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<M"):
            endian = ">"
        else:
            raise ValueError(f"{path} is not a classic pcap file")
        nano = magic in (b"M<\xb2\xa1", b"\xa1\xb2<M")
        scale = 1_000_000_000 if nano else 1_000_000

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + "IIII", packet_header
            )
            payload = f.read(incl_len)
            if len(payload) < incl_len:
                break
            yield ts_sec + ts_frac / scale, orig_len, payload


def parse_ipv4_packet(frame: bytes) -> dict[str, object] | None:
    if len(frame) < 34:
        return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if eth_type == 0x8100 and len(frame) >= 38:
        eth_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if eth_type != 0x0800 or len(frame) < offset + 20:
        return None

    version_ihl = frame[offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < offset + ihl:
        return None

    proto = frame[offset + 9]
    total_len = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
    src = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16 : offset + 20])
    src_port = None
    dst_port = None
    udp_payload = b""
    l4 = offset + ihl
    if proto in (6, 17) and len(frame) >= l4 + 4:
        src_port, dst_port = struct.unpack("!HH", frame[l4 : l4 + 4])
    if proto == 17 and len(frame) >= l4 + 8:
        udp_len = struct.unpack("!H", frame[l4 + 4 : l4 + 6])[0]
        payload_end = min(len(frame), l4 + udp_len, offset + total_len)
        udp_payload = frame[l4 + 8 : payload_end]
    return {
        "proto": proto,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "udp_payload": udp_payload,
    }


def discover_local_ips(pcap_files: Iterable[str | Path], sample_packets: int = 5000) -> set[str]:
    counts: Counter[str] = Counter()
    for path in pcap_files:
        for idx, (_, _, frame) in enumerate(read_pcap_packets(path)):
            meta = parse_ipv4_packet(frame)
            if meta:
                for ip in (str(meta["src"]), str(meta["dst"])):
                    if _is_private_ipv4(ip):
                        counts[ip] += 1
            if idx + 1 >= sample_packets:
                break
    return {ip for ip, _ in counts.most_common(3)}


def discover_control_flows(
    pcap_files: Iterable[str | Path],
    *,
    min_packets: int = 1000,
    min_valid_ratio: float = 0.95,
) -> set[tuple[int, int]]:
    flow_counts: Counter[tuple[int, int]] = Counter()
    valid_counts: Counter[tuple[int, int]] = Counter()
    for path in pcap_files:
        for _, _, frame in read_pcap_packets(path):
            meta = parse_ipv4_packet(frame)
            if not meta or meta["proto"] != 17:
                continue
            flow = (int(meta["src_port"]), int(meta["dst_port"]))
            flow_counts[flow] += 1
            payload_info = validate_unitree_payload(meta.get("udp_payload", b""))
            if payload_info["valid"]:
                valid_counts[flow] += 1

    return {
        flow
        for flow, valid_count in valid_counts.items()
        if valid_count >= min_packets
        and valid_count / max(flow_counts[flow], 1) >= min_valid_ratio
    }


def validate_unitree_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, (bytes, bytearray)):
        return {"valid": False, "reason": "not_udp", "msg_type": None}
    if len(payload) < 12:
        return {"valid": False, "reason": "payload_short", "msg_type": None}
    msg_type = payload[0]
    sub_type = payload[1]
    data_len = int.from_bytes(payload[4:8], "little")
    if msg_type not in VALID_MSGTYPES:
        return {"valid": False, "reason": "invalid_msg_type", "msg_type": msg_type}
    if sub_type not in VALID_SUBTYPES:
        return {"valid": False, "reason": "invalid_sub_type", "msg_type": msg_type}
    if data_len != len(payload) - 12:
        return {"valid": False, "reason": "data_len_mismatch", "msg_type": msg_type}
    if len(payload) not in EXPECTED_PAYLOAD_LENGTHS.get(msg_type, {len(payload)}):
        return {"valid": False, "reason": "unexpected_payload_len", "msg_type": msg_type}
    return {
        "valid": True,
        "reason": "ok",
        "msg_type": msg_type,
        "payload_len": len(payload),
    }


def extract_payload_records(
    path: str | Path,
    *,
    control_flows: set[tuple[int, int]] | None,
) -> tuple[np.ndarray, np.ndarray, list[int]]:
    payloads, timestamps, msg_types = _collect_payload_records(path, control_flows)
    if not payloads and control_flows:
        payloads, timestamps, msg_types = _collect_payload_records(path, None)
    if not payloads:
        return np.empty((0, PAYLOAD_PAD_LEN), dtype=np.float32), np.empty(0), []
    ts_array = np.asarray(timestamps, dtype=float)
    ts_array = ts_array - ts_array[0]
    return np.vstack(payloads), ts_array, msg_types


def _collect_payload_records(
    path: str | Path,
    control_flows: set[tuple[int, int]] | None,
) -> tuple[list[np.ndarray], list[float], list[int]]:
    payloads: list[np.ndarray] = []
    timestamps: list[float] = []
    msg_types: list[int] = []
    for ts, _, frame in read_pcap_packets(path):
        meta = parse_ipv4_packet(frame)
        if not meta or meta["proto"] != 17:
            continue
        flow = (int(meta["src_port"]), int(meta["dst_port"]))
        if control_flows and flow not in control_flows:
            continue
        payload = meta.get("udp_payload", b"")
        info = validate_unitree_payload(payload)
        if not info["valid"]:
            continue
        padded = bytes(payload[:PAYLOAD_PAD_LEN]) + b"\x00" * max(0, PAYLOAD_PAD_LEN - len(payload))
        payloads.append(
            np.frombuffer(padded[:PAYLOAD_PAD_LEN], dtype=np.uint8).astype(np.float32) / 255.0
        )
        timestamps.append(ts)
        msg_types.append(int(info["msg_type"]))
    return payloads, timestamps, msg_types


def payload_feature_vector(
    payloads: np.ndarray,
    timestamps: np.ndarray,
    msg_types: list[int],
) -> np.ndarray:
    if len(payloads) == 0:
        return np.zeros(PAYLOAD_PAD_LEN * 4 + 16, dtype=np.float32)
    diffs = np.diff(payloads, axis=0) if len(payloads) > 1 else np.zeros((1, PAYLOAD_PAD_LEN))
    counts = np.asarray([msg_types.count(msg_type) for msg_type in MSG_TYPES], dtype=np.float32)
    ratios = counts / max(len(msg_types), 1)
    duration = float(timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0
    return np.concatenate(
        [
            payloads.mean(axis=0),
            payloads.std(axis=0),
            np.abs(diffs).mean(axis=0),
            np.abs(diffs).std(axis=0),
            counts / 1000.0,
            ratios,
            np.asarray(
                [len(payloads) / 1000.0, duration, float(payloads.mean()), float(payloads.std())],
                dtype=np.float32,
            ),
        ]
    ).astype(np.float32)


def learn_controller_command_map(
    data_dir: str | Path,
    *,
    payload_len: int = 12,
    min_label_support: float = 0.6,
    duplicate_window_s: float = 0.2,
    max_occurrences_per_file: int = 4,
) -> tuple[dict[str, str], dict[str, object]]:
    by_label: defaultdict[str, list[dict[str, list[float]]]] = defaultdict(list)
    for label, path in iter_pcaps(data_dir):
        if path.suffix.lower() != ".pcap":
            continue
        first_ts = None
        payload_times: defaultdict[str, list[float]] = defaultdict(list)
        for ts, _, frame in read_pcap_packets(path):
            if first_ts is None:
                first_ts = ts
            meta = parse_ipv4_packet(frame)
            if not meta or meta.get("proto") != 17:
                continue
            payload = bytes(meta.get("udp_payload", b""))
            if len(payload) != payload_len:
                continue
            payload_times[payload.hex()].append(ts - first_ts)
        by_label[str(label)].append(dict(payload_times))

    label_support: defaultdict[str, Counter[str]] = defaultdict(Counter)
    burst_support: defaultdict[str, Counter[str]] = defaultdict(Counter)
    occurrence_counts: defaultdict[str, defaultdict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for label, files in by_label.items():
        for payload_times in files:
            for payload_hex, times in payload_times.items():
                label_support[label][payload_hex] += 1
                occurrence_counts[label][payload_hex].append(len(times))
                if any(
                    right - left <= duplicate_window_s
                    for left, right in zip(times, times[1:])
                ):
                    burst_support[label][payload_hex] += 1

    command_map: dict[str, str] = {}
    rows = []
    for label, files in sorted(by_label.items()):
        required = max(2, ceil(len(files) * min_label_support))
        candidates = []
        for payload_hex, support in label_support[label].items():
            other_support = sum(
                supports.get(payload_hex, 0)
                for other_label, supports in label_support.items()
                if other_label != label
            )
            counts = occurrence_counts[label][payload_hex]
            median_count = float(np.median(counts)) if counts else 0.0
            bursts = int(burst_support[label][payload_hex])
            if (
                support >= required
                and bursts >= required
                and other_support == 0
                and median_count <= max_occurrences_per_file
            ):
                candidates.append(
                    {
                        "payload_hex": payload_hex,
                        "support": int(support),
                        "burst_support": bursts,
                        "median_occurrences": median_count,
                    }
                )
        candidates.sort(
            key=lambda item: (
                -int(item["support"]),
                abs(float(item["median_occurrences"]) - 2.0),
                str(item["payload_hex"]),
            )
        )
        if candidates:
            command_map[str(candidates[0]["payload_hex"])] = canonical_action_label(label)
        rows.append(
            {
                "label": label,
                "files": len(files),
                "required_support": required,
                "candidates": candidates,
                "selected": candidates[0]["payload_hex"] if candidates else None,
            }
        )
    return command_map, {
        "payload_len": payload_len,
        "duplicate_window_s": duplicate_window_s,
        "signatures": command_map,
        "rows": rows,
    }


def predict_controller_command_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    dedupe_window_s: float = 0.5,
    joystick_gap_s: float = 0.6,
    joystick_min_packets: int = 20,
    joystick_min_duration_s: float = 0.25,
) -> dict[str, object]:
    command_map = dict(getattr(model, "controller_command_map", None) or {})
    if not command_map:
        return {
            "status": "NO_COMMAND_MAP",
            "pcap_file": str(pcap_path),
            "method": "controller_command",
            "actions": [],
        }

    first_ts = None
    raw_events = []
    joystick_packets: list[float] = []
    for ts, _, frame in read_pcap_packets(pcap_path):
        if first_ts is None:
            first_ts = ts
        meta = parse_ipv4_packet(frame)
        if not meta or meta.get("proto") != 17:
            continue
        payload = bytes(meta.get("udp_payload", b""))
        payload_hex = payload.hex()
        label = command_map.get(payload_hex)
        if label is not None:
            raw_events.append(
                {
                    "label": label,
                    "status": "NORMAL",
                    "confidence": 1.0,
                    "t_start_s": float(ts - first_ts),
                    "t_end_s": float(ts - first_ts),
                    "duration_s": 0.0,
                    "payload_hex": payload_hex,
                    "src": meta.get("src"),
                    "dst": meta.get("dst"),
                    "src_port": meta.get("src_port"),
                    "dst_port": meta.get("dst_port"),
                    "source": "fixed_signature",
                }
            )
        if (
            meta.get("dst_port") == 43893
            and len(payload) == 12
            and payload[0] in {0x30, 0x31}
        ):
            joystick_packets.append(float(ts - first_ts))

    actions = []
    for event in raw_events:
        if (
            actions
            and event["label"] == actions[-1]["label"]
            and float(event["t_start_s"]) - float(actions[-1]["t_start_s"])
            <= dedupe_window_s
        ):
            actions[-1]["duplicate_packets"] = int(actions[-1].get("duplicate_packets", 1)) + 1
            actions[-1]["t_end_s"] = event["t_end_s"]
            continue
        event["duplicate_packets"] = 1
        actions.append(event)

    joystick_segments: list[list[float]] = []
    for event_time in joystick_packets:
        if (
            not joystick_segments
            or event_time - joystick_segments[-1][-1] > joystick_gap_s
        ):
            joystick_segments.append([event_time])
        else:
            joystick_segments[-1].append(event_time)
    for segment in joystick_segments:
        start = segment[0]
        end = segment[-1]
        if (
            len(segment) < joystick_min_packets
            or end - start < joystick_min_duration_s
        ):
            continue
        actions.append(
            {
                "label": MOVEMENT_ACTION_LABEL,
                "status": "NORMAL",
                "confidence": 1.0,
                "t_start_s": start,
                "t_end_s": end,
                "duration_s": end - start,
                "packet_count": len(segment),
                "source": "joystick_0x30_0x31",
            }
        )

    actions.sort(key=lambda item: float(item["t_start_s"]))
    result = {
        "status": "OK" if actions else "NO_COMMAND_EVENTS",
        "pcap_file": str(pcap_path),
        "method": "controller_command_with_joystick",
        "dedupe_window_s": dedupe_window_s,
        "joystick_gap_s": joystick_gap_s,
        "actions": actions,
        "raw_event_count": len(raw_events),
        "joystick_segment_count": sum(
            1 for action in actions if action.get("source") == "joystick_0x30_0x31"
        ),
    }
    return _canonicalize_sequence_result(result)


def train_amnar_payload_model(
    data_dir: str | Path,
    *,
    control_flows: set[tuple[int, int]],
) -> tuple[object, list[str], dict[str, list[float]], dict[str, object]]:
    try:
        from sklearn.ensemble import ExtraTreesClassifier
    except ImportError as exc:
        raise RuntimeError("scikit-learn is required for AMNAR payload model") from exc

    x_rows: list[np.ndarray] = []
    labels: list[str] = []
    durations: dict[str, list[float]] = defaultdict(list)
    rows: list[dict[str, object]] = []
    for label, path in iter_pcaps(data_dir):
        if path.suffix.lower() != ".pcap":
            continue
        payloads, timestamps, msg_types = extract_payload_records(path, control_flows=control_flows)
        if len(payloads) == 0:
            continue
        x_rows.append(payload_feature_vector(payloads, timestamps, msg_types))
        labels.append(label)
        duration = float(timestamps[-1]) if len(timestamps) else 0.0
        durations[label].append(duration)
        rows.append(
            {
                "label": label,
                "sample": path.stem,
                "payload_packets": int(len(payloads)),
                "duration_s": duration,
            }
        )
    if len(set(labels)) < 2:
        raise ValueError("Need at least two labels with valid payloads for AMNAR payload model")

    model = ExtraTreesClassifier(
        n_estimators=800,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(np.vstack(x_rows), np.asarray(labels))
    return model, [str(item) for item in model.classes_], dict(durations), {
        "samples": len(labels),
        "labels": sorted(set(labels)),
        "control_flows": [
            {"src_port": src_port, "dst_port": dst_port}
            for src_port, dst_port in sorted(control_flows)
        ],
        "rows": rows,
    }


def train_amnar_window_model(
    data_dir: str | Path,
    *,
    control_flows: set[tuple[int, int]],
    window_s: float = 2.5,
    step_s: float = 1.0,
    min_packets: int = 80,
) -> tuple[object, dict[str, object]]:
    try:
        from sklearn.ensemble import ExtraTreesClassifier
    except ImportError as exc:
        raise RuntimeError("scikit-learn is required for AMNAR window model") from exc

    x_rows: list[np.ndarray] = []
    labels: list[str] = []
    rows: list[dict[str, object]] = []
    for label, path in iter_pcaps(data_dir):
        if path.suffix.lower() != ".pcap":
            continue
        payloads, timestamps, msg_types = extract_payload_records(path, control_flows=control_flows)
        if len(payloads) == 0:
            continue
        duration = float(timestamps[-1]) if len(timestamps) else 0.0
        starts = np.arange(0.0, max(duration - 0.1, 0.0), step_s)
        sample_count = 0
        for start_t in starts:
            end_t = min(duration, start_t + window_s)
            mask = (timestamps >= start_t) & (timestamps < end_t)
            if int(mask.sum()) < min_packets:
                continue
            selected_msg_types = [msg for msg, keep in zip(msg_types, mask) if keep]
            rel_ts = timestamps[mask] - timestamps[mask][0]
            x_rows.append(payload_feature_vector(payloads[mask], rel_ts, selected_msg_types))
            labels.append(label)
            sample_count += 1
        rows.append(
            {
                "label": label,
                "sample": path.stem,
                "duration_s": duration,
                "windows": sample_count,
            }
        )

    if len(set(labels)) < 2:
        raise ValueError("Need at least two labels with valid windows for AMNAR window model")

    model = ExtraTreesClassifier(
        n_estimators=900,
        random_state=43,
        class_weight="balanced",
        min_samples_leaf=2,
    )
    model.fit(np.vstack(x_rows), np.asarray(labels))
    return model, {
        "windows": len(labels),
        "labels": sorted(set(labels)),
        "window_s": window_s,
        "step_s": step_s,
        "min_packets": min_packets,
        "rows": rows,
    }


def train_traffic_profile_model(
    grouped_rows: dict[tuple[str, str], list[dict[str, object]]],
    feature_columns: list[str],
) -> tuple[object | None, dict[str, object] | None]:
    try:
        from sklearn.ensemble import ExtraTreesClassifier
    except ImportError as exc:
        raise RuntimeError("scikit-learn is required for traffic profile model") from exc

    x_rows: list[np.ndarray] = []
    labels: list[str] = []
    rows: list[dict[str, object]] = []
    for (label, sample), sample_rows in sorted(grouped_rows.items()):
        if not sample_rows:
            continue
        x_rows.append(_traffic_profile_vector(sample_rows, feature_columns))
        labels.append(label)
        rows.append({"label": label, "sample": sample, "windows": len(sample_rows)})

    if len(set(labels)) < 2:
        return None, None

    model = ExtraTreesClassifier(
        n_estimators=800,
        random_state=42,
        class_weight="balanced",
    )
    x = np.vstack(x_rows)
    model.fit(x, labels)
    predictions = model.predict(x)
    report = {
        "samples": len(labels),
        "labels": sorted(set(labels)),
        "training_accuracy": float(np.mean(np.asarray(predictions) == np.asarray(labels))),
        "rows": rows,
    }
    return model, report


def predict_amnar_payload(
    model: MotionModel,
    pcap_path: str | Path,
) -> dict[str, object] | None:
    if model.amnar_model is None:
        return None
    payloads, timestamps, msg_types = extract_payload_records(
        pcap_path,
        control_flows=model.control_flows,
    )
    if len(payloads) == 0:
        return None
    fv = payload_feature_vector(payloads, timestamps, msg_types)
    pred = str(model.amnar_model.predict(fv.reshape(1, -1))[0])
    result: dict[str, object] = {
        "predicted": pred,
        "payload_packets": int(len(payloads)),
        "duration_s": float(timestamps[-1]) if len(timestamps) else 0.0,
    }
    if hasattr(model.amnar_model, "predict_proba"):
        probs = model.amnar_model.predict_proba(fv.reshape(1, -1))[0]
        classes = [str(cls) for cls in model.amnar_model.classes_]
        result["confidence"] = float(max(probs))
        result["proba"] = dict(sorted((label, float(prob)) for label, prob in zip(classes, probs)))
    return _canonicalize_prediction(result, label_key="predicted")


def predict_traffic_profile(
    model: MotionModel,
    rows: list[dict[str, float]],
) -> dict[str, object] | None:
    classifier = getattr(model, "traffic_model", None)
    if classifier is None or not rows:
        return None
    fv = _traffic_profile_vector(rows, model.feature_columns)
    pred = str(classifier.predict(fv.reshape(1, -1))[0])
    result: dict[str, object] = {"predicted": pred}
    if hasattr(classifier, "predict_proba"):
        probs = classifier.predict_proba(fv.reshape(1, -1))[0]
        classes = [str(cls) for cls in classifier.classes_]
        result["confidence"] = float(max(probs))
        result["proba"] = dict(sorted((label, float(prob)) for label, prob in zip(classes, probs)))
    return _canonicalize_prediction(result, label_key="predicted")


def extract_window_features(
    path: str | Path,
    *,
    local_ips: set[str],
    window_ms: int,
    include_ports: set[int] | None = None,
    exclude_ports: set[int] | None = None,
    clean_mode: str = "none",
    control_flows: set[tuple[int, int]] | None = None,
) -> tuple[list[dict[str, float]], dict[str, float]]:
    window_s = window_ms / 1000.0
    windows: defaultdict[int, dict[str, object]] = defaultdict(_empty_window)
    first_ts: float | None = None
    raw_packets = 0
    kept_packets = 0
    invalid_payloads = 0

    for ts, length, frame in read_pcap_packets(path):
        raw_packets += 1
        meta = parse_ipv4_packet(frame)
        if not _packet_allowed(meta, include_ports, exclude_ports):
            continue
        payload_info = validate_unitree_payload(meta.get("udp_payload", b""))
        if clean_mode == "protocol":
            flow = (int(meta["src_port"]), int(meta["dst_port"]))
            if control_flows and flow not in control_flows:
                continue
            if not payload_info["valid"]:
                invalid_payloads += 1
                continue
        kept_packets += 1
        if first_ts is None:
            first_ts = ts
        idx = int((ts - first_ts) / window_s)
        w = windows[idx]
        w["pkt_count"] = int(w["pkt_count"]) + 1
        w["byte_count"] = int(w["byte_count"]) + length

        direction = _packet_direction(meta, local_ips)
        w[f"{direction}_pkt_count"] = int(w[f"{direction}_pkt_count"]) + 1
        w[f"{direction}_bytes"] = int(w[f"{direction}_bytes"]) + length

        if meta["proto"] == 6:
            w["tcp_count"] = int(w["tcp_count"]) + 1
        elif meta["proto"] == 17:
            w["udp_count"] = int(w["udp_count"]) + 1
        if length <= 128:
            w["small_count"] = int(w["small_count"]) + 1
        if length >= 1000:
            w["large_count"] = int(w["large_count"]) + 1
        if payload_info["valid"]:
            msg_type = int(payload_info["msg_type"])
            w["valid_payload_count"] = int(w["valid_payload_count"]) + 1
            w["payload_byte_count"] = int(w["payload_byte_count"]) + int(payload_info["payload_len"])
            w[f"msg_type_{msg_type:02x}_count"] = int(w[f"msg_type_{msg_type:02x}_count"]) + 1
        w["sizes"].append(length)
        w["times"].append(ts)

    if not windows:
        return [], {"raw_packets": raw_packets, "kept_packets": kept_packets, "duration_s": 0.0}

    rows: list[dict[str, float]] = []
    for idx in range(max(windows) + 1):
        w = windows[idx]
        sizes = np.asarray(w["sizes"], dtype=float)
        times = np.asarray(w["times"], dtype=float)
        pkt_count = int(w["pkt_count"])
        valid_payload_count = int(w["valid_payload_count"])
        iats = np.diff(times) * 1000 if len(times) > 1 else np.asarray([0.0])
        mean_len = float(sizes.mean()) if sizes.size else 0.0
        std_len = float(sizes.std()) if sizes.size else 0.0
        mean_iat = float(iats.mean()) if pkt_count else 0.0
        std_iat = float(iats.std()) if pkt_count else 0.0
        row = {
                "window_idx": float(idx),
                "t_start_s": float(idx * window_s),
                "pkt_count": float(pkt_count),
                "byte_count": float(w["byte_count"]),
                "up_pkt_count": float(w["up_pkt_count"]),
                "down_pkt_count": float(w["down_pkt_count"]),
                "up_bytes": float(w["up_bytes"]),
                "down_bytes": float(w["down_bytes"]),
                "tcp_count": float(w["tcp_count"]),
                "udp_count": float(w["udp_count"]),
                "small_count": float(w["small_count"]),
                "large_count": float(w["large_count"]),
                "mean_len": mean_len,
                "std_len": std_len,
                "mean_iat_ms": mean_iat,
                "std_iat_ms": std_iat,
                "byte_rate": float(w["byte_count"]) / max(window_s, 1e-9),
                "direction_balance": (
                    float(w["up_pkt_count"]) - float(w["down_pkt_count"])
                )
                / max(pkt_count, 1),
                "len_cv": std_len / max(mean_len, 1.0),
                "iat_cv": std_iat / max(mean_iat, 1.0),
                "small_ratio": float(w["small_count"]) / max(pkt_count, 1),
                "large_ratio": float(w["large_count"]) / max(pkt_count, 1),
                "valid_payload_count": float(valid_payload_count),
                "valid_payload_ratio": float(valid_payload_count / max(pkt_count, 1)),
                "payload_byte_count": float(w["payload_byte_count"]),
            }
        for msg_type in MSG_TYPES:
            count = int(w[f"msg_type_{msg_type:02x}_count"])
            row[f"msg_type_{msg_type:02x}_count"] = float(count)
            row[f"msg_type_{msg_type:02x}_ratio"] = float(count / max(valid_payload_count, 1))
        rows.append(row)
    return rows, {
        "raw_packets": raw_packets,
        "kept_packets": kept_packets,
        "invalid_payloads": invalid_payloads,
        "duration_s": float(len(rows) * window_s),
    }


def train_motion_model(
    data_dir: str | Path,
    *,
    window_ms: int = 100,
    clusters: int = 8,
    include_ports: set[int] | None = None,
    exclude_ports: set[int] | None = None,
    clean_mode: str = "none",
    max_templates_per_action: int = 2,
    threshold_quantile: float = 0.85,
    threshold_floor: float = 0.20,
    threshold_padding: float = 0.12,
    train_signal: bool = True,
    train_amnar: bool = True,
    signal_bin_size: float = 0.02,
    signal_protocol: Protocol = "all",
    signal_positive_ip: str | None = None,
    signal_length_mode: LengthMode = "packet",
    signal_classifier: str = "rf",
) -> tuple[MotionModel, dict[str, object]]:
    data_dir = Path(data_dir)
    pcap_files = sorted(path for _, path in iter_pcaps(data_dir) if path.suffix.lower() == ".pcap")
    if not pcap_files:
        raise ValueError(f"No classic .pcap files found under {data_dir}")

    exclude_ports = set(exclude_ports or {22})
    local_ips = discover_local_ips(pcap_files)
    discovered_control_flows = discover_control_flows(pcap_files)
    control_flows = discovered_control_flows if clean_mode == "protocol" else None
    feature_columns = (
        list(PROTOCOL_FEATURE_COLUMNS)
        if clean_mode == "protocol"
        else list(DEFAULT_FEATURE_COLUMNS)
    )
    all_rows: list[dict[str, object]] = []
    sample_rows: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []

    for label, path in iter_pcaps(data_dir):
        if path.suffix.lower() != ".pcap":
            continue
        rows, summary = extract_window_features(
            path,
            local_ips=local_ips,
            window_ms=window_ms,
            include_ports=include_ports,
            exclude_ports=exclude_ports,
            clean_mode=clean_mode,
            control_flows=control_flows,
        )
        sample = path.stem
        for row in rows:
            row.update({"label": label, "sample": sample, "source_file": str(path)})
            all_rows.append(row)
        summaries.append({"label": label, "sample": sample, "source_file": str(path), **summary})

    if not all_rows:
        raise ValueError("No valid IPv4 TCP/UDP packets found in training pcaps")

    x = _feature_matrix(all_rows, feature_columns)
    xz, mean, std = _standardize(_feature_transform(x))
    clusters = max(2, min(clusters, len(xz)))
    labels, centroids = _fit_kmeans(xz, clusters)
    for row, cluster in zip(all_rows, labels):
        row["cluster"] = int(cluster)
        row["symbol"] = chr(ord("A") + int(cluster))

    by_sample: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in all_rows:
        by_sample[(str(row["label"]), str(row["sample"]))].append(row)
    for (label, sample), rows in sorted(by_sample.items()):
        seq = compress_symbols([str(row["symbol"]) for row in sorted(rows, key=lambda r: r["window_idx"])])
        sample_rows.append({"label": label, "sample": sample, "length": len(seq), "sequence": seq})

    templates = _build_templates(sample_rows, max_templates=max_templates_per_action)
    score_rows = _score_samples(sample_rows, templates)
    thresholds = _compute_thresholds(
        score_rows,
        threshold_quantile,
        threshold_floor,
        threshold_padding,
    )
    for row in score_rows:
        row["threshold"] = thresholds[str(row["label"])]
        row["is_anomaly"] = float(row["anomaly_score"]) > float(row["threshold"])

    signal_model = None
    signal_report = None
    if train_signal:
        items = load_dataset(
            data_dir,
            bin_size=signal_bin_size,
            protocol=signal_protocol,
            positive_ip=signal_positive_ip,
            length_mode=signal_length_mode,
        )
        signal_model = train_action_model(
            items,
            bin_size=signal_bin_size,
            protocol=signal_protocol,
            length_mode=signal_length_mode,
            classifier_name=signal_classifier,
            trim=True,
        )
        signal_report = {
            "samples": len(items),
            "labels": sorted({item.label for item in items}),
            "bin_size": signal_bin_size,
            "protocol": signal_protocol,
            "length_mode": signal_length_mode,
            "classifier": signal_classifier,
        }

    amnar_model = None
    amnar_labels = None
    amnar_durations = None
    amnar_window_model = None
    amnar_report = None
    amnar_window_report = None
    controller_command_map, controller_command_report = learn_controller_command_map(data_dir)
    traffic_model, traffic_report = train_traffic_profile_model(by_sample, feature_columns)
    if train_amnar and discovered_control_flows:
        amnar_model, amnar_labels, amnar_durations, amnar_report = train_amnar_payload_model(
            data_dir,
            control_flows=discovered_control_flows,
        )
        amnar_window_model, amnar_window_report = train_amnar_window_model(
            data_dir,
            control_flows=discovered_control_flows,
        )

    model = MotionModel(
        centroids=centroids,
        mean=mean,
        std=std,
        templates=templates,
        thresholds=thresholds,
        feature_columns=feature_columns,
        local_ips=local_ips,
        window_ms=window_ms,
        include_ports=include_ports,
        exclude_ports=exclude_ports,
        clean_mode=clean_mode,
        control_flows=discovered_control_flows,
        signal_model=signal_model,
        amnar_model=amnar_model,
        amnar_labels=amnar_labels,
        amnar_durations=amnar_durations,
        amnar_window_model=amnar_window_model,
        traffic_model=traffic_model,
        controller_command_map=controller_command_map,
    )
    report = _training_report(
        all_rows=all_rows,
        sample_rows=sample_rows,
        score_rows=score_rows,
        summaries=summaries,
        model=model,
        signal_report=signal_report,
        amnar_report=amnar_report,
        amnar_window_report=amnar_window_report,
        traffic_report=traffic_report,
    )
    report["controller_command_report"] = controller_command_report
    return model, report


def predict_motion_pcap(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    signal_fusion: str = "compare",
    signal_confidence: float = 0.60,
) -> dict[str, object]:
    rows, metadata = extract_window_features(
        pcap_path,
        local_ips=model.local_ips,
        window_ms=model.window_ms,
        include_ports=model.include_ports,
        exclude_ports=model.exclude_ports,
        clean_mode=model.clean_mode,
        control_flows=model.control_flows,
    )
    if not rows:
        return {"status": "NO_DATA", "pcap_file": str(pcap_path), "metadata": metadata}

    sequence = symbolize_rows(model, rows)
    motion_result = classify_sequence(model, sequence)
    signal_result = None
    if model.signal_model is not None:
        signal_result = predict_signal_pcap(model.signal_model, pcap_path)
        _canonicalize_prediction(signal_result, label_key="predicted")
    amnar_result = predict_amnar_payload(model, pcap_path)
    traffic_result = predict_traffic_profile(model, rows)
    _canonicalize_prediction(motion_result, label_key="label")

    if amnar_result:
        final_label = amnar_result["predicted"]
        final_status = "NORMAL"
        fusion_reason = "amnar_payload_primary"
    elif traffic_result:
        final_label = traffic_result["predicted"]
        final_status = "NORMAL"
        fusion_reason = "traffic_profile_fallback"
    else:
        final_label = motion_result["label"]
        final_status = motion_result["status"]
        fusion_reason = "motion_only"

    if signal_result and signal_fusion == "signal_primary":
        if float(signal_result.get("confidence") or 0.0) >= signal_confidence:
            final_label = str(signal_result["predicted"])
            final_status = "NORMAL"
            fusion_reason = "signal_primary"
    elif signal_result and signal_fusion == "disagree":
        if (
            float(signal_result.get("confidence") or 0.0) >= signal_confidence
            and signal_result.get("predicted") != motion_result["label"]
        ):
            final_status = "ANOMALY"
            fusion_reason = "signal_disagrees_with_motion"
    elif signal_result:
        fusion_reason = "reported_side_by_side"

    return {
        "status": final_status,
        "label": final_label,
        "pcap_file": str(pcap_path),
        "sequence": sequence,
        "metadata": metadata,
        "motion": motion_result,
        "amnar": amnar_result,
        "traffic": traffic_result,
        "signal": signal_result,
        "fusion": {"mode": signal_fusion, "reason": fusion_reason},
    }


def predict_action_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    method: str = "dp",
    transcript: list[str] | None = None,
    min_segment_s: float = 0.25,
    max_segment_s: float | None = None,
    step_s: float = 0.5,
    segment_penalty: float = 0.02,
    gap_windows: int = 5,
    active_quantile: float = 0.25,
) -> dict[str, object]:
    result = _predict_action_sequence_raw(
        model,
        pcap_path,
        method=method,
        transcript=transcript,
        min_segment_s=min_segment_s,
        max_segment_s=max_segment_s,
        step_s=step_s,
        segment_penalty=segment_penalty,
        gap_windows=gap_windows,
        active_quantile=active_quantile,
    )
    return _canonicalize_sequence_result(result)


def _predict_action_sequence_raw(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    method: str = "dp",
    transcript: list[str] | None = None,
    min_segment_s: float = 0.25,
    max_segment_s: float | None = None,
    step_s: float = 0.5,
    segment_penalty: float = 0.02,
    gap_windows: int = 5,
    active_quantile: float = 0.25,
) -> dict[str, object]:
    if method == "command":
        return predict_controller_command_sequence(model, pcap_path)

    if method == "scan":
        if model.amnar_model is None:
            return {
                "status": "NO_AMNAR_MODEL",
                "pcap_file": str(pcap_path),
                "method": "amnar_scan",
                "actions": [],
            }
        return predict_amnar_scan_sequence(
            model,
            pcap_path,
            window_s=max(0.5, max_segment_s or 2.5),
            step_s=step_s,
            min_run_s=max(0.5, min_segment_s),
        )

    if method == "scripted":
        normalized_transcript = normalize_transcript(
            transcript or preset_transcript_for_pcap(pcap_path),
            allowed_labels=_amnar_classes(model),
        )
        if not normalized_transcript:
            return {
                "status": "NO_TRANSCRIPT",
                "pcap_file": str(pcap_path),
                "method": "scripted",
                "actions": [],
            }
        if model.amnar_model is not None:
            result = predict_constrained_amnar_action_sequence(
                model,
                pcap_path,
                transcript=normalized_transcript,
                min_segment_s=min_segment_s,
                max_segment_s=max_segment_s,
            )
            if result["status"] == "OK":
                return result
            return predict_constrained_motion_action_sequence(
                model,
                pcap_path,
                transcript=normalized_transcript,
                min_segment_s=min_segment_s,
                max_segment_s=max_segment_s,
                fallback_from=str(result["status"]),
            )
        return {
            "status": "NO_AMNAR_MODEL",
            "pcap_file": str(pcap_path),
            "method": "scripted",
            "transcript": normalized_transcript,
            "actions": [],
        }

    if model.amnar_model is not None and method == "dp":
        result = predict_amnar_action_sequence(
            model,
            pcap_path,
            step_s=step_s,
            min_segment_s=min_segment_s,
            max_segment_s=max_segment_s,
            segment_penalty=segment_penalty,
        )
        if result["status"] == "OK":
            return result

    rows, metadata = extract_window_features(
        pcap_path,
        local_ips=model.local_ips,
        window_ms=model.window_ms,
        include_ports=model.include_ports,
        exclude_ports=model.exclude_ports,
        clean_mode=model.clean_mode,
        control_flows=model.control_flows,
    )
    if not rows:
        return {"status": "NO_DATA", "pcap_file": str(pcap_path), "metadata": metadata}
    symbols = [symbolize_row(model, row) for row in rows]

    if method == "activity":
        segments = _activity_segments(
            rows,
            min_segment_windows=max(1, int(min_segment_s / (model.window_ms / 1000.0))),
            gap_windows=gap_windows,
            active_quantile=active_quantile,
        )
        predictions = []
        for start, end in segments:
            seq = compress_symbols(symbols[start:end])
            item = classify_sequence(model, seq)
            item.update(_segment_times(rows, start, end))
            predictions.append(item)
    else:
        sequence = compress_symbols(symbols)
        predictions = _dp_segment_sequence(
            model,
            sequence,
            max_segment_s=max_segment_s,
        )
        for item in predictions:
            start = int(item["start_symbol"])
            end = int(item["end_symbol"])
            item["t_start_s"] = start * model.window_ms / 1000.0
            item["t_end_s"] = end * model.window_ms / 1000.0
            item["duration_s"] = item["t_end_s"] - item["t_start_s"]

    return {
        "status": "OK",
        "pcap_file": str(pcap_path),
        "method": method,
        "metadata": metadata,
        "actions": predictions,
    }


def predict_amnar_scan_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    window_s: float = 2.5,
    step_s: float = 1.0,
    min_run_s: float = 1.5,
) -> dict[str, object]:
    payloads, timestamps, msg_types = extract_payload_records(
        pcap_path,
        control_flows=model.control_flows,
    )
    if len(payloads) == 0:
        return {
            "status": "NO_DATA",
            "pcap_file": str(pcap_path),
            "method": "amnar_scan",
            "actions": [],
        }

    classifier = model.amnar_window_model or model.amnar_model
    classes = [str(cls) for cls in classifier.classes_]
    duration = float(timestamps[-1])
    starts = np.arange(0.0, max(duration - 0.1, 0.0), step_s)
    windows = []
    for start_t in starts:
        end_t = min(duration, start_t + window_s)
        mask = (timestamps >= start_t) & (timestamps < end_t)
        if int(mask.sum()) < 80:
            continue
        selected_msg_types = [msg for msg, keep in zip(msg_types, mask) if keep]
        rel_ts = timestamps[mask] - timestamps[mask][0]
        fv = payload_feature_vector(payloads[mask], rel_ts, selected_msg_types)
        probs = classifier.predict_proba(fv.reshape(1, -1))[0]
        best_idx = int(np.argmax(probs))
        windows.append(
            {
                "label": classes[best_idx],
                "confidence": float(probs[best_idx]),
                "t_start_s": float(start_t),
                "t_end_s": float(end_t),
                "proba": dict(
                    sorted(
                        ((label, float(prob)) for label, prob in zip(classes, probs)),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:5]
                ),
            }
        )

    if not windows:
        return {
            "status": "NO_WINDOWS",
            "pcap_file": str(pcap_path),
            "method": "amnar_scan",
            "actions": [],
        }

    smoothed_labels = _smooth_labels([str(item["label"]) for item in windows], radius=1)
    actions = []
    start_idx = 0
    for idx in range(1, len(windows) + 1):
        if idx < len(windows) and smoothed_labels[idx] == smoothed_labels[start_idx]:
            continue
        label = smoothed_labels[start_idx]
        group = windows[start_idx:idx]
        t_start = float(group[0]["t_start_s"])
        t_end = float(group[-1]["t_end_s"])
        confidence = float(np.mean([item["confidence"] for item in group]))
        actions.append(
            {
                "label": label,
                "status": "NORMAL" if confidence >= 0.35 else "LOW_CONFIDENCE",
                "confidence": confidence,
                "t_start_s": t_start,
                "t_end_s": t_end,
                "duration_s": max(0.0, t_end - t_start),
                "windows": len(group),
            }
        )
        start_idx = idx

    actions = _merge_short_scan_runs(actions, min_run_s=min_run_s)
    return {
        "status": "OK",
        "pcap_file": str(pcap_path),
        "method": "amnar_scan",
        "duration_s": duration,
        "window_s": window_s,
        "step_s": step_s,
        "actions": actions,
        "windows": windows,
    }


def predict_constrained_amnar_action_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    transcript: list[str],
    step_s: float = 0.5,
    min_segment_s: float = 0.25,
    max_segment_s: float | None = None,
    low_confidence_threshold: float = 0.05,
) -> dict[str, object]:
    payloads, timestamps, msg_types = extract_payload_records(
        pcap_path,
        control_flows=model.control_flows,
    )
    if len(payloads) == 0:
        return {"status": "NO_DATA", "pcap_file": str(pcap_path), "actions": []}
    classes = [str(cls) for cls in model.amnar_model.classes_]
    if any(label not in classes for label in transcript):
        missing = [label for label in transcript if label not in classes]
        return {
            "status": "BAD_TRANSCRIPT",
            "pcap_file": str(pcap_path),
            "missing_labels": missing,
            "actions": [],
        }

    durations = model.amnar_durations or {}
    known_durations = [
        duration for values in durations.values() for duration in values if duration > 0
    ]
    if max_segment_s is None:
        max_segment_s = min(14.0, max(known_durations) * 1.35) if known_durations else 14.0
    min_segment_s = max(0.25, min_segment_s)

    total_duration = float(timestamps[-1])
    times = np.arange(0.0, total_duration + step_s, step_s)
    if times[-1] < total_duration:
        times = np.append(times, total_duration)
    n = len(times)
    m = len(transcript)
    dp = np.full((m + 1, n), -1e12, dtype=float)
    back: list[list[tuple[int, dict[str, object]] | None]] = [
        [None for _ in range(n)] for _ in range(m + 1)
    ]
    dp[0, 0] = 0.0
    cache: dict[tuple[int, int], dict[str, object] | None] = {}

    def score_segment(start_idx: int, end_idx: int) -> dict[str, object] | None:
        key = (start_idx, end_idx)
        if key in cache:
            return cache[key]
        start_t = times[start_idx]
        end_t = times[end_idx]
        mask = (timestamps >= start_t) & (timestamps < end_t)
        if int(mask.sum()) < 80:
            cache[key] = None
            return None
        selected_msg_types = [msg for msg, keep in zip(msg_types, mask) if keep]
        rel_ts = timestamps[mask] - timestamps[mask][0]
        fv = payload_feature_vector(payloads[mask], rel_ts, selected_msg_types)
        probs = model.amnar_model.predict_proba(fv.reshape(1, -1))[0]
        proba = {label: float(prob) for label, prob in zip(classes, probs)}
        value = {
            "proba": proba,
            "packets": int(mask.sum()),
            "duration_s": float(end_t - start_t),
        }
        cache[key] = value
        return value

    for action_idx, label in enumerate(transcript, 1):
        median_duration = _label_median_duration(model, label)
        for start_idx in range(n):
            if dp[action_idx - 1, start_idx] < -1e11:
                continue
            for end_idx in range(start_idx + 1, n):
                duration = times[end_idx] - times[start_idx]
                if duration < min_segment_s:
                    continue
                if duration > max_segment_s:
                    break
                remaining = m - action_idx
                if remaining and total_duration - times[end_idx] < remaining * min_segment_s:
                    break
                scored = score_segment(start_idx, end_idx)
                if scored is None:
                    continue
                prob = max(float(scored["proba"].get(label, 0.0)), 1e-8)
                duration_penalty = 0.0
                if median_duration:
                    duration_penalty = 0.08 * abs(np.log(duration / median_duration))
                transition_penalty = 0.08 if action_idx > 1 and transcript[action_idx - 2] == label else 0.0
                score = float(np.log(prob) - duration_penalty - transition_penalty)
                candidate = dp[action_idx - 1, start_idx] + score
                if candidate > dp[action_idx, end_idx]:
                    dp[action_idx, end_idx] = candidate
                    back[action_idx][end_idx] = (start_idx, scored)

    tail_start = max(0, n - max(3, int(1.5 / step_s)))
    end_idx = max(range(tail_start, n), key=lambda idx: dp[m, idx])
    if dp[m, end_idx] < -1e11:
        return {
            "status": "NO_PATH",
            "pcap_file": str(pcap_path),
            "method": "scripted_amnar_dp",
            "transcript": transcript,
            "actions": [],
        }

    actions = []
    cursor = end_idx
    for action_idx in range(m, 0, -1):
        item = back[action_idx][cursor]
        if item is None:
            break
        start_idx, scored = item
        label = transcript[action_idx - 1]
        proba = dict(scored["proba"])
        confidence = float(proba.get(label, 0.0))
        actions.append(
            {
                "label": label,
                "status": "NORMAL" if confidence >= low_confidence_threshold else "LOW_CONFIDENCE",
                "confidence": confidence,
                "t_start_s": float(times[start_idx]),
                "t_end_s": float(times[cursor]),
                "duration_s": float(times[cursor] - times[start_idx]),
                "payload_packets": int(scored["packets"]),
                "proba": dict(sorted(proba.items(), key=lambda item: item[1], reverse=True)[:5]),
            }
        )
        cursor = start_idx
    actions.reverse()
    return {
        "status": "OK",
        "pcap_file": str(pcap_path),
        "method": "scripted_amnar_dp",
        "duration_s": total_duration,
        "transcript": transcript,
        "actions": actions,
    }


def predict_constrained_motion_action_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    transcript: list[str],
    min_segment_s: float = 0.25,
    max_segment_s: float | None = None,
    fallback_from: str | None = None,
) -> dict[str, object]:
    rows, metadata = extract_window_features(
        pcap_path,
        local_ips=model.local_ips,
        window_ms=model.window_ms,
        include_ports=model.include_ports,
        exclude_ports=model.exclude_ports,
        clean_mode=model.clean_mode,
        control_flows=model.control_flows,
    )
    if not rows:
        return {
            "status": "NO_DATA",
            "pcap_file": str(pcap_path),
            "method": "scripted_motion_dp",
            "transcript": transcript,
            "fallback_from": fallback_from,
            "metadata": metadata,
            "actions": [],
        }

    symbols = [symbolize_row(model, row) for row in rows]
    sequence = compress_symbols(symbols)
    n = len(sequence)
    m = len(transcript)
    if n == 0 or m == 0:
        return {
            "status": "NO_DATA",
            "pcap_file": str(pcap_path),
            "method": "scripted_motion_dp",
            "transcript": transcript,
            "fallback_from": fallback_from,
            "metadata": metadata,
            "actions": [],
        }

    window_s = model.window_ms / 1000.0
    min_len = max(1, int(min_segment_s / window_s))
    if max_segment_s is None:
        all_lengths = [t.length for templates in model.templates.values() for t in templates]
        max_len = min(n, max(3, int(max(all_lengths) * 1.35))) if all_lengths else n
    else:
        max_len = max(2, int(max_segment_s / window_s))

    dp = np.full((m + 1, n + 1), -1e12, dtype=float)
    back: list[list[tuple[int, MotionTemplate | None, float] | None]] = [
        [None for _ in range(n + 1)] for _ in range(m + 1)
    ]
    dp[0, 0] = 0.0

    for action_idx, label in enumerate(transcript, 1):
        templates = model.templates.get(label, [])
        if not templates:
            return {
                "status": "BAD_TRANSCRIPT",
                "pcap_file": str(pcap_path),
                "method": "scripted_motion_dp",
                "missing_labels": [label],
                "transcript": transcript,
                "fallback_from": fallback_from,
                "metadata": metadata,
                "actions": [],
            }
        for start in range(n + 1):
            if dp[action_idx - 1, start] < -1e11:
                continue
            remaining = m - action_idx
            max_end = min(n - remaining * min_len, start + max_len)
            for end in range(start + min_len, max_end + 1):
                part = sequence[start:end]
                best_template = None
                best_similarity = -1.0
                for template in templates:
                    similarity = sequence_similarity(part, template.sequence)
                    length_ratio = len(part) / max(template.action_avg_length, 1.0)
                    similarity -= abs(np.log(max(length_ratio, 1e-6))) * 0.08
                    if similarity > best_similarity:
                        best_similarity = similarity
                        best_template = template
                repeat_penalty = 0.04 if action_idx > 1 and transcript[action_idx - 2] == label else 0.0
                score = best_similarity - repeat_penalty
                candidate = dp[action_idx - 1, start] + score
                if candidate > dp[action_idx, end]:
                    dp[action_idx, end] = candidate
                    back[action_idx][end] = (start, best_template, best_similarity)

    end = int(np.argmax(dp[m]))
    if dp[m, end] < -1e11:
        return {
            "status": "NO_PATH",
            "pcap_file": str(pcap_path),
            "method": "scripted_motion_dp",
            "transcript": transcript,
            "fallback_from": fallback_from,
            "metadata": metadata,
            "actions": [],
        }

    actions = []
    cursor = end
    for action_idx in range(m, 0, -1):
        item = back[action_idx][cursor]
        if item is None:
            break
        start, template, similarity = item
        label = transcript[action_idx - 1]
        threshold = float(model.thresholds.get(label, 0.5))
        anomaly_score = max(0.0, 1.0 - float(similarity))
        actions.append(
            {
                "label": label,
                "status": "NORMAL" if anomaly_score <= threshold else "LOW_SIMILARITY",
                "similarity": float(similarity),
                "anomaly_score": anomaly_score,
                "threshold": threshold,
                "t_start_s": float(start * window_s),
                "t_end_s": float(cursor * window_s),
                "duration_s": float((cursor - start) * window_s),
                "sequence": sequence[start:cursor],
                "template_sample": template.sample if template else None,
            }
        )
        cursor = start
    actions.reverse()
    return {
        "status": "OK",
        "pcap_file": str(pcap_path),
        "method": "scripted_motion_dp",
        "fallback_from": fallback_from,
        "metadata": metadata,
        "transcript": transcript,
        "actions": actions,
    }


def predict_amnar_action_sequence(
    model: MotionModel,
    pcap_path: str | Path,
    *,
    step_s: float = 0.5,
    min_segment_s: float | None = None,
    max_segment_s: float | None = None,
    segment_penalty: float = 0.18,
    low_confidence_threshold: float = 0.55,
) -> dict[str, object]:
    payloads, timestamps, msg_types = extract_payload_records(
        pcap_path,
        control_flows=model.control_flows,
    )
    if len(payloads) == 0:
        return {"status": "NO_DATA", "pcap_file": str(pcap_path), "actions": []}
    durations = [
        duration
        for values in (model.amnar_durations or {}).values()
        for duration in values
        if duration > 0
    ]
    if min_segment_s is None:
        min_segment_s = max(2.0, min(durations) * 0.75) if durations else 2.0
    if max_segment_s is None:
        max_segment_s = min(13.5, max(durations) * 1.15) if durations else 12.0

    times = np.arange(0.0, float(timestamps[-1]) + step_s, step_s)
    n = len(times)
    dp = [-1e9] * n
    back: list[tuple[int, int, str, float, dict[str, float]] | None] = [None] * n
    dp[0] = 0.0
    classes = [str(cls) for cls in model.amnar_model.classes_]

    cache: dict[tuple[int, int], tuple[str, float, dict[str, float]]] = {}

    def score_candidate(start_idx: int, end_idx: int):
        key = (start_idx, end_idx)
        if key in cache:
            return cache[key]
        start_t = times[start_idx]
        end_t = times[end_idx]
        mask = (timestamps >= start_t) & (timestamps < end_t)
        if int(mask.sum()) < 200:
            return None
        selected_msg_types = [msg for msg, keep in zip(msg_types, mask) if keep]
        rel_ts = timestamps[mask] - timestamps[mask][0]
        fv = payload_feature_vector(payloads[mask], rel_ts, selected_msg_types)
        probs = model.amnar_model.predict_proba(fv.reshape(1, -1))[0]
        best_idx = int(np.argmax(probs))
        proba = {label: float(prob) for label, prob in zip(classes, probs)}
        value = (classes[best_idx], float(probs[best_idx]), proba)
        cache[key] = value
        return value

    for start_idx in range(n):
        if dp[start_idx] < -1e8:
            continue
        for end_idx in range(start_idx + 1, n):
            duration = times[end_idx] - times[start_idx]
            if duration < min_segment_s:
                continue
            if duration > max_segment_s:
                break
            scored = score_candidate(start_idx, end_idx)
            if scored is None:
                continue
            label, confidence, proba = scored
            score = float(np.log(confidence + 1e-6) - segment_penalty)
            if back[start_idx] and back[start_idx][2] == label:
                score -= 0.25
            if dp[start_idx] + score > dp[end_idx]:
                dp[end_idx] = dp[start_idx] + score
                back[end_idx] = (start_idx, end_idx, label, confidence, proba)

    end = max(range(max(0, n - 4), n), key=lambda idx: dp[idx])
    actions = []
    cursor = end
    while cursor > 0 and back[cursor] is not None:
        start_idx, end_idx, label, confidence, proba = back[cursor]
        status = "NORMAL" if confidence >= low_confidence_threshold else "UNKNOWN"
        actions.append(
            {
                "label": label,
                "status": status,
                "confidence": confidence,
                "t_start_s": float(times[start_idx]),
                "t_end_s": float(times[end_idx]),
                "duration_s": float(times[end_idx] - times[start_idx]),
                "proba": dict(sorted(proba.items(), key=lambda item: item[1], reverse=True)[:5]),
            }
        )
        cursor = start_idx
    actions.reverse()
    return {
        "status": "OK",
        "pcap_file": str(pcap_path),
        "method": "amnar_payload_dp",
        "duration_s": float(timestamps[-1]),
        "min_segment_s": float(min_segment_s),
        "max_segment_s": float(max_segment_s),
        "actions": actions,
    }


def preset_transcript_for_pcap(pcap_path: str | Path) -> list[str] | None:
    stem = Path(pcap_path).stem.lower()
    return SEQUENCE_TRANSCRIPT_PRESETS.get(stem)


def normalize_transcript(
    transcript: list[str] | None,
    *,
    allowed_labels: set[str] | None = None,
) -> list[str]:
    if not transcript:
        return []
    normalized = []
    for raw in transcript:
        key = raw.strip()
        if not key:
            continue
        label = ACTION_ALIASES.get(key, ACTION_ALIASES.get(key.lower(), key))
        if allowed_labels is None or label in allowed_labels:
            normalized.append(label)
    return normalized


def _amnar_classes(model: MotionModel) -> set[str] | None:
    if model.amnar_model is None or not hasattr(model.amnar_model, "classes_"):
        return None
    return {str(label) for label in model.amnar_model.classes_}


def _label_median_duration(model: MotionModel, label: str) -> float | None:
    values = [
        duration
        for duration in (model.amnar_durations or {}).get(label, [])
        if duration > 0
    ]
    if not values:
        return None
    return float(np.median(values))


def compare_models(
    model: MotionModel,
    test_dir: str | Path,
    *,
    signal_fusion: str = "compare",
) -> dict[str, object]:
    rows = []
    for label, path in iter_pcaps(test_dir):
        if path.suffix.lower() != ".pcap":
            continue
        pred = predict_motion_pcap(model, path, signal_fusion=signal_fusion)
        raw_truth = label
        label = canonical_action_label(label)
        motion_label = pred.get("motion", {}).get("label")
        amnar_label = (pred.get("amnar") or {}).get("predicted")
        traffic_label = (pred.get("traffic") or {}).get("predicted")
        signal_label = (pred.get("signal") or {}).get("predicted")
        rows.append(
            {
                "file": str(path),
                "truth": label,
                "raw_truth": raw_truth,
                "motion_label": motion_label,
                "motion_status": pred.get("motion", {}).get("status"),
                "motion_similarity": pred.get("motion", {}).get("similarity"),
                "amnar_label": amnar_label,
                "amnar_confidence": (pred.get("amnar") or {}).get("confidence"),
                "traffic_label": traffic_label,
                "traffic_confidence": (pred.get("traffic") or {}).get("confidence"),
                "signal_label": signal_label,
                "signal_confidence": (pred.get("signal") or {}).get("confidence"),
                "final_label": pred.get("label"),
                "final_status": pred.get("status"),
                "motion_correct": motion_label == label,
                "amnar_correct": amnar_label == label if amnar_label is not None else None,
                "traffic_correct": traffic_label == label if traffic_label is not None else None,
                "signal_correct": signal_label == label if signal_label is not None else None,
                "final_correct": pred.get("label") == label,
            }
        )
    return {
        "samples": len(rows),
        "motion_accuracy": _accuracy(rows, "motion_correct"),
        "amnar_accuracy": _accuracy(rows, "amnar_correct"),
        "traffic_accuracy": _accuracy(rows, "traffic_correct"),
        "signal_accuracy": _accuracy(rows, "signal_correct"),
        "final_accuracy": _accuracy(rows, "final_correct"),
        "rows": rows,
    }


def classify_sequence(model: MotionModel, sequence: str) -> dict[str, object]:
    candidates = []
    for label, templates in model.templates.items():
        best_template = None
        best_similarity = -1.0
        for template in templates:
            similarity = sequence_similarity(sequence, template.sequence)
            if similarity > best_similarity:
                best_similarity = similarity
                best_template = template
        threshold = float(model.thresholds.get(label, 0.5))
        anomaly_score = 1.0 - best_similarity
        candidates.append(
            {
                "label": label,
                "similarity": float(best_similarity),
                "anomaly_score": float(anomaly_score),
                "threshold": threshold,
                "is_match": anomaly_score <= threshold,
                "template_sample": best_template.sample if best_template else None,
                "template_sequence": best_template.sequence if best_template else None,
            }
        )
    best = max(candidates, key=lambda item: item["similarity"])
    return {
        "status": "NORMAL" if bool(best["is_match"]) else "ANOMALY",
        "label": best["label"],
        "similarity": best["similarity"],
        "anomaly_score": best["anomaly_score"],
        "threshold": best["threshold"],
        "candidates": sorted(candidates, key=lambda item: item["similarity"], reverse=True),
    }


def symbolize_rows(model: MotionModel, rows: list[dict[str, float]]) -> str:
    return compress_symbols([symbolize_row(model, row) for row in rows])


def symbolize_row(model: MotionModel, row: dict[str, float]) -> str:
    x = np.asarray([row[col] for col in model.feature_columns], dtype=float)
    logged = _feature_transform(x)
    logged = np.where(np.isfinite(logged), logged, model.mean)
    z = (logged - model.mean) / (model.std + 1e-8)
    distances = ((z - model.centroids) ** 2).sum(axis=1)
    return chr(ord("A") + int(distances.argmin()))


def save_motion_model(model: MotionModel, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        pickle.dump(model, f)


def load_motion_model(path: str | Path) -> MotionModel:
    model_path = Path(path)
    with model_path.open("rb") as f:
        model = pickle.load(f)
    command_map_path = model_path.with_name("controller_command_map.json")
    if command_map_path.exists():
        with command_map_path.open("r", encoding="utf-8") as f:
            profile = json.load(f)
        signatures = profile.get("signatures", profile) if isinstance(profile, dict) else {}
        if isinstance(signatures, dict):
            model.controller_command_map = {
                str(payload_hex).lower(): canonical_action_label(label)
                for payload_hex, label in signatures.items()
            }
    return model


def write_training_outputs(model: MotionModel, report: dict[str, object], out_dir: str | Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_motion_model(model, out_dir / "motion_model.pkl")
    if model.signal_model is not None:
        save_signal_model(model.signal_model, out_dir / "signal_action_model.joblib")
    _write_json(out_dir / "report.json", report)
    _write_csv(out_dir / "sample_sequences.csv", report["sample_sequences"])
    _write_csv(out_dir / "template_scores.csv", report["template_scores"])
    _write_csv(out_dir / "pcap_summary.csv", report["pcap_summary"])


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def sequence_similarity(a: str, b: str) -> float:
    return 1.0 - levenshtein(a, b) / max(len(a), len(b), 1)


def compress_symbols(symbols: Iterable[str], max_run: int = 3) -> str:
    seq: list[str] = []
    last = None
    run = 0
    for symbol in symbols:
        if symbol == last:
            run += 1
            if run <= max_run:
                seq.append(symbol)
        else:
            last = symbol
            run = 1
            seq.append(symbol)
    return "".join(seq)


def _dp_segment_sequence(
    model: MotionModel,
    sequence: str,
    *,
    max_segment_s: float | None,
) -> list[dict[str, object]]:
    n = len(sequence)
    if n == 0:
        return []
    all_templates = [template for items in model.templates.values() for template in items]
    min_len = max(2, int(min(t.length for t in all_templates) * 0.45))
    if max_segment_s is None:
        max_len = max(3, int(max(t.length for t in all_templates) * 1.75))
    else:
        max_len = max(3, int(max_segment_s / (model.window_ms / 1000.0)))

    dp = [-1e9] * (n + 1)
    back: list[tuple[int, MotionTemplate, float] | None] = [None] * (n + 1)
    dp[0] = 0.0
    for start in range(n):
        if dp[start] <= -1e8:
            continue
        for end in range(start + min_len, min(n, start + max_len) + 1):
            part = sequence[start:end]
            for template in all_templates:
                length_ratio = len(part) / max(template.action_avg_length, 1.0)
                if length_ratio < 0.45 or length_ratio > 1.85:
                    continue
                similarity = sequence_similarity(part, template.sequence)
                length_penalty = abs(np.log(length_ratio)) * 0.12
                score = similarity - length_penalty - 0.02
                if dp[start] + score > dp[end]:
                    dp[end] = dp[start] + score
                    back[end] = (start, template, similarity)

    end = max(range(max(0, n - max_len), n + 1), key=lambda idx: dp[idx])
    if back[end] is None:
        item = classify_sequence(model, sequence)
        item.update({"start_symbol": 0, "end_symbol": n, "sequence": sequence})
        return [item]

    output = []
    cursor = end
    while cursor > 0 and back[cursor] is not None:
        start, template, similarity = back[cursor]
        part = sequence[start:cursor]
        threshold = model.thresholds.get(template.label, 0.5)
        anomaly_score = 1.0 - similarity
        output.append(
            {
                "label": template.label,
                "status": "NORMAL" if anomaly_score <= threshold else "ANOMALY",
                "similarity": float(similarity),
                "anomaly_score": float(anomaly_score),
                "threshold": float(threshold),
                "sequence": part,
                "start_symbol": start,
                "end_symbol": cursor,
                "template_sample": template.sample,
            }
        )
        cursor = start
    return list(reversed(output))


def _activity_segments(
    rows: list[dict[str, float]],
    *,
    min_segment_windows: int,
    gap_windows: int,
    active_quantile: float,
) -> list[tuple[int, int]]:
    activity = np.asarray([row["byte_count"] + row["pkt_count"] for row in rows], dtype=float)
    positive = activity[activity > 0]
    if not positive.size:
        return []
    threshold = max(1.0, float(np.quantile(positive, active_quantile)))
    active = activity >= threshold
    segments = []
    start = None
    last_active = None
    for idx, is_active in enumerate(active):
        if is_active:
            if start is None:
                start = idx
            last_active = idx
        elif start is not None and last_active is not None and idx - last_active >= gap_windows:
            if last_active + 1 - start >= min_segment_windows:
                segments.append((start, last_active + 1))
            start = None
            last_active = None
    if start is not None and last_active is not None and last_active + 1 - start >= min_segment_windows:
        segments.append((start, last_active + 1))
    return segments or [(0, len(rows))]


def _smooth_labels(labels: list[str], *, radius: int = 1) -> list[str]:
    if not labels or radius <= 0:
        return labels
    output = []
    for idx in range(len(labels)):
        lo = max(0, idx - radius)
        hi = min(len(labels), idx + radius + 1)
        counts = Counter(labels[lo:hi])
        output.append(counts.most_common(1)[0][0])
    return output


def _merge_short_scan_runs(
    actions: list[dict[str, object]],
    *,
    min_run_s: float,
) -> list[dict[str, object]]:
    if len(actions) <= 1:
        return actions
    merged = [dict(action) for action in actions]
    changed = True
    while changed and len(merged) > 1:
        changed = False
        for idx, action in enumerate(list(merged)):
            duration = float(action.get("duration_s") or 0.0)
            if duration >= min_run_s:
                continue
            target_idx = idx - 1 if idx > 0 else idx + 1
            if target_idx < 0 or target_idx >= len(merged):
                continue
            target = merged[target_idx]
            target["t_start_s"] = min(float(target["t_start_s"]), float(action["t_start_s"]))
            target["t_end_s"] = max(float(target["t_end_s"]), float(action["t_end_s"]))
            target["duration_s"] = float(target["t_end_s"]) - float(target["t_start_s"])
            target["confidence"] = float(np.mean([float(target["confidence"]), float(action["confidence"])]))
            target["windows"] = int(target.get("windows", 0)) + int(action.get("windows", 0))
            del merged[idx]
            changed = True
            break
    compact = []
    for action in merged:
        if compact and compact[-1]["label"] == action["label"]:
            prev = compact[-1]
            prev["t_end_s"] = action["t_end_s"]
            prev["duration_s"] = float(prev["t_end_s"]) - float(prev["t_start_s"])
            prev["confidence"] = float(np.mean([float(prev["confidence"]), float(action["confidence"])]))
            prev["windows"] = int(prev.get("windows", 0)) + int(action.get("windows", 0))
        else:
            compact.append(action)
    return compact


def _segment_times(rows: list[dict[str, float]], start: int, end: int) -> dict[str, float]:
    t_start = float(rows[start]["t_start_s"])
    t_end = float(rows[end - 1]["t_start_s"]) if end > start else t_start
    return {"t_start_s": t_start, "t_end_s": t_end, "duration_s": max(0.0, t_end - t_start)}


def _build_templates(
    sample_rows: list[dict[str, object]],
    *,
    max_templates: int,
    diversity_threshold: float = 0.85,
) -> dict[str, list[MotionTemplate]]:
    templates = {}
    for label in sorted({str(row["label"]) for row in sample_rows}):
        rows = [row for row in sample_rows if row["label"] == label]
        avg_length = float(np.mean([int(row["length"]) for row in rows]))
        candidates = []
        for row in rows:
            sims = [
                sequence_similarity(str(row["sequence"]), str(other["sequence"]))
                for other in rows
                if other is not row
            ]
            mean_similarity = float(np.mean(sims)) if sims else 1.0
            support = sum(sim >= diversity_threshold for sim in sims)
            candidates.append((mean_similarity, support, row))
        candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected: list[MotionTemplate] = []
        for mean_similarity, support, row in candidates:
            if len(selected) >= max_templates:
                break
            seq = str(row["sequence"])
            if selected and max(sequence_similarity(seq, item.sequence) for item in selected) >= diversity_threshold:
                continue
            selected.append(
                MotionTemplate(
                    label=label,
                    sequence=seq,
                    sample=str(row["sample"]),
                    rank=len(selected) + 1,
                    length=len(seq),
                    action_avg_length=avg_length,
                    support=int(support),
                    mean_similarity=mean_similarity,
                )
            )
        if not selected and candidates:
            mean_similarity, support, row = candidates[0]
            seq = str(row["sequence"])
            selected.append(
                MotionTemplate(label, seq, str(row["sample"]), 1, len(seq), avg_length, int(support), mean_similarity)
            )
        templates[label] = selected
    return templates


def _score_samples(
    sample_rows: list[dict[str, object]],
    templates: dict[str, list[MotionTemplate]],
) -> list[dict[str, object]]:
    rows = []
    for row in sample_rows:
        label = str(row["label"])
        sequence = str(row["sequence"])
        own = [
            (sequence_similarity(sequence, template.sequence), template)
            for template in templates[label]
        ]
        best_own_sim, best_own = max(own, key=lambda item: item[0])
        all_sims = {
            candidate_label: max(
                sequence_similarity(sequence, template.sequence)
                for template in label_templates
            )
            for candidate_label, label_templates in templates.items()
        }
        predicted = max(all_sims, key=all_sims.get)
        rows.append(
            {
                "label": label,
                "sample": str(row["sample"]),
                "sequence": sequence,
                "template_sample": best_own.sample,
                "similarity": float(best_own_sim),
                "anomaly_score": float(1.0 - best_own_sim),
                "predicted_label": predicted,
                "correct": predicted == label,
            }
        )
    return rows


def _compute_thresholds(
    rows: list[dict[str, object]],
    quantile: float,
    floor: float,
    padding: float,
) -> dict[str, float]:
    by_label: defaultdict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_label[str(row["label"])].append(float(row["anomaly_score"]))
    return {
        label: float(min(max(np.quantile(scores, quantile) + padding, floor), 0.85))
        for label, scores in by_label.items()
    }


def _training_report(
    *,
    all_rows: list[dict[str, object]],
    sample_rows: list[dict[str, object]],
    score_rows: list[dict[str, object]],
    summaries: list[dict[str, object]],
    model: MotionModel,
    signal_report: dict[str, object] | None,
    amnar_report: dict[str, object] | None,
    amnar_window_report: dict[str, object] | None = None,
    traffic_report: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "window_ms": model.window_ms,
        "clean_mode": model.clean_mode,
        "control_flows": [
            {"src_port": src_port, "dst_port": dst_port}
            for src_port, dst_port in sorted(model.control_flows or set())
        ],
        "feature_columns": model.feature_columns,
        "labels": sorted(model.templates),
        "samples": len(sample_rows),
        "windows": len(all_rows),
        "local_ips": sorted(model.local_ips),
        "include_ports": sorted(model.include_ports) if model.include_ports else None,
        "exclude_ports": sorted(model.exclude_ports),
        "motion_training_accuracy": _accuracy(score_rows, "correct"),
        "thresholds": model.thresholds,
        "templates": {
            label: [template.__dict__ for template in templates]
            for label, templates in model.templates.items()
        },
        "sample_sequences": sample_rows,
        "template_scores": score_rows,
        "pcap_summary": summaries,
        "signal_report": signal_report,
        "amnar_report": amnar_report,
        "amnar_window_report": amnar_window_report,
        "traffic_report": traffic_report,
    }


def _fit_kmeans(x: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
    try:
        from sklearn.cluster import KMeans

        fitted = KMeans(n_clusters=k, random_state=7, n_init=10).fit(x)
        return fitted.labels_.astype(int), fitted.cluster_centers_.astype(float)
    except Exception:
        rng = np.random.default_rng(7)
        centroids = x[rng.choice(len(x), size=k, replace=False)].copy()
        labels = np.zeros(len(x), dtype=int)
        for _ in range(80):
            distances = ((x[:, None, :] - centroids[None, :, :]) ** 2).sum(axis=2)
            new_labels = distances.argmin(axis=1)
            if np.array_equal(labels, new_labels):
                break
            labels = new_labels
            for idx in range(k):
                members = x[labels == idx]
                if len(members):
                    centroids[idx] = members.mean(axis=0)
        return labels, centroids


def _standardize(x: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    std[std == 0] = 1.0
    return (x - mean) / std, mean, std


def _feature_matrix(rows: list[dict[str, object]], columns: list[str]) -> np.ndarray:
    return np.asarray([[float(row[column]) for column in columns] for row in rows], dtype=float)


def _feature_transform(x: np.ndarray) -> np.ndarray:
    values = np.asarray(x, dtype=float)
    transformed = np.sign(values) * np.log1p(np.abs(values))
    return np.where(np.isfinite(transformed), transformed, 0.0)


def _traffic_profile_vector(
    rows: list[dict[str, object]],
    columns: list[str],
) -> np.ndarray:
    if not rows:
        return np.zeros(len(columns) * 4 + 1, dtype=np.float32)
    x = _feature_matrix(rows, columns)
    return np.concatenate(
        [
            x.mean(axis=0),
            x.std(axis=0),
            x.max(axis=0),
            x.sum(axis=0),
            np.asarray([len(rows)], dtype=float),
        ]
    ).astype(np.float32)


def _empty_window() -> dict[str, object]:
    window = {
        "pkt_count": 0,
        "byte_count": 0,
        "up_pkt_count": 0,
        "down_pkt_count": 0,
        "up_bytes": 0,
        "down_bytes": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "small_count": 0,
        "large_count": 0,
        "valid_payload_count": 0,
        "payload_byte_count": 0,
        "sizes": [],
        "times": [],
    }
    for msg_type in MSG_TYPES:
        window[f"msg_type_{msg_type:02x}_count"] = 0
    return window


def _packet_allowed(
    meta: dict[str, object] | None,
    include_ports: set[int] | None,
    exclude_ports: set[int] | None,
) -> bool:
    if not meta:
        return False
    if meta["src_port"] is None or meta["dst_port"] is None:
        return False
    ports = {port for port in (meta["src_port"], meta["dst_port"]) if port is not None}
    if include_ports and not ports.intersection(include_ports):
        return False
    if exclude_ports and ports.intersection(exclude_ports):
        return False
    return True


def _packet_direction(meta: dict[str, object], local_ips: set[str]) -> str:
    src = str(meta["src"])
    dst = str(meta["dst"])
    if src in local_ips and dst not in local_ips:
        return "up"
    if dst in local_ips and src not in local_ips:
        return "down"
    return "up" if _ip_to_int(src) <= _ip_to_int(dst) else "down"


def _ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _is_private_ipv4(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")


def _accuracy(rows: list[dict[str, object]], key: str) -> float | None:
    values = [row[key] for row in rows if row.get(key) is not None]
    if not values:
        return None
    return float(sum(bool(value) for value in values) / len(values))


def _write_json(path: Path, data: object) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _write_csv(path: Path, rows: object) -> None:
    rows = list(rows or [])
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
