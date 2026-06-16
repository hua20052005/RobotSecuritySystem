import argparse
import csv
import json
import math
import os
import random
import socket
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

SRC_ROOT = Path(__file__).resolve().parent / "src"
if SRC_ROOT.exists() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from robot_traffic_action.features import extract_features
    from robot_traffic_action.model import (
        leave_one_out_report,
        load_dataset,
        save_model,
        train_action_model,
    )
except Exception:  # pragma: no cover - optional pipeline
    extract_features = None
    leave_one_out_report = None
    load_dataset = None
    save_model = None
    train_action_model = None


DEFAULT_EXCLUDE_PORTS = {22}
END_ACTION = "__END__"


def read_pcap_packets(path):
    """Yield packet timestamp and raw captured bytes without loading the pcap into memory."""
    with open(path, "rb") as f:
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
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            payload = f.read(incl_len)
            if len(payload) < incl_len:
                break
            yield ts_sec + ts_frac / scale, orig_len, payload


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def parse_ipv4_packet(frame):
    """Parse Ethernet + IPv4 + TCP/UDP enough for metadata features."""
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
    src = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16 : offset + 20])
    src_port = None
    dst_port = None
    l4 = offset + ihl
    if proto in (6, 17) and len(frame) >= l4 + 4:
        src_port, dst_port = struct.unpack("!HH", frame[l4 : l4 + 4])
    return {
        "proto": proto,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def discover_local_ips(pcap_files, sample_packets=5000):
    counts = Counter()
    for path in pcap_files:
        for i, (_, _, frame) in enumerate(read_pcap_packets(path)):
            meta = parse_ipv4_packet(frame)
            if meta:
                for ip in (meta["src"], meta["dst"]):
                    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                        counts[ip] += 1
            if i + 1 >= sample_packets:
                break
    return {ip for ip, _ in counts.most_common(3)}


def packet_allowed(meta, include_ports=None, exclude_ports=None):
    if not meta:
        return False
    ports = {p for p in (meta["src_port"], meta["dst_port"]) if p is not None}
    if include_ports and not ports.intersection(include_ports):
        return False
    if exclude_ports and ports.intersection(exclude_ports):
        return False
    return True


def extract_window_features(path, local_ips, window_ms=100, include_ports=None, exclude_ports=None):
    window_s = window_ms / 1000.0
    windows = defaultdict(lambda: {
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
        "sizes": [],
        "times": [],
    })
    first_ts = None
    raw_packets = 0
    kept_packets = 0

    for ts, length, frame in read_pcap_packets(path):
        raw_packets += 1
        meta = parse_ipv4_packet(frame)
        if not packet_allowed(meta, include_ports, exclude_ports):
            continue
        kept_packets += 1
        if first_ts is None:
            first_ts = ts
        idx = int((ts - first_ts) / window_s)
        w = windows[idx]
        w["pkt_count"] += 1
        w["byte_count"] += length
        if meta["src"] in local_ips and meta["dst"] not in local_ips:
            direction = "up"
        elif meta["dst"] in local_ips and meta["src"] not in local_ips:
            direction = "down"
        elif ip_to_int(meta["src"]) <= ip_to_int(meta["dst"]):
            direction = "up"
        else:
            direction = "down"
        w[f"{direction}_pkt_count"] += 1
        w[f"{direction}_bytes"] += length
        if meta["proto"] == 6:
            w["tcp_count"] += 1
        elif meta["proto"] == 17:
            w["udp_count"] += 1
        if length <= 128:
            w["small_count"] += 1
        if length >= 1000:
            w["large_count"] += 1
        w["sizes"].append(length)
        w["times"].append(ts)

    rows = []
    if not windows:
        return rows, {"raw_packets": raw_packets, "kept_packets": kept_packets, "duration_s": 0}

    max_idx = max(windows)
    for idx in range(max_idx + 1):
        w = windows[idx]
        sizes = w["sizes"]
        times = w["times"]
        iats = np.diff(times) * 1000 if len(times) > 1 else np.array([0.0])
        pkt_count = w["pkt_count"]
        rows.append({
            "window_idx": idx,
            "t_start_s": idx * window_s,
            "pkt_count": pkt_count,
            "byte_count": w["byte_count"],
            "up_pkt_count": w["up_pkt_count"],
            "down_pkt_count": w["down_pkt_count"],
            "up_bytes": w["up_bytes"],
            "down_bytes": w["down_bytes"],
            "tcp_count": w["tcp_count"],
            "udp_count": w["udp_count"],
            "small_count": w["small_count"],
            "large_count": w["large_count"],
            "mean_len": float(np.mean(sizes)) if sizes else 0.0,
            "std_len": float(np.std(sizes)) if sizes else 0.0,
            "mean_iat_ms": float(np.mean(iats)) if pkt_count else 0.0,
            "std_iat_ms": float(np.std(iats)) if pkt_count else 0.0,
            "byte_rate": float(w["byte_count"] / window_s) if window_s else 0.0,
            "direction_balance": float((w["up_pkt_count"] - w["down_pkt_count"]) / max(pkt_count, 1)),
            "len_cv": float(np.std(sizes) / max(np.mean(sizes), 1.0)) if sizes else 0.0,
            "iat_cv": float(np.std(iats) / max(np.mean(iats), 1.0)) if pkt_count else 0.0,
            "small_ratio": float(w["small_count"] / max(pkt_count, 1)),
            "large_ratio": float(w["large_count"] / max(pkt_count, 1)),
        })
    duration_s = (max_idx + 1) * window_s
    return rows, {"raw_packets": raw_packets, "kept_packets": kept_packets, "duration_s": duration_s}


FEATURE_COLUMNS = [
    "pkt_count", "byte_count", "up_pkt_count", "down_pkt_count", "up_bytes", "down_bytes",
    "tcp_count", "udp_count", "small_count", "large_count", "mean_len", "std_len",
    "mean_iat_ms", "std_iat_ms", "byte_rate", "direction_balance", "len_cv", "iat_cv",
    "small_ratio", "large_ratio",
]


def standardize(x):
    mu = x.mean(axis=0)
    sigma = x.std(axis=0)
    sigma[sigma == 0] = 1.0
    return (x - mu) / sigma, mu, sigma


def kmeans(x, k=8, iterations=80, seed=7):
    rng = random.Random(seed)
    centroids = x[rng.sample(range(len(x)), k)].copy()
    labels = np.zeros(len(x), dtype=int)
    for _ in range(iterations):
        distances = ((x[:, None, :] - centroids[None, :, :]) ** 2).sum(axis=2)
        new_labels = distances.argmin(axis=1)
        if np.array_equal(labels, new_labels):
            break
        labels = new_labels
        for c in range(k):
            members = x[labels == c]
            if len(members):
                centroids[c] = members.mean(axis=0)
    return labels, centroids


def compress_sequence(labels, max_run=3):
    seq = []
    last = None
    run = 0
    for label in labels:
        token = chr(ord("A") + int(label))
        if token == last:
            run += 1
            if run <= max_run:
                seq.append(token)
        else:
            last = token
            run = 1
            seq.append(token)
    return "".join(seq)


def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def sequence_similarity(a, b):
    denom = max(len(a), len(b), 1)
    return 1.0 - levenshtein(a, b) / denom


def temporal_consistency_score(sequences_by_label):
    scores = {}
    for label, seqs in sequences_by_label.items():
        if len(seqs) < 2:
            scores[label] = 1.0
            continue
        sims = []
        for i in range(len(seqs)):
            for j in range(i + 1, len(seqs)):
                sims.append(sequence_similarity(seqs[i], seqs[j]))
        scores[label] = float(np.mean(sims))
    return scores


def nearest_neighbor_accuracy(sample_rows):
    correct = 0
    predictions = []
    for i, row in enumerate(sample_rows):
        best = None
        for j, other in enumerate(sample_rows):
            if i == j:
                continue
            sim = sequence_similarity(row["sequence"], other["sequence"])
            if best is None or sim > best["similarity"]:
                best = {"label": other["label"], "sample": other["sample"], "similarity": sim}
        pred = best["label"] if best else None
        correct += int(pred == row["label"])
        predictions.append({
            "label": row["label"],
            "sample": row["sample"],
            "predicted_label": pred,
            "nearest_sample": best["sample"] if best else "",
            "nearest_similarity": best["similarity"] if best else 0.0,
            "correct": pred == row["label"],
        })
    return correct / max(len(sample_rows), 1), predictions


def choose_multi_templates(rows, max_templates=2, min_template_support=2, diversity_threshold=0.85):
    """Choose diverse medoid sequences that represent normal variants of one action."""
    if not rows:
        return []

    action_avg_length = float(np.mean([row["length"] for row in rows]))
    pair_sims = {}
    for row in rows:
        for other in rows:
            pair_sims[(row["sample"], other["sample"])] = sequence_similarity(row["sequence"], other["sequence"])

    candidates = []
    for row in rows:
        sims = [
            pair_sims[(row["sample"], other["sample"])]
            for other in rows
            if other["sample"] != row["sample"]
        ]
        avg_sim = float(np.mean(sims)) if sims else 1.0
        support = sum(
            1 for other in rows
            if pair_sims[(row["sample"], other["sample"])] >= diversity_threshold
        )
        candidates.append({"row": row, "avg_sim": avg_sim, "support": support})

    candidates.sort(key=lambda item: (item["avg_sim"], item["support"]), reverse=True)
    selected = []
    for item in candidates:
        if len(selected) >= max_templates:
            break
        if selected:
            nearest_selected = max(
                sequence_similarity(item["row"]["sequence"], template["template_sequence"])
                for template in selected
            )
            if nearest_selected >= diversity_threshold:
                continue
            if item["support"] < min_template_support:
                continue
        selected.append({
            "label": item["row"]["label"],
            "template_rank": len(selected) + 1,
            "template_sample": item["row"]["sample"],
            "template_sequence": item["row"]["sequence"],
            "template_length": item["row"]["length"],
            "action_avg_length": action_avg_length,
            "template_similarity": item["avg_sim"],
            "template_support": item["support"],
        })

    return selected or [{
        "label": candidates[0]["row"]["label"],
        "template_rank": 1,
        "template_sample": candidates[0]["row"]["sample"],
        "template_sequence": candidates[0]["row"]["sequence"],
        "template_length": candidates[0]["row"]["length"],
        "action_avg_length": action_avg_length,
        "template_similarity": candidates[0]["avg_sim"],
        "template_support": candidates[0]["support"],
    }]


def build_action_templates(sample_rows, max_templates=2, min_template_support=2, diversity_threshold=0.85):
    """Choose one or more medoid sequences of each action as normal temporal templates."""
    templates = {}
    for label in sorted({row["label"] for row in sample_rows}):
        rows = [row for row in sample_rows if row["label"] == label]
        templates[label] = choose_multi_templates(
            rows,
            max_templates=max_templates,
            min_template_support=min_template_support,
            diversity_threshold=diversity_threshold,
        )
    return templates


def score_against_templates(sample_rows, templates):
    rows = []
    for row in sample_rows:
        own_candidates = [
            {
                "template": template,
                "similarity": sequence_similarity(row["sequence"], template["template_sequence"]),
            }
            for template in templates[row["label"]]
        ]
        own_best = max(own_candidates, key=lambda item: item["similarity"])
        own_similarity = own_best["similarity"]
        action_avg_length = float(own_best["template"].get("action_avg_length", own_best["template"]["template_length"]))
        length_delta = abs(float(row["length"]) - action_avg_length) / max(action_avg_length, 1.0)
        all_sims = {
            label: max(
                sequence_similarity(row["sequence"], template["template_sequence"])
                for template in label_templates
            )
            for label, label_templates in templates.items()
        }
        predicted_label = max(all_sims, key=all_sims.get)
        best_other = max(
            (label for label in all_sims if label != row["label"]),
            key=lambda label: all_sims[label],
            default=row["label"],
        )
        # A high anomaly score means the action evolution deviates from its normal template.
        anomaly_score = 1.0 - own_similarity
        margin = own_similarity - all_sims[best_other]
        rows.append({
            "label": row["label"],
            "sample": row["sample"],
            "template_sample": own_best["template"]["template_sample"],
            "template_rank": own_best["template"]["template_rank"],
            "template_count": len(templates[row["label"]]),
            "own_template_similarity": own_similarity,
            "action_avg_length": action_avg_length,
            "length_delta": length_delta,
            "anomaly_score": anomaly_score,
            "best_other_label": best_other,
            "best_other_similarity": all_sims[best_other],
            "margin_vs_other": margin,
            "template_predicted_label": predicted_label,
            "template_correct": predicted_label == row["label"],
        })
    return rows


def compute_action_thresholds(score_rows, quantile=0.85, floor=0.20):
    thresholds = {}
    by_label = defaultdict(list)
    for row in score_rows:
        by_label[row["label"]].append(float(row["anomaly_score"]))
    for label, scores in by_label.items():
        if scores:
            thresholds[label] = float(max(np.quantile(scores, quantile), floor))
        else:
            thresholds[label] = float(floor)
    return thresholds


def attach_threshold_decisions(score_rows, thresholds):
    enriched = []
    for row in score_rows:
        threshold = float(thresholds.get(row["label"], 0.5))
        item = dict(row)
        item["action_threshold"] = threshold
        item["template_is_anomaly"] = float(item["anomaly_score"]) > threshold
        enriched.append(item)
    return enriched


def parse_task_sequence(value):
    return [part.strip() for part in value.replace("->", ",").split(",") if part.strip()]


def _resolve_action_map(data, source_path):
    action_map = {}
    if isinstance(data, dict):
        action_map = data.get("actions") or data.get("action_map") or {}

    if not action_map and source_path:
        candidate = Path(source_path).with_name("action_map.json")
        if candidate.exists():
            action_map = json.loads(candidate.read_text(encoding="utf-8"))

    return {
        str(key).strip(): str(value).strip()
        for key, value in (action_map or {}).items()
        if str(value).strip()
    }


def _coerce_action_label(value, action_map):
    label = str(value).strip()
    if not label:
        return ""

    mapped = action_map.get(label)
    if mapped is not None:
        return str(mapped).strip()

    if action_map:
        try:
            numeric_key = str(int(float(label)))
        except ValueError:
            numeric_key = ""
        if numeric_key:
            mapped = action_map.get(numeric_key)
            if mapped is not None:
                return str(mapped).strip()

    return label


def _map_task_sequence(sequence, action_map):
    mapped = []
    for item in sequence:
        label = _coerce_action_label(item, action_map)
        if label:
            mapped.append(label)
    return mapped


def load_task_sequences(path):
    if not path:
        return []
    task_path = Path(path)
    if not task_path.exists():
        raise SystemExit(f"Task sequence file not found: {task_path}")

    if task_path.suffix.lower() == ".json":
        data = json.loads(task_path.read_text(encoding="utf-8"))
        action_map = _resolve_action_map(data, task_path)
        if isinstance(data, dict):
            raw = (
                data.get("sequences")
                or data.get("normal_sequences")
                or data.get("task_sequences")
                or data.get("normal_templates")
                or data.get("training_sequences")
                or []
            )
        else:
            raw = data

        sequences = []
        for entry in raw:
            if isinstance(entry, dict):
                seq = entry.get("sequence", entry.get("actions", []))
            else:
                seq = entry
            if seq:
                sequences.append(_map_task_sequence(seq, action_map))
        return sequences

    sequences = []
    with open(task_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                sequences.append(parse_task_sequence(line))
    return sequences


def build_default_task_sequences(labels):
    labels = sorted(labels)
    preferred = [
        ["hello", "walk", "step"],
        ["hello", "jump"],
        ["walk", "step", "jump"],
    ]
    usable = [seq for seq in preferred if all(label in labels for label in seq)]
    if usable:
        return usable
    return [labels] if labels else []


def build_action_transition_graph(task_sequences):
    graph = defaultdict(set)
    edge_counts = Counter()
    for seq in task_sequences:
        cleaned = [label for label in seq if label]
        for i, next_action in enumerate(cleaned):
            prefix = tuple(cleaned[:i])
            graph[prefix].add(next_action)
            edge_counts[(prefix, next_action)] += 1
        if cleaned:
            prefix = tuple(cleaned)
            graph[prefix].add(END_ACTION)
            edge_counts[(prefix, END_ACTION)] += 1
    return {prefix: sorted(next_actions) for prefix, next_actions in graph.items()}, edge_counts


def build_action_adjacency(task_sequences):
    """Build action-to-action legal successors used by PAPB-style prediction."""
    adjacency = defaultdict(set)
    edge_counts = Counter()
    start_actions = set()
    for seq in task_sequences:
        cleaned = [label for label in seq if label]
        if not cleaned:
            continue
        start_actions.add(cleaned[0])
        for current_action, next_action in zip(cleaned, cleaned[1:]):
            adjacency[current_action].add(next_action)
            edge_counts[(current_action, next_action)] += 1
        adjacency[cleaned[-1]].add(END_ACTION)
        edge_counts[(cleaned[-1], END_ACTION)] += 1
    return {action: sorted(next_actions) for action, next_actions in adjacency.items()}, sorted(start_actions), edge_counts


def predict_valid_next_actions(executed_sequence, task_graph_adjacency, start_actions=None):
    """
    Predict all legal next actions from a partially executed task.

    This mirrors the paper's PAPB idea: instead of requiring an exact prefix match,
    find the longest subsequence of executed actions that is consistent with the
    action graph, then collect all legal successors of that matched subsequence.
    """
    start_actions = set(start_actions or [])
    cleaned = [action for action in executed_sequence if action]
    if not cleaned:
        return start_actions, set(), 0

    n = len(cleaned)
    dp = [1] * n
    subseq_actions = [{action} for action in cleaned]

    for i in range(1, n):
        for j in range(i):
            yi, yj = cleaned[i], cleaned[j]
            if yi in task_graph_adjacency.get(yj, []):
                candidate_len = dp[j] + 1
                candidate_actions = subseq_actions[j] | {yi}
                if candidate_len > dp[i]:
                    dp[i] = candidate_len
                    subseq_actions[i] = candidate_actions
                elif candidate_len == dp[i]:
                    subseq_actions[i] |= candidate_actions

    max_len = max(dp)
    matched_actions = set()
    for i, length in enumerate(dp):
        if length == max_len:
            matched_actions |= subseq_actions[i]

    last_action = cleaned[max(range(n), key=lambda idx: dp[idx])]
    valid_next = set(task_graph_adjacency.get(last_action, []))
    return valid_next, matched_actions, max_len


def flatten_transition_graph(graph, edge_counts):
    rows = []
    for prefix, next_actions in sorted(graph.items(), key=lambda item: (len(item[0]), item[0])):
        prefix_text = "->".join(prefix)
        for next_action in next_actions:
            rows.append({
                "prefix": prefix_text,
                "next_action": next_action,
                "count": edge_counts[(prefix, next_action)],
            })
    return rows


def best_template_match(row, label, templates):
    scored = [
        {
            "template": template,
            "similarity": sequence_similarity(row["sequence"], template["template_sequence"]),
        }
        for template in templates.get(label, [])
    ]
    if not scored:
        return None
    return max(scored, key=lambda item: item["similarity"])


def score_task_transitions(task_sequences, sample_rows, templates, action_thresholds=None, sample_seed=7):
    action_thresholds = action_thresholds or {}
    rows_by_label = defaultdict(list)
    for row in sample_rows:
        rows_by_label[row["label"]].append(row)

    graph, edge_counts = build_action_transition_graph(task_sequences)
    adjacency, start_actions, _adjacency_edge_counts = build_action_adjacency(task_sequences)
    rng = random.Random(sample_seed)
    scores = []
    for task_id, seq in enumerate(task_sequences, start=1):
        executed_sequence = []
        for step_idx, expected_action in enumerate(seq, start=1):
            valid_next_set, papb_matched_actions, papb_match_length = predict_valid_next_actions(
                executed_sequence,
                adjacency,
                start_actions=start_actions,
            )
            valid_next = sorted(valid_next_set)
            if expected_action not in rows_by_label:
                executed_sequence.append(expected_action)
                continue

            current = rng.choice(rows_by_label[expected_action])
            candidate_scores = []
            for action in valid_next:
                match = best_template_match(current, action, templates)
                if match:
                    candidate_scores.append((action, match))

            if candidate_scores:
                best_action, best_match = max(candidate_scores, key=lambda item: item[1]["similarity"])
                valid_similarity = best_match["similarity"]
                template_sample = best_match["template"]["template_sample"]
                template_rank = best_match["template"]["template_rank"]
                action_avg_length = float(best_match["template"].get("action_avg_length", best_match["template"]["template_length"]))
            else:
                best_action = ""
                valid_similarity = 0.0
                template_sample = ""
                template_rank = ""
                action_avg_length = 0.0

            length_delta = (
                abs(float(current["length"]) - action_avg_length) / max(action_avg_length, 1.0)
                if action_avg_length
                else ""
            )
            transition_anomaly_score = 1.0 - valid_similarity
            matched_threshold = action_thresholds.get(best_action, "")
            transition_is_valid = expected_action in valid_next_set
            transition_is_anomaly = (not transition_is_valid) or (
                bool(best_action) and transition_anomaly_score > float(matched_threshold or 1.0)
            )

            scores.append({
                "task_id": task_id,
                "step_idx": step_idx,
                "prefix": "->".join(executed_sequence),
                "papb_matched_actions": "|".join(sorted(papb_matched_actions)),
                "papb_match_length": papb_match_length,
                "current_action": expected_action,
                "sample": current["sample"],
                "valid_next_actions": "|".join(valid_next),
                "best_valid_action": best_action,
                "best_template_sample": template_sample,
                "best_template_rank": template_rank,
                "valid_next_similarity": valid_similarity,
                "action_avg_length": action_avg_length if action_avg_length else "",
                "length_delta": length_delta,
                "transition_anomaly_score": transition_anomaly_score,
                "matched_action_threshold": matched_threshold,
                "transition_is_valid": transition_is_valid,
                "transition_is_anomaly": transition_is_anomaly,
            })
            executed_sequence.append(expected_action)
    return scores, graph, edge_counts


def leave_one_out_template_scores(sample_rows, max_templates=2, min_template_support=2, diversity_threshold=0.85):
    rows = []
    labels = sorted({row["label"] for row in sample_rows})
    for row in sample_rows:
        candidate_scores = {}
        candidate_templates = {}
        candidate_template_counts = {}
        candidate_action_lengths = {}
        for label in labels:
            candidates = [
                other for other in sample_rows
                if other["label"] == label and other["sample"] != row["sample"]
            ]
            if not candidates:
                continue
            label_templates = choose_multi_templates(
                candidates,
                max_templates=max_templates,
                min_template_support=min_template_support,
                diversity_threshold=diversity_threshold,
            )
            scored_templates = [
                {
                    "template": template,
                    "similarity": sequence_similarity(row["sequence"], template["template_sequence"]),
                }
                for template in label_templates
            ]
            best = max(scored_templates, key=lambda item: item["similarity"])
            candidate_templates[label] = best["template"]["template_sample"]
            candidate_template_counts[label] = len(label_templates)
            candidate_action_lengths[label] = float(best["template"].get("action_avg_length", best["template"]["template_length"]))
            candidate_scores[label] = best["similarity"]
        if not candidate_scores:
            continue
        predicted_label = max(candidate_scores, key=candidate_scores.get)
        own_similarity = candidate_scores.get(row["label"], 0.0)
        action_avg_length = candidate_action_lengths.get(row["label"], float(row["length"]))
        length_delta = abs(float(row["length"]) - action_avg_length) / max(action_avg_length, 1.0)
        best_other = max(
            (label for label in candidate_scores if label != row["label"]),
            key=lambda label: candidate_scores[label],
            default=row["label"],
        )
        rows.append({
            "label": row["label"],
            "sample": row["sample"],
            "loo_predicted_label": predicted_label,
            "loo_correct": predicted_label == row["label"],
            "own_template_sample": candidate_templates.get(row["label"], ""),
            "own_template_count": candidate_template_counts.get(row["label"], 0),
            "own_template_similarity": own_similarity,
            "action_avg_length": action_avg_length,
            "length_delta": length_delta,
            "anomaly_score": 1.0 - own_similarity,
            "best_other_label": best_other,
            "best_other_similarity": candidate_scores[best_other],
            "margin_vs_other": own_similarity - candidate_scores[best_other],
        })
    return rows


def summarize_template_scores(rows):
    by_label = defaultdict(list)
    for row in rows:
        by_label[row["label"]].append(row)
    summary = []
    for label, items in sorted(by_label.items()):
        anomaly_scores = [r["anomaly_score"] for r in items]
        margins = [r["margin_vs_other"] for r in items]
        correct = [r.get("loo_correct", r.get("template_correct", False)) for r in items]
        summary.append({
            "label": label,
            "mean_anomaly_score": float(np.mean(anomaly_scores)),
            "max_anomaly_score": float(np.max(anomaly_scores)),
            "mean_margin_vs_other": float(np.mean(margins)),
            "template_accuracy": float(np.mean(correct)),
            "anomaly_rate": float(np.mean([bool(r.get("template_is_anomaly", False)) for r in items])),
            "action_threshold": float(items[0].get("action_threshold", 0.0)),
        })
    return summary


def save_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def safe_name(value):
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)


def save_per_sample_outputs(out, all_rows, sample_rows, summaries):
    cleaned_root = out / "cleaned_samples"
    feature_fields = ["label", "sample", "source_file", "window_idx", "t_start_s"] + FEATURE_COLUMNS + ["cluster", "symbol"]
    grouped_features = group_rows(all_rows)
    summaries_by_key = {(row["label"], row["sample"]): row for row in summaries}
    sequences_by_key = {(row["label"], row["sample"]): row for row in sample_rows}

    manifest_rows = []
    for key, rows in sorted(grouped_features.items()):
        label, sample = key
        label_dir = cleaned_root / safe_name(label)
        sample_base = safe_name(sample)
        feature_path = label_dir / f"{sample_base}_windows.csv"
        sequence_path = label_dir / f"{sample_base}_sequence.txt"
        summary_path = label_dir / f"{sample_base}_summary.json"

        sorted_rows = sorted(rows, key=lambda row: row["window_idx"])
        save_csv(feature_path, sorted_rows, feature_fields)
        sequence = sequences_by_key[key]["sequence"]
        sequence_path.parent.mkdir(parents=True, exist_ok=True)
        sequence_path.write_text(sequence + "\n", encoding="utf-8")

        summary = {
            **summaries_by_key[key],
            "sequence_length": sequences_by_key[key]["length"],
            "sequence": sequence,
            "feature_file": str(feature_path),
            "sequence_file": str(sequence_path),
        }
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest_rows.append({
            "label": label,
            "sample": sample,
            "source_file": summaries_by_key[key]["source_file"],
            "raw_packets": summaries_by_key[key]["raw_packets"],
            "kept_packets": summaries_by_key[key]["kept_packets"],
            "windows": summaries_by_key[key]["windows"],
            "sequence_length": sequences_by_key[key]["length"],
            "feature_file": str(feature_path),
            "sequence_file": str(sequence_path),
            "summary_file": str(summary_path),
        })
    save_csv(
        cleaned_root / "manifest.csv",
        manifest_rows,
        ["label", "sample", "source_file", "raw_packets", "kept_packets", "windows", "sequence_length", "feature_file", "sequence_file", "summary_file"],
    )


def plot_sequences(sample_rows, out_path):
    labels = sorted({r["label"] for r in sample_rows})
    fig, axes = plt.subplots(len(labels), 1, figsize=(12, 2.2 * len(labels)), constrained_layout=True)
    if len(labels) == 1:
        axes = [axes]
    for ax, label in zip(axes, labels):
        rows = [r for r in sample_rows if r["label"] == label]
        max_len = max(len(r["sequence"]) for r in rows)
        matrix = np.full((len(rows), max_len), np.nan)
        for i, row in enumerate(rows):
            for j, token in enumerate(row["sequence"]):
                matrix[i, j] = ord(token) - ord("A")
        ax.imshow(matrix, aspect="auto", interpolation="nearest", cmap="tab20")
        ax.set_title(label)
        ax.set_yticks(range(len(rows)), [r["sample"] for r in rows])
        ax.set_xlabel("symbol position")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def write_markdown_report(path, report, templates, template_summary):
    lines = [
        "# Motion Temporal Consistency Report",
        "",
        "## Core Idea",
        "",
        "Encrypted packet payloads are not decoded. Each packet capture is converted into a temporal sequence of traffic symbols using observable metadata: packet length, timing, direction, protocol, and byte counts.",
        "",
        "## Pipeline",
        "",
        "1. Read each pcap in streaming mode.",
        "2. Remove noisy ports, by default TCP/22.",
        "3. Aggregate packets into fixed time windows.",
        "4. Convert every window into a feature vector.",
        "5. Cluster feature vectors into symbolic states A/B/C/...",
        "6. Compress repeated states to form an action evolution sequence.",
        "7. Compare sequences with normalized edit similarity.",
        "8. Build one or more normal templates per action and compute anomaly scores from the best matching template.",
        "9. Estimate action-specific anomaly thresholds from leave-one-out normal samples.",
        "10. Build a procedural transition graph, use PAPB-style dynamic programming to predict all legal next actions, then compare each current action only against legal successor templates.",
        "",
        "## Cleaning Rules",
        "",
        f"- Keep only IPv4 packets with parsable TCP/UDP metadata.",
        f"- Exclude ports: {report['exclude_ports']}",
        f"- Include ports filter: {report['include_ports'] if report['include_ports'] else 'all remaining ports'}",
        f"- Window size: {report['window_ms']} ms",
        "- Direction is inferred from discovered local IPs first, then by deterministic IP ordering fallback.",
        "- Each sample is also exported separately under `cleaned_samples/` for dataset building.",
        "",
        "## Main Scores",
        "",
        f"- Mean within-action similarity: {report['mean_within_action_similarity']:.3f}",
        f"- Mean between-action similarity: {report['mean_between_action_similarity']:.3f}",
        f"- Separability score: {report['separability_score']:.3f}",
        f"- Nearest-neighbor action accuracy: {report['nearest_neighbor_accuracy']:.3f}",
        f"- Leave-one-out template accuracy: {report['leave_one_out_template_accuracy']:.3f}",
        "",
        "## Temporal Consistency Score",
        "",
    ]
    for label, score in sorted(report["temporal_consistency_score"].items()):
        lines.append(f"- {label}: {score:.3f}")
    lines.extend(["", "## Action Templates", ""])
    for label, label_templates in sorted(templates.items()):
        lines.append(f"- {label}: {len(label_templates)} template(s)")
        for template in label_templates:
            seq = template["template_sequence"]
            preview = seq[:90] + ("..." if len(seq) > 90 else "")
            lines.append(
                f"  - rank {template['template_rank']}: sample `{template['template_sample']}`, "
                f"length {template['template_length']}, action avg length {template['action_avg_length']:.2f}, "
                f"avg similarity {template['template_similarity']:.3f}, "
                f"support {template['template_support']}, sequence `{preview}`"
            )
    lines.extend(["", "## Template Anomaly Summary", ""])
    for row in template_summary:
        lines.append(
            f"- {row['label']}: mean anomaly {row['mean_anomaly_score']:.3f}, "
            f"max anomaly {row['max_anomaly_score']:.3f}, mean margin {row['mean_margin_vs_other']:.3f}, "
            f"template accuracy {row['template_accuracy']:.3f}, "
            f"threshold {row['action_threshold']:.3f}, anomaly rate {row['anomaly_rate']:.3f}"
        )
    lines.extend(["", "## Procedural Transition Graph", ""])
    for row in report["transition_graph_rows"]:
        prefix = row["prefix"] if row["prefix"] else "<start>"
        lines.append(f"- prefix `{prefix}` -> `{row['next_action']}` count {row['count']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_signal_pipeline(
    root: Path,
    out: Path,
    *,
    bin_size: float,
    protocol: str,
    positive_ip: str | None,
    length_mode: str,
    classifier: str,
    no_loo: bool,
) -> dict[str, object]:
    if extract_features is None or load_dataset is None or train_action_model is None:
        raise RuntimeError(
            "robot_traffic_action package is not importable. "
            "Make sure motion/motion/src is on the PYTHONPATH."
        )

    out.mkdir(parents=True, exist_ok=True)
    items = load_dataset(
        root,
        bin_size=bin_size,
        protocol=protocol,
        positive_ip=positive_ip,
        length_mode=length_mode,
    )
    model = train_action_model(
        items,
        bin_size=bin_size,
        protocol=protocol,
        length_mode=length_mode,
        classifier_name=classifier,
        trim=True,
    )
    model_path = out / "signal_action_model.joblib"
    save_model(model, model_path)

    prediction_rows = []
    for item in items:
        fv = extract_features(
            item.signal,
            model.templates,
            bin_size=model.bin_size,
            trim=model.trim,
        )
        pred = str(model.classifier.predict(fv.values.reshape(1, -1))[0])
        result = {"predicted": pred}
        if hasattr(model.classifier, "predict_proba"):
            probs = model.classifier.predict_proba(fv.values.reshape(1, -1))[0]
            classes = [str(cls) for cls in model.classifier.classes_]
            proba = {label: float(prob) for label, prob in zip(classes, probs)}
            result["proba"] = dict(sorted(proba.items()))
            result["confidence"] = float(max(proba.values())) if proba else None
        row = {
            "label": item.label,
            "sample": item.path.stem,
            "source_file": str(item.path),
            "predicted": result.get("predicted", ""),
            "confidence": result.get("confidence", ""),
            "proba_json": json.dumps(result.get("proba", {}), ensure_ascii=False),
        }
        prediction_rows.append(row)

    prediction_path = out / "signal_predictions.csv"
    save_csv(
        prediction_path,
        prediction_rows,
        ["label", "sample", "source_file", "predicted", "confidence", "proba_json"],
    )

    report: dict[str, object] = {
        "bin_size": bin_size,
        "protocol": protocol,
        "length_mode": length_mode,
        "classifier": classifier,
        "model_path": str(model_path),
        "predictions_path": str(prediction_path),
    }
    if not no_loo:
        report["leave_one_out_report"] = leave_one_out_report(
            items,
            bin_size=bin_size,
            protocol=protocol,
            length_mode=length_mode,
            classifier_name=classifier,
            trim=True,
        )

    report_path = out / "signal_report.json"
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    report["report_path"] = str(report_path)
    return report


def main():
    parser = argparse.ArgumentParser(description="Build temporal-symbolic motion sequences from encrypted pcap metadata.")
    parser.add_argument(
        "--mode",
        choices=["sequence", "signal", "hybrid"],
        default="hybrid",
        help="Run sequence pipeline, signal pipeline, or both.",
    )
    parser.add_argument("--root", default=".", help="Dataset root containing label folders with .pcap files.")
    parser.add_argument("--out", default="outputs_motion_model", help="Output directory.")
    parser.add_argument("--window-ms", type=int, default=100, help="Aggregation window size.")
    parser.add_argument("--clusters", type=int, default=8, help="Number of symbolic packet/window states.")
    parser.add_argument("--max-templates-per-action", type=int, default=2, help="Maximum normal templates kept for each action.")
    parser.add_argument("--min-template-support", type=int, default=2, help="Minimum similar samples required before adding an extra template.")
    parser.add_argument("--template-diversity-threshold", type=float, default=0.85, help="Similarity threshold used to keep templates diverse.")
    parser.add_argument("--task-sequences", default="", help="JSON or text file containing normal procedural action sequences.")
    parser.add_argument("--include-ports", default="", help="Comma-separated ports to keep. Empty means all ports.")
    parser.add_argument("--exclude-ports", default="22", help="Comma-separated ports to remove. Default removes SSH noise.")
    parser.add_argument("--signal-bin-size", type=float, default=0.02, help="Signal bin size in seconds.")
    parser.add_argument("--signal-protocol", choices=["all", "tcp", "udp"], default="all", help="Signal protocol filter.")
    parser.add_argument("--signal-length-mode", choices=["packet", "ip", "transport", "payload"], default="packet", help="Signal length mode.")
    parser.add_argument("--signal-classifier", choices=["rf", "xgboost"], default="rf", help="Signal classifier.")
    parser.add_argument("--positive-ip", default="", help="Force positive direction IP for signal pipeline.")
    parser.add_argument("--signal-no-loo", action="store_true", help="Skip signal leave-one-out evaluation.")
    args = parser.parse_args()

    root = Path(args.root)
    out = Path(args.out)
    if args.mode == "signal":
        signal_out = out / "signal_pipeline"
        report = run_signal_pipeline(
            root,
            signal_out,
            bin_size=args.signal_bin_size,
            protocol=args.signal_protocol,
            positive_ip=args.positive_ip or None,
            length_mode=args.signal_length_mode,
            classifier=args.signal_classifier,
            no_loo=args.signal_no_loo,
        )
        print(f"Saved signal pipeline outputs to: {signal_out.resolve()}")
        if report.get("leave_one_out_report"):
            accuracy = report["leave_one_out_report"].get("accuracy")
            print(f"Signal leave-one-out accuracy: {accuracy}")
        return
    pcap_files = sorted(p for p in root.glob("*/*.pcap"))
    if not pcap_files:
        raise SystemExit("No .pcap files found under label folders.")

    include_ports = {int(p) for p in args.include_ports.split(",") if p.strip()}
    exclude_ports = {int(p) for p in args.exclude_ports.split(",") if p.strip()}
    local_ips = discover_local_ips(pcap_files)

    all_rows = []
    sample_rows = []
    summaries = []
    for path in pcap_files:
        label = path.parent.name
        rows, summary = extract_window_features(path, local_ips, args.window_ms, include_ports, exclude_ports)
        sample = path.stem
        for row in rows:
            row["label"] = label
            row["sample"] = sample
            row["source_file"] = str(path)
            all_rows.append(row)
        summary.update({"label": label, "sample": sample, "source_file": str(path), "windows": len(rows)})
        summaries.append(summary)
        print(f"extracted {label}/{sample}: raw={summary['raw_packets']} kept={summary['kept_packets']} windows={len(rows)}")

    x = np.array([[row[c] for c in FEATURE_COLUMNS] for row in all_rows], dtype=float)
    xz, mu, sigma = standardize(np.log1p(x))
    cluster_labels, centroids = kmeans(xz, k=args.clusters)
    for row, cluster in zip(all_rows, cluster_labels):
        row["cluster"] = int(cluster)
        row["symbol"] = chr(ord("A") + int(cluster))

    sequences_by_label = defaultdict(list)
    for (label, sample), rows in sorted(group_rows(all_rows).items()):
        labels = [r["cluster"] for r in sorted(rows, key=lambda r: r["window_idx"])]
        seq = compress_sequence(labels)
        sample_rows.append({"label": label, "sample": sample, "sequence": seq, "length": len(seq)})
        sequences_by_label[label].append(seq)

    tcs = temporal_consistency_score(sequences_by_label)
    between_scores = []
    labels = sorted(sequences_by_label)
    for i, a in enumerate(labels):
        for b in labels[i + 1 :]:
            sims = [sequence_similarity(sa, sb) for sa in sequences_by_label[a] for sb in sequences_by_label[b]]
            between_scores.append({"a": a, "b": b, "mean_similarity": float(np.mean(sims))})

    mean_within = float(np.mean(list(tcs.values())))
    mean_between = float(np.mean([r["mean_similarity"] for r in between_scores]))
    separability = mean_within - mean_between
    nn_acc, nn_predictions = nearest_neighbor_accuracy(sample_rows)
    templates = build_action_templates(
        sample_rows,
        max_templates=args.max_templates_per_action,
        min_template_support=args.min_template_support,
        diversity_threshold=args.template_diversity_threshold,
    )
    template_scores = score_against_templates(sample_rows, templates)
    loo_template_scores = leave_one_out_template_scores(
        sample_rows,
        max_templates=args.max_templates_per_action,
        min_template_support=args.min_template_support,
        diversity_threshold=args.template_diversity_threshold,
    )
    action_thresholds = compute_action_thresholds(loo_template_scores)
    template_scores = attach_threshold_decisions(template_scores, action_thresholds)
    loo_template_scores = attach_threshold_decisions(loo_template_scores, action_thresholds)
    loo_template_acc = float(np.mean([r["loo_correct"] for r in loo_template_scores]))
    template_summary = summarize_template_scores(loo_template_scores)
    default_task_path = Path(__file__).with_name("database_know") / "normal_sequences.json"
    task_sequence_path = args.task_sequences or (
        str(default_task_path) if default_task_path.exists() else ""
    )
    task_sequences = load_task_sequences(task_sequence_path)
    if not task_sequences:
        task_sequences = build_default_task_sequences(sequences_by_label.keys())
    transition_scores, transition_graph, transition_edge_counts = score_task_transitions(
        task_sequences,
        sample_rows,
        templates,
        action_thresholds=action_thresholds,
    )
    transition_graph_rows = flatten_transition_graph(transition_graph, transition_edge_counts)

    fieldnames = ["label", "sample", "source_file", "window_idx", "t_start_s"] + FEATURE_COLUMNS + ["cluster", "symbol"]
    save_csv(out / "window_features.csv", all_rows, fieldnames)
    save_csv(out / "sample_sequences.csv", sample_rows, ["label", "sample", "length", "sequence"])
    save_csv(out / "pcap_summary.csv", summaries, ["label", "sample", "source_file", "raw_packets", "kept_packets", "duration_s", "windows"])
    save_csv(out / "nearest_neighbor_predictions.csv", nn_predictions, ["label", "sample", "predicted_label", "nearest_sample", "nearest_similarity", "correct"])
    flat_templates = [template for label_templates in templates.values() for template in label_templates]
    save_csv(out / "action_templates.csv", flat_templates, ["label", "template_rank", "template_sample", "template_length", "action_avg_length", "template_similarity", "template_support", "template_sequence"])
    save_csv(out / "template_scores.csv", template_scores, ["label", "sample", "template_sample", "template_rank", "template_count", "own_template_similarity", "action_avg_length", "length_delta", "anomaly_score", "action_threshold", "template_is_anomaly", "best_other_label", "best_other_similarity", "margin_vs_other", "template_predicted_label", "template_correct"])
    save_csv(out / "leave_one_out_template_scores.csv", loo_template_scores, ["label", "sample", "loo_predicted_label", "loo_correct", "own_template_sample", "own_template_count", "own_template_similarity", "action_avg_length", "length_delta", "anomaly_score", "action_threshold", "template_is_anomaly", "best_other_label", "best_other_similarity", "margin_vs_other"])
    save_csv(out / "template_summary.csv", template_summary, ["label", "mean_anomaly_score", "max_anomaly_score", "mean_margin_vs_other", "template_accuracy", "anomaly_rate", "action_threshold"])
    save_csv(out / "task_transition_graph.csv", transition_graph_rows, ["prefix", "next_action", "count"])
    save_csv(out / "task_transition_scores.csv", transition_scores, ["task_id", "step_idx", "prefix", "papb_matched_actions", "papb_match_length", "current_action", "sample", "valid_next_actions", "best_valid_action", "best_template_sample", "best_template_rank", "valid_next_similarity", "action_avg_length", "length_delta", "transition_anomaly_score", "matched_action_threshold", "transition_is_valid", "transition_is_anomaly"])
    save_per_sample_outputs(out, all_rows, sample_rows, summaries)

    report = {
        "window_ms": args.window_ms,
        "clusters": args.clusters,
        "max_templates_per_action": args.max_templates_per_action,
        "min_template_support": args.min_template_support,
        "template_diversity_threshold": args.template_diversity_threshold,
        "include_ports": sorted(include_ports),
        "exclude_ports": sorted(exclude_ports),
        "local_ips_used_for_direction": sorted(local_ips),
        "temporal_consistency_score": tcs,
        "between_action_similarity": between_scores,
        "mean_within_action_similarity": mean_within,
        "mean_between_action_similarity": mean_between,
        "separability_score": separability,
        "nearest_neighbor_accuracy": nn_acc,
        "leave_one_out_template_accuracy": loo_template_acc,
        "action_anomaly_thresholds": action_thresholds,
        "action_templates": templates,
        "template_summary": template_summary,
        "task_sequences": task_sequences,
        "transition_graph_rows": transition_graph_rows,
        "task_transition_scores": transition_scores,
        "feature_columns": FEATURE_COLUMNS,
        "explanation": {
            "temporal_consistency_score": "Mean pairwise sequence similarity within the same action. Higher means more stable action evolution.",
            "between_action_similarity": "Mean sequence similarity between different action labels. Lower means actions are easier to distinguish.",
        },
    }
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    np.savez(out / "model_params.npz", centroids=centroids, mean=mu, std=sigma)
    plot_sequences(sample_rows, out / "symbol_sequences.png")
    write_markdown_report(out / "REPORT.md", report, templates, template_summary)

    print("\nTemporal Consistency Score")
    for label, score in sorted(tcs.items()):
        print(f"  {label}: {score:.3f}")
    print(f"\nMean within-action similarity: {mean_within:.3f}")
    print(f"Mean between-action similarity: {mean_between:.3f}")
    print(f"Separability score: {separability:.3f}")
    print(f"Nearest-neighbor action accuracy: {nn_acc:.3f}")
    print(f"Leave-one-out template accuracy: {loo_template_acc:.3f}")
    print(f"\nSaved outputs to: {out.resolve()}")

    if args.mode == "hybrid":
        signal_out = out / "signal_pipeline"
        signal_report = run_signal_pipeline(
            root,
            signal_out,
            bin_size=args.signal_bin_size,
            protocol=args.signal_protocol,
            positive_ip=args.positive_ip or None,
            length_mode=args.signal_length_mode,
            classifier=args.signal_classifier,
            no_loo=args.signal_no_loo,
        )
        hybrid_report = {
            "sequence_report": str((out / "report.json").resolve()),
            "signal_report": str(Path(signal_report["report_path"]).resolve()),
        }
        with open(out / "hybrid_report.json", "w", encoding="utf-8") as f:
            json.dump(hybrid_report, f, ensure_ascii=False, indent=2)
        print(f"Signal pipeline outputs: {signal_out.resolve()}")
        print(f"Hybrid report: {(out / 'hybrid_report.json').resolve()}")


def group_rows(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["label"], row["sample"])].append(row)
    return grouped


if __name__ == "__main__":
    main()
