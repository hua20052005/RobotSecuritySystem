#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert_flow_to_tsv_v3.py
=========================
V3 流级 TSV 转换器，支持 3 种采样密度用于消融实验。

用法:
  python convert_flow_to_tsv_v3.py --mode 4pos   # 4位置×120B=480bigrams
  python convert_flow_to_tsv_v3.py --mode 8pos   # 8位置×60B=480bigrams
  python convert_flow_to_tsv_v3.py --mode full   # 64包×7B=448bigrams
"""

import os, csv, random, argparse
import numpy as np

FLOW_DIR   = "dataset/flow_v3"
OUTPUT_BASE = "datasets/flow_v3"

FLOW_FILES = {
    0: f"{FLOW_DIR}/flow_normal.npy",
    1: f"{FLOW_DIR}/flow_heartbeat_hijack.npy",
    2: f"{FLOW_DIR}/flow_command_steganography.npy",
    3: f"{FLOW_DIR}/flow_command_flooding.npy",
    4: f"{FLOW_DIR}/flow_protocol_downgrade.npy",
    5: f"{FLOW_DIR}/flow_msgtype_sequence_anomaly.npy",
    6: f"{FLOW_DIR}/flow_silence_injection.npy",
}

SAMPLING_CONFIGS = {
    "4pos": {"positions": [0, 21, 42, 63],            "bytes": 120, "name": "4位置×120B"},
    "8pos": {"positions": [0, 9, 18, 27, 36, 45, 54, 63], "bytes": 60,  "name": "8位置×60B"},
    "full": {"positions": list(range(64)),             "bytes": 7,   "name": "64包×7B"},
}

SEED = 42


def flow_to_bigram_string(flow_seq, positions, nbytes):
    all_bigrams = []
    for pos in positions:
        chunk = flow_seq[pos][:nbytes]
        hex_str = chunk.astype(np.uint8).tobytes().hex()
        all_bigrams.extend([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
    return " ".join(all_bigrams)


def load_and_label():
    random.seed(SEED); np.random.seed(SEED)
    payloads, labels = [], []
    for lb in sorted(FLOW_FILES):
        arr = np.load(FLOW_FILES[lb])
        print(f"[INFO] label={lb}: {os.path.basename(FLOW_FILES[lb])} {arr.shape}")
        payloads.append(arr)
        labels.append(np.full(len(arr), lb, dtype=np.int32))
    all_p = np.vstack(payloads)
    all_l = np.concatenate(labels)
    perm = np.random.permutation(len(all_p))
    return all_p[perm], all_l[perm]


def split_save(payloads, labels, output_dir, positions, nbytes):
    n = len(payloads)
    indices = np.random.permutation(n)
    splits = {
        "train": indices[:int(n*0.8)],
        "valid": indices[int(n*0.8):int(n*0.9)],
        "test":  indices[int(n*0.9):],
    }
    os.makedirs(output_dir, exist_ok=True)

    for split_name, idx in splits.items():
        path = os.path.join(output_dir, f"{split_name}_dataset.tsv")
        print(f"\n[SAVE] {split_name}: {len(idx)} → {path}")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(["label", "text_a"])
            for i, pos in enumerate(idx):
                bigrams = flow_to_bigram_string(payloads[pos], positions, nbytes)
                w.writerow([int(labels[pos]), bigrams])
                if (i+1) % 10000 == 0:
                    print(f"  {i+1}/{len(idx)} ...")
        counts = {lb: int(np.sum(labels[idx]==lb)) for lb in sorted(FLOW_FILES)}
        print(f"  分布: {counts}")

    # nolabel
    nolabel = os.path.join(output_dir, "nolabel_test_dataset.tsv")
    print(f"\n[SAVE] nolabel test: {len(splits['test'])} → {nolabel}")
    with open(nolabel, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["text_a"])
        for pos in splits["test"]:
            w.writerow([flow_to_bigram_string(payloads[pos], positions, nbytes)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["4pos","8pos","full"], required=True)
    args = parser.parse_args()

    cfg = SAMPLING_CONFIGS[args.mode]
    output_dir = f"{OUTPUT_BASE}_{args.mode}"
    bigram_count = len(cfg["positions"]) * cfg["bytes"]

    print(f"[INFO] 采样模式: {cfg['name']}")
    print(f"[INFO] 输出目录: {output_dir}")
    print(f"[INFO] bigram 总数: {bigram_count}")

    payloads, labels = load_and_label()
    split_save(payloads, labels, output_dir, cfg["positions"], cfg["bytes"])
    print(f"\n[DONE] V3 {args.mode} TSV 完成。")


if __name__ == "__main__":
    main()
