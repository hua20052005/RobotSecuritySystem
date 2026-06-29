#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert_flow_to_tsv.py
======================
将流级数据集 (.npy uint8 arrays, shape=(N,64,380)) 转换为 TSV 格式。

流级每个样本含 64 包 × 380 字节，总量过大无法直接全量编码。
策略：从 64 包中均匀采样 4 个代表位置（0, 21, 42, 63），
      每包取前 120 字节 → 240 hex → 120 bigrams，
      4 包合并: 480 bigrams + [CLS] < 512，适配 seq_length。

输出 TSV 格式:
  label\ttext_a
  0\tab cd ef 01 23 ...      (480 bigrams, space-separated)

数据划分: 8:1:1
"""

import os
import csv
import random
import argparse
import numpy as np

# ── 配置（纯相对路径，从项目根目录运行）──
OUTPUT_DIR = "datasets/flow"

# 从 64 包序列中采样的位置和每包字节数
SAMPLE_POSITIONS = [0, 21, 42, 63]   # 均匀覆盖整条流
BYTES_PER_PACKET = 120                # 每包取前 N 字节

FLOW_FILES = {
    0:  "dataset/flow/flow_normal.npy",
    7:  "dataset/flow/flow_replay.npy",
    8:  "dataset/flow/flow_state_logic_jump.npy",
    9:  "dataset/flow/flow_heartbeat_hijack.npy",
    10: "dataset/flow/flow_command_steganography.npy",
    11: "dataset/flow/flow_flooding.npy",
    12: "dataset/flow/flow_out_of_order.npy",
}

# 流级标签重映射：{0,7,8,9,10,11,12} → {0,1,2,3,4,5,6}
LABEL_REMAP_FLOW = {0: 0, 7: 1, 8: 2, 9: 3, 10: 4, 11: 5, 12: 6}

SEED = 42


def flow_to_bigram_string(flow_seq: np.ndarray) -> str:
    """
    将流序列 (64, 380) 转为空格分隔的 hex bigram 字符串。
    采样 4 个位置 × 每包 120 字节 = 480 bigrams。
    """
    all_bigrams = []
    for pos in SAMPLE_POSITIONS:
        pkt = flow_seq[pos]  # shape (380,)
        # 取前 BYTES_PER_PACKET 字节
        chunk = pkt[:BYTES_PER_PACKET]
        hex_str = chunk.astype(np.uint8).tobytes().hex()
        bigrams = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        all_bigrams.extend(bigrams)
    return " ".join(all_bigrams)


def load_and_label():
    """加载流级数据，返回 (payloads_list, labels_list)"""
    random.seed(SEED)
    np.random.seed(SEED)

    payloads = []
    labels = []

    for label_id in sorted(FLOW_FILES.keys()):
        fpath = FLOW_FILES[label_id]
        print(f"[INFO] 加载 label={label_id:2d}: {os.path.basename(fpath)}")
        arr = np.load(fpath)
        print(f"       形状: {arr.shape} (N={arr.shape[0]}, seq={arr.shape[1]}, dim={arr.shape[2]})")
        payloads.append(arr)
        labels.append(np.full(len(arr), label_id, dtype=np.int32))

    all_payloads = np.vstack(payloads)   # (N, 64, 380)
    all_labels = np.concatenate(labels)

    # ── 打乱 ──
    perm = np.random.permutation(len(all_payloads))
    all_payloads = all_payloads[perm]
    all_labels = all_labels[perm]

    bigram_count = len(SAMPLE_POSITIONS) * BYTES_PER_PACKET
    print(f"\n[INFO] 总计: {len(all_payloads)} 条")
    print(f"[INFO] 每条样本: {len(SAMPLE_POSITIONS)} 包 × {BYTES_PER_PACKET} 字节 = {bigram_count} bigrams")
    for lb in sorted(FLOW_FILES.keys()):
        print(f"       label {lb:2d}: {np.sum(all_labels==lb)} 条")
    return all_payloads, all_labels


def split_save(payloads, labels, output_dir):
    """8:1:1 划分并写入 TSV"""
    n = len(payloads)
    indices = np.random.permutation(n)
    train_end = int(n * 0.8)
    valid_end = int(n * 0.9)

    splits = {
        "train": indices[:train_end],
        "valid": indices[train_end:valid_end],
        "test":  indices[valid_end:],
    }

    os.makedirs(output_dir, exist_ok=True)

    for split_name, idx in splits.items():
        tsv_path = os.path.join(output_dir, f"{split_name}_dataset.tsv")
        print(f"\n[SAVE] {split_name}: {len(idx)} 条 → {tsv_path}")

        split_labels = labels[idx]
        class_counts = {lb: int(np.sum(split_labels == lb))
                        for lb in sorted(FLOW_FILES.keys())}

        with open(tsv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["label", "text_a"])
            for i, pos in enumerate(idx):
                bigram_str = flow_to_bigram_string(payloads[pos])
                remapped = LABEL_REMAP_FLOW[int(labels[pos])]
                writer.writerow([remapped, bigram_str])
                if (i + 1) % 10000 == 0:
                    print(f"       已写入 {i+1}/{len(idx)} ...")

        remapped_counts = {LABEL_REMAP_FLOW[lb]: int(np.sum(split_labels == lb))
                           for lb in sorted(FLOW_FILES.keys())}
        print(f"       类别分布 (remapped): {remapped_counts}")

    # 无标签测试集
    nolabel_path = os.path.join(output_dir, "nolabel_test_dataset.tsv")
    print(f"\n[SAVE] nolabel test: {len(splits['test'])} 条 → {nolabel_path}")
    with open(nolabel_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["text_a"])
        for pos in splits["test"]:
            writer.writerow([flow_to_bigram_string(payloads[pos])])


def main():
    parser = argparse.ArgumentParser(description="Convert flow-level .npy to TSV")
    parser.add_argument("--output_dir", default=OUTPUT_DIR, help="TSV output directory")
    args = parser.parse_args()

    payloads, labels = load_and_label()
    split_save(payloads, labels, args.output_dir)
    print("\n[DONE] 流级 TSV 数据集构建完成。")


if __name__ == "__main__":
    main()
