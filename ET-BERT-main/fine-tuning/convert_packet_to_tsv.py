#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert_packet_to_tsv.py
========================
将包级数据集 (.npy uint8 arrays) 转换为 ET-BERT 微调所需的 TSV 格式。

转换流程：
  380 字节 payload → 每字节转 2 位 hex → 每 2 hex 组成 1 个 bigram token
  → 380 个 bigrams，以空格分隔 → 写入 TSV 的 text_a 列

输出 TSV 格式:
  label\ttext_a
  0\tab cd ef 01 23 ...
  1\tfe dc ba 98 ...

数据划分: 8:1:1 (train:valid:test)
"""

import os
import sys
import csv
import random
import argparse
import numpy as np

# ── 配置（纯相对路径，从项目根目录运行）──
OUTPUT_DIR = "datasets/packet"

NORMAL_FILE = "dataset/normal_all.npy"

ANOMALY_FILES = {
    1: "dataset/anomaly/anomaly_unauthorized_src.npy",
    2: "dataset/anomaly/anomaly_port_scanning.npy",
    3: "dataset/anomaly/anomaly_boundary_value.npy",
    4: "dataset/anomaly/anomaly_semantic_inversion.npy",
    5: "dataset/anomaly/anomaly_fuzzing.npy",
    6: "dataset/anomaly/anomaly_buffer_overflow.npy",
}

NORMAL_LIMIT = 360000   # 下采样正常样本使与异常均衡
SEED = 42


def payload_to_bigram_string(payload: np.ndarray) -> str:
    """
    将 uint8 payload 转为空格分隔的 hex bigram 字符串。
    payload: shape (380,) uint8
    返回: "ab cd ef 01 23 ..." (380 个 bigrams)
    """
    # 每个字节 → 2 位 hex，相邻 hex 配对为 bigram
    hex_str = payload.astype(np.uint8).tobytes().hex()
    bigrams = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    return " ".join(bigrams)


def load_and_label():
    """加载包级数据，返回 (payloads_list, labels_list)"""
    random.seed(SEED)
    np.random.seed(SEED)

    payloads = []
    labels = []

    # ── 正常样本 ──
    print(f"[INFO] 加载正常样本: {NORMAL_FILE}")
    normal_all = np.load(NORMAL_FILE)
    print(f"       全量: {len(normal_all)} 条")
    if NORMAL_LIMIT and len(normal_all) > NORMAL_LIMIT:
        idx = np.random.choice(len(normal_all), size=NORMAL_LIMIT, replace=False)
        normal_all = normal_all[idx]
        print(f"       下采样至: {len(normal_all)} 条")
    payloads.append(normal_all)
    labels.append(np.zeros(len(normal_all), dtype=np.int32))

    # ── 异常样本 ──
    for label_id in sorted(ANOMALY_FILES.keys()):
        fpath = ANOMALY_FILES[label_id]
        print(f"[INFO] 加载异常 label={label_id}: {os.path.basename(fpath)}")
        arr = np.load(fpath)
        print(f"       数量: {len(arr)} 条")
        payloads.append(arr)
        labels.append(np.full(len(arr), label_id, dtype=np.int32))

    all_payloads = np.vstack(payloads)
    all_labels = np.concatenate(labels)

    # ── 打乱 ──
    perm = np.random.permutation(len(all_payloads))
    all_payloads = all_payloads[perm]
    all_labels = all_labels[perm]

    print(f"\n[INFO] 总计: {len(all_payloads)} 条 (正常 {sum(all_labels==0)}, 异常 {sum(all_labels>0)})")
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

        # 统计类别分布
        split_labels = labels[idx]
        class_counts = {lb: int(np.sum(split_labels == lb)) for lb in range(7)}

        with open(tsv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["label", "text_a"])
            for i, pos in enumerate(idx):
                bigram_str = payload_to_bigram_string(payloads[pos])
                writer.writerow([int(labels[pos]), bigram_str])
                if (i + 1) % 50000 == 0:
                    print(f"       已写入 {i+1}/{len(idx)} ...")

        print(f"       类别分布: {class_counts}")

    # 额外输出无标签测试集（用于推理）
    nolabel_path = os.path.join(output_dir, "nolabel_test_dataset.tsv")
    print(f"\n[SAVE] nolabel test: {len(splits['test'])} 条 → {nolabel_path}")
    with open(nolabel_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["text_a"])
        for pos in splits["test"]:
            writer.writerow([payload_to_bigram_string(payloads[pos])])


def main():
    parser = argparse.ArgumentParser(description="Convert packet-level .npy to TSV")
    parser.add_argument("--output_dir", default=OUTPUT_DIR, help="TSV output directory")
    args = parser.parse_args()

    payloads, labels = load_and_label()
    split_save(payloads, labels, args.output_dir)
    print("\n[DONE] 包级 TSV 数据集构建完成。")


if __name__ == "__main__":
    main()
