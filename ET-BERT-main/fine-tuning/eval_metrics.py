#!/usr/bin/env python3
"""
eval_metrics.py — 对比预测结果与真实标签，输出混淆矩阵 + 每类 P/R/F1
"""
import sys
import numpy as np

def main():
    tsv_path = sys.argv[1]      # test_dataset.tsv (含真实标签)
    pred_path = sys.argv[2]     # test_prediction.txt (含预测标签)
    labels_num = int(sys.argv[3])

    # 读真实标签
    with open(tsv_path, "r", encoding="utf-8") as f:
        lines = f.readlines()[1:]  # skip header
    y_true = [int(l.strip().split("\t")[0]) for l in lines]

    # 读预测标签
    with open(pred_path, "r", encoding="utf-8") as f:
        lines = f.readlines()[1:]  # skip header
    y_pred = [int(l.strip().split("\t")[0]) for l in lines]

    assert len(y_true) == len(y_pred), f"数量不一致: {len(y_true)} vs {len(y_pred)}"

    # 混淆矩阵
    confusion = np.zeros((labels_num, labels_num), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        confusion[p, t] += 1

    print("Confusion matrix (row=pred, col=true):")
    print(confusion)

    # 每类指标
    eps = 1e-9
    correct = np.trace(confusion)
    total = confusion.sum()
    print(f"\nAcc. (Correct/Total): {correct/total:.4f} ({correct}/{total})")
    print(f"\n{'Class':<8} {'Precision':<10} {'Recall':<10} {'F1':<10} {'Support':<10}")
    print("-" * 48)

    for i in range(labels_num):
        tp = confusion[i, i]
        pred_total = confusion[i, :].sum()
        true_total = confusion[:, i].sum()
        p = tp / (pred_total + eps)
        r = tp / (true_total + eps)
        f1 = 2 * p * r / (p + r + eps)
        print(f"{i:<8} {p:<10.4f} {r:<10.4f} {f1:<10.4f} {true_total:<10}")

    # 宏平均
    macro_p = np.mean([confusion[i,i] / (confusion[i,:].sum() + eps) for i in range(labels_num)])
    macro_r = np.mean([confusion[i,i] / (confusion[:,i].sum() + eps) for i in range(labels_num)])
    macro_f1 = 2 * macro_p * macro_r / (macro_p + macro_r + eps)
    print("-" * 48)
    print(f"{'macro avg':<8} {macro_p:<10.4f} {macro_r:<10.4f} {macro_f1:<10.4f} {total:<10}")

if __name__ == "__main__":
    main()
