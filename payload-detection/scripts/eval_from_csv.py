#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
eval.py - 评估脚本

用法示例：
python scripts/eval.py \
    --model models/ensemble_classifier_improved.pkl \
    --test data/datasets/UNSW_NB15_testing-set.csv \
    --output eval_result.csv
"""

import argparse
import os
import sys
import pickle
import csv

# 兼容直接在 scripts 目录下运行，确保 modules 可 import
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

from modules.model.csv_loader import CSVDataLoader


def parse_args():
    parser = argparse.ArgumentParser(description='评估训练好的模型（测试集）')
    parser.add_argument('--model', type=str, default='models/ensemble_classifier_improved.pkl', help='已保存模型路径')
    parser.add_argument('--test', type=str, default='data/datasets/UNSW_NB15_testing-set.csv', help='测试集 CSV 路径')
    parser.add_argument('--output', type=str, default='eval_output.csv', help='评估结果 CSV 输出文件')
    parser.add_argument('--verbose', action='store_true', help='打印详细日志')
    return parser.parse_args()


def load_saved_model(model_path):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f'Model file not found: {model_path}')

    with open(model_path, 'rb') as f:
        state = pickle.load(f)

    if 'model' not in state or 'scaler' not in state or 'var_selector' not in state or 'kbest_selector' not in state:
        raise KeyError('Model pickle must contain model/scaler/var_selector/kbest_selector')

    return state['model'], state['scaler'], state['var_selector'], state['kbest_selector']


def preprocess_data(X, scaler, var_selector, kbest_selector):
    X_scaled = scaler.transform(X)
    X_var = var_selector.transform(X_scaled)
    X_sel = kbest_selector.transform(X_var)
    return X_sel


def evaluate_labels(y_true, y_pred, verbose=False):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    rep = classification_report(y_true, y_pred, target_names=['Normal', 'Attack'], zero_division=0)

    if verbose:
        print('=== 评估结果 ===')
        print(f'Accuracy:  {acc:.4f}')
        print(f'Precision: {prec:.4f}')
        print(f'Recall:    {rec:.4f}')
        print(f'F1 Score:  {f1:.4f}')
        print('\nClassification Report:\n', rep)
        print('Confusion Matrix:\n', cm)

    return {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'confusion_matrix': cm,
        'report': rep
    }


def main():
    args = parse_args()

    loader = CSVDataLoader(verbose=args.verbose)
    X_test, y_test = loader.load_unswnb15(args.test)

    model, scaler, var_selector, kbest_selector = load_saved_model(args.model)

    X_test_proc = preprocess_data(X_test, scaler, var_selector, kbest_selector)

    if hasattr(model, 'predict'):
        y_pred = model.predict(X_test_proc)
    else:
        raise AttributeError('Loaded model has no predict() method')

    metrics = evaluate_labels(y_test, y_pred, verbose=args.verbose)

    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['item', 'value'])
        writer.writerow(['model', args.model])
        writer.writerow(['test', args.test])
        writer.writerow(['accuracy', metrics['accuracy']])
        writer.writerow(['precision', metrics['precision']])
        writer.writerow(['recall', metrics['recall']])
        writer.writerow(['f1', metrics['f1']])
        writer.writerow([])
        writer.writerow(['confusion_matrix'])
        for row in metrics['confusion_matrix']:
            writer.writerow(list(row))

    # 生成图形输出
    plot_dir = os.path.join(os.path.dirname(args.output), 'eval_plots')
    os.makedirs(plot_dir, exist_ok=True)
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import seaborn as sns

        # 指标柱状图
        plt.figure(figsize=(8, 6))
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1']
        metric_values = [metrics['accuracy'], metrics['precision'], metrics['recall'], metrics['f1']]
        sns.barplot(x=metric_names, y=metric_values, palette='viridis')
        plt.ylim(0, 1)
        for i, v in enumerate(metric_values):
            plt.text(i, v + 0.02, f'{v:.4f}', ha='center')
        plt.title('Evaluation Metrics')
        plt.tight_layout()
        metrics_path = os.path.join(plot_dir, 'eval_metrics.png')
        plt.savefig(metrics_path, dpi=150)
        plt.close()

        # 混淆矩阵热力图
        plt.figure(figsize=(6, 5))
        cm = metrics['confusion_matrix']
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Confusion Matrix')
        plt.tight_layout()
        cm_path = os.path.join(plot_dir, 'confusion_matrix.png')
        plt.savefig(cm_path, dpi=150)
        plt.close()

        print(f'✅ 图表已保存：{metrics_path}, {cm_path}')
    except Exception as e:
        print(f'⚠️ 图表生成失败: {e}')

    print(f'✅ 评估完成，结果已保存到：{args.output}')


if __name__ == '__main__':
    main()
