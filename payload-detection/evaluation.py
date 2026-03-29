# evaluation.py - 模型评估脚本

import torch
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    precision_recall_curve, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Any, Optional, Tuple
import json
import os
from datetime import datetime
import logging

from modules.model.inference import InferenceEngine, DetectionResult
from modules.model.trainer import DataPreprocessor, ExperimentTracker

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelEvaluator:
    """
    模型评估器
    """

    def __init__(self, inference_engine: InferenceEngine):
        """
        初始化评估器

        Args:
            inference_engine: 推理引擎实例
        """
        self.engine = inference_engine
        self.experiment_tracker = ExperimentTracker('evaluation_logs')

        # 设置matplotlib
        plt.style.use('default')
        sns.set_palette("husl")

    def evaluate_on_dataset(self, X: np.ndarray, y: np.ndarray,
                          dataset_name: str = "test_dataset") -> Dict[str, Any]:
        """
        在数据集上评估模型

        Args:
            X: 特征矩阵
            y: 标签向量
            dataset_name: 数据集名称

        Returns:
            Dict[str, Any]: 评估结果
        """
        logger.info(f"开始评估数据集: {dataset_name}")

        # 转换数据格式
        packets = self._features_to_packets(X)

        # 批量检测
        results = self.engine.detect_batch(packets)

        # 提取预测结果
        y_pred = []
        y_prob = []
        processing_times = []

        for result in results:
            # 转换检测结果为数值
            if result.result == DetectionResult.NORMAL:
                pred = 0
            elif result.result == DetectionResult.SUSPICIOUS:
                pred = 1
            elif result.result == DetectionResult.MALICIOUS:
                pred = 2
            else:  # UNKNOWN
                pred = 3

            y_pred.append(pred)
            y_prob.append(result.confidence)
            processing_times.append(result.processing_time)

        y_pred = np.array(y_pred)
        y_prob = np.array(y_prob)
        processing_times = np.array(processing_times)

        # 计算指标
        metrics = self._calculate_metrics(y, y_pred, y_prob)

        # 添加额外信息
        metrics.update({
            'dataset_name': dataset_name,
            'num_samples': len(y),
            'processing_time_avg': np.mean(processing_times),
            'processing_time_std': np.std(processing_times),
            'timestamp': datetime.now().isoformat()
        })

        logger.info(f"数据集 {dataset_name} 评估完成")
        return metrics

    def _features_to_packets(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """将特征矩阵转换为数据包格式"""
        packets = []
        for i in range(len(X)):
            # 创建模拟数据包
            packet = {
                'payload': f'sample_payload_{i}',
                'protocol': 'TCP',
                'src_ip': f'192.168.1.{i % 256}',
                'dst_ip': '10.0.0.1',
                'src_port': 10000 + i,
                'dst_port': 80,
                'features': X[i].tolist()
            }
            packets.append(packet)
        return packets

    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray,
                          y_prob: np.ndarray) -> Dict[str, Any]:
        """计算评估指标"""
        metrics = {}

        # 基础分类指标
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['precision_macro'] = precision_score(y_true, y_pred, average='macro', zero_division=0)
        metrics['precision_micro'] = precision_score(y_true, y_pred, average='micro', zero_division=0)
        metrics['recall_macro'] = recall_score(y_true, y_pred, average='macro', zero_division=0)
        metrics['recall_micro'] = recall_score(y_true, y_pred, average='micro', zero_division=0)
        metrics['f1_macro'] = f1_score(y_true, y_pred, average='macro', zero_division=0)
        metrics['f1_micro'] = f1_score(y_true, y_pred, average='micro', zero_division=0)

        # 分类报告
        class_report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        metrics['classification_report'] = class_report

        # 混淆矩阵
        cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()

        # AUC
        try:
            if len(np.unique(y_true)) == 2:  # 二分类
                auc = roc_auc_score(y_true, y_prob)
                metrics['auc'] = auc
            else:  # 多分类
                auc = roc_auc_score(y_true, y_prob, multi_class='ovr')
                metrics['auc'] = auc
        except:
            metrics['auc'] = None

        return metrics

    def cross_validate(self, X: np.ndarray, y: np.ndarray, n_folds: int = 5) -> Dict[str, Any]:
        """
        交叉验证

        Args:
            X: 特征矩阵
            y: 标签向量
            n_folds: 折数

        Returns:
            Dict[str, Any]: 交叉验证结果
        """
        logger.info(f"开始 {n_folds} 折交叉验证")

        fold_results = []
        fold_size = len(X) // n_folds

        for fold in range(n_folds):
            # 分割数据
            start_idx = fold * fold_size
            end_idx = (fold + 1) * fold_size if fold < n_folds - 1 else len(X)

            X_test = X[start_idx:end_idx]
            y_test = y[start_idx:end_idx]
            X_train = np.concatenate([X[:start_idx], X[end_idx:]])
            y_train = np.concatenate([y[:start_idx], y[end_idx:]])

            # 评估当前折
            fold_metrics = self.evaluate_on_dataset(X_test, y_test, f"fold_{fold+1}")
            fold_results.append(fold_metrics)

        # 计算平均结果
        cv_results = {}
        metric_keys = ['accuracy', 'precision_macro', 'precision_micro',
                      'recall_macro', 'recall_micro', 'f1_macro', 'f1_micro']

        for key in metric_keys:
            values = [fold[key] for fold in fold_results]
            cv_results[f'{key}_mean'] = np.mean(values)
            cv_results[f'{key}_std'] = np.std(values)

        cv_results['fold_results'] = fold_results
        cv_results['n_folds'] = n_folds

        logger.info("交叉验证完成")
        return cv_results

    def plot_confusion_matrix(self, cm: List[List[int]], class_names: List[str],
                            save_path: Optional[str] = None):
        """绘制混淆矩阵"""
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_names, yticklabels=class_names)
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def plot_roc_curve(self, y_true: np.ndarray, y_prob: np.ndarray,
                      save_path: Optional[str] = None):
        """绘制ROC曲线"""
        if len(np.unique(y_true)) != 2:
            logger.warning("ROC曲线只适用于二分类问题")
            return

        fpr, tpr, _ = roc_curve(y_true, y_prob)
        auc = roc_auc_score(y_true, y_prob)

        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, label=f'AUC = {auc:.3f}')
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend()
        plt.grid(True)

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_report(self, results: Dict[str, Any], output_path: str = 'evaluation_report.json'):
        """生成评估报告"""
        # 保存详细结果
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # 生成文本报告
        report_path = output_path.replace('.json', '.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("RoboGuard4 模型评估报告\n")
            f.write("="*50 + "\n\n")

            f.write(f"评估时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            if 'accuracy' in results:
                f.write("主要指标:\n")
                f.write(f"  准确率: {results['accuracy']:.4f}\n")
                f.write(f"  精确率 (Macro): {results['precision_macro']:.4f}\n")
                f.write(f"  召回率 (Macro): {results['recall_macro']:.4f}\n")
                f.write(f"  F1分数 (Macro): {results['f1_macro']:.4f}\n")

                if 'auc' in results and results['auc'] is not None:
                    f.write(f"  AUC: {results['auc']:.4f}\n")

                f.write(f"  处理时间 (平均): {results.get('processing_time_avg', 0):.6f} 秒\n")
                f.write(f"  处理时间 (标准差): {results.get('processing_time_std', 0):.6f} 秒\n")

            if 'confusion_matrix' in results:
                f.write("\n混淆矩阵:\n")
                cm = results['confusion_matrix']
                for row in cm:
                    f.write(f"  {row}\n")

        logger.info(f"评估报告已保存到: {report_path}")

    def benchmark_attack_detection(self, attack_samples: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        基准攻击检测性能

        Args:
            attack_samples: 攻击样本字典 {attack_type: [payloads]}

        Returns:
            Dict[str, Any]: 检测结果
        """
        logger.info("开始攻击检测基准测试")

        results = {}

        for attack_type, payloads in attack_samples.items():
            logger.info(f"测试 {attack_type} 攻击检测")

            detections = []
            for payload in payloads:
                packet = {
                    'payload': payload,
                    'protocol': 'TCP',
                    'src_ip': '192.168.1.100',
                    'dst_ip': '10.0.0.1',
                    'src_port': 12345,
                    'dst_port': 80
                }

                result = self.engine.detect_packet(packet)
                detected = result.result in [DetectionResult.SUSPICIOUS, DetectionResult.MALICIOUS]
                detections.append({
                    'payload': payload,
                    'detected': detected,
                    'confidence': result.confidence,
                    'result': result.result.value
                })

            # 计算检测率
            detection_rate = sum(1 for d in detections if d['detected']) / len(detections) if detections else 0
            avg_confidence = np.mean([d['confidence'] for d in detections]) if detections else 0

            results[attack_type] = {
                'detection_rate': detection_rate,
                'avg_confidence': avg_confidence,
                'total_samples': len(payloads),
                'detections': detections
            }

        logger.info("攻击检测基准测试完成")
        return results


def run_evaluation():
    """运行评估流程"""
    print("RoboGuard4 - 模型评估系统")
    print("="*50)

    # 初始化推理引擎
    try:
        engine = InferenceEngine()
        evaluator = ModelEvaluator(engine)
        print("✓ 评估系统初始化成功")
    except Exception as e:
        print(f"✗ 评估系统初始化失败: {e}")
        return

    # 生成模拟测试数据
    print("\n生成测试数据...")
    np.random.seed(42)

    # 正常样本
    n_normal = 1000
    X_normal = np.random.normal(0, 1, (n_normal, 43))  # 43维特征
    y_normal = np.zeros(n_normal)

    # 异常样本
    n_anomaly = 200
    X_anomaly = np.random.normal(2, 1.5, (n_anomaly, 43))
    y_anomaly = np.ones(n_anomaly)

    # 合并数据
    X = np.concatenate([X_normal, X_anomaly])
    y = np.concatenate([y_normal, y_anomaly])

    print(f"✓ 生成测试数据集: {len(X)} 样本, {X.shape[1]} 维特征")

    # 运行评估
    print("\n运行模型评估...")
    try:
        results = evaluator.evaluate_on_dataset(X, y, "synthetic_dataset")
        print("✓ 评估完成")

        # 显示关键指标
        print("主要指标:")
        print(f"  准确率: {results.get('accuracy', 0):.4f}")
        print(f"  精确率 (Macro): {results.get('precision_macro', 0):.4f}")
        print(f"  召回率 (Macro): {results.get('recall_macro', 0):.4f}")
        print(f"  F1分数 (Macro): {results.get('f1_macro', 0):.4f}")
        print(f"  处理时间 (平均): {results.get('processing_time_avg', 0):.6f} 秒")
        print(f"  样本数: {results.get('num_samples', 0)}")

        # 生成报告
        evaluator.generate_report(results)
        print("✓ 评估报告已生成")

    except Exception as e:
        print(f"✗ 评估失败: {e}")
        return

    # 攻击检测基准测试
    print("\n运行攻击检测基准测试...")
    attack_samples = {
        'SQL注入': [
            "SELECT * FROM users WHERE id='1' OR '1'='1'",
            "UNION SELECT username, password FROM admin--",
            "'; DROP TABLE users; --"
        ],
        'XSS攻击': [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(document.cookie)'
        ],
        '命令注入': [
            '; rm -rf /',
            '| cat /etc/passwd',
            '`whoami`'
        ]
    }

    try:
        attack_results = evaluator.benchmark_attack_detection(attack_samples)
        print("✓ 攻击检测基准测试完成")

        print("\n攻击检测结果:")
        for attack_type, result in attack_results.items():
            print(f"  {attack_type}: 检测率 {result['detection_rate']:.3f}")

        # 保存攻击检测结果
        with open('attack_detection_results.json', 'w', encoding='utf-8') as f:
            json.dump(attack_results, f, indent=2, ensure_ascii=False)

    except Exception as e:
        print(f"✗ 攻击检测基准测试失败: {e}")

    print("\n" + "="*50)
    print("评估流程完成！")
    print("="*50)


if __name__ == "__main__":
    run_evaluation()