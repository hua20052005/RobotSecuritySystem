#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
train_anomaly_detector.py - 异常检测模型训练脚本
使用UNSW-NB15训练集训练IsolationForest异常检测器
输出：models/anomaly_detector.pkl
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.model.csv_loader import CSVDataLoader
from modules.model.anomaly_detector import IsolationForestAnomalyDetector
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AnomalyDetectorTrainer:
    """
    异常检测器训练器 - 基于IsolationForest
    """

    def __init__(self, output_dir: str = "models"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.csv_loader = CSVDataLoader(verbose=True)

    def train_from_unswnb15(self, csv_path: str, contamination: float = 0.1, 
                            n_estimators: int = 100, random_state: int = 42):
        """
        从UNSW-NB15数据集训练异常检测器
        
        Args:
            csv_path: CSV文件路径
            contamination: 异常比例（期望异常样本占比）
            n_estimators: 树的数量
            random_state: 随机种子
        """
        
        print("\n" + "=" * 70)
        print("🔍 异常检测器训练启动")
        print("=" * 70 + "\n")

        # ===== 步骤 1: 加载数据 =====
        print("📥 步骤 1: 加载 UNSW-NB15 训练数据...")
        try:
            X, y = self.csv_loader.load_unswnb15(csv_path)
        except Exception as e:
            logger.error(f"❌ 加载失败：{e}")
            return False
        
        print(f"\n   数据统计：")
        print(f"   - 样本数：{X.shape[0]:,}")
        print(f"   - 特征维度：{X.shape[1]}")
        
        # 统计标签分布
        unique, counts = np.unique(y, return_counts=True)
        label_dist = dict(zip(unique, counts))
        print(f"   - 标签分布：")
        for label, count in sorted(label_dist.items()):
            pct = 100.0 * count / len(y)
            print(f"     • {label} (攻击): {count:,} ({pct:.1f}%)" if label == 1 else f"     • {label} (正常): {count:,} ({pct:.1f}%)")

        # ===== 步骤 2: 特征标准化 =====
        print("\n🔄 步骤 2: 特征标准化...")
        from sklearn.preprocessing import RobustScaler
        
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)
        print(f"   ✅ 使用RobustScaler进行标准化（对异常值鲁棒）")

        # ===== 步骤 3: 训练异常检测器 =====
        print(f"\n🧠 步骤 3: 训练IsolationForest异常检测器...")
        print(f"   配置：")
        print(f"   - n_estimators: {n_estimators}")
        print(f"   - contamination: {contamination} (期望异常比例)")
        print(f"   - random_state: {random_state}")
        
        anomaly_detector = IsolationForestAnomalyDetector(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        
        anomaly_detector.fit(X_scaled)
        print(f"   ✅ 训练完成！")

        # ===== 步骤 4: 评估异常检测性能 =====
        print(f"\n📊 步骤 4: 检测器性能评估...")
        
        scores = anomaly_detector.predict(X_scaled)
        
        # 使用训练集上的性能评估
        y_pred = (scores > np.percentile(scores, 100 * contamination)).astype(int)
        
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        
        try:
            accuracy = accuracy_score(y, y_pred)
            precision = precision_score(y, y_pred, zero_division=0)
            recall = recall_score(y, y_pred, zero_division=0)
            f1 = f1_score(y, y_pred, zero_division=0)
            
            # 对于异常检测，compute AUC
            auc = roc_auc_score(y, scores)
            
            print(f"\n   ✅ 训练集评估结果：")
            print(f"   - 准确率 (Accuracy):  {accuracy:.4f}")
            print(f"   - 精确率 (Precision): {precision:.4f}")
            print(f"   - 召回率 (Recall):    {recall:.4f}")
            print(f"   - F1 分数：            {f1:.4f}")
            print(f"   - AUC 分数：           {auc:.4f}")
            
            # 诊断
            detected_anomalies = np.sum(y_pred)
            pct_detected = 100.0 * detected_anomalies / len(y_pred)
            print(f"\n   📈 检测统计：")
            print(f"   - 检测为异常样本：{detected_anomalies:,} ({pct_detected:.1f}%)")
            print(f"   - 实际异常样本：  {np.sum(y):,} ({100.0 * np.sum(y) / len(y):.1f}%)")
            
            if recall > 0.8:
                print(f"   ✅ 召回率良好，能捕捉大部分异常")
            elif recall > 0.5:
                print(f"   ⚠️  召回率中等，可能漏检部分异常")
            else:
                print(f"   ⚠️  召回率偏低，需要调整contamination参数")
                
        except Exception as e:
            print(f"   ⚠️  评估失败：{e}")

        # ===== 步骤 5: 保存模型 =====
        print(f"\n💾 步骤 5: 保存异常检测模型...")
        
        # 只保存detector和scaler（pipeline会直接调用detector的方法）
        model_save = {
            'detector': anomaly_detector,
            'scaler': scaler
        }
        
        model_path = os.path.join(self.output_dir, 'anomaly_detector.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model_save, f)
        
        file_size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"   ✅ 模型已保存：{model_path}")
        print(f"   - 文件大小：{file_size_mb:.2f} MB")

        # ===== 步骤 6: 保存配置 =====
        print(f"\n📋 步骤 6: 保存训练配置...")
        
        config = {
            'model_type': 'IsolationForestAnomalyDetector',
            'n_estimators': n_estimators,
            'contamination': contamination,
            'feature_dim': X.shape[1],
            'training_samples': X.shape[0],
            'data_source': 'UNSW-NB15',
            'attack_ratio': float(np.sum(y) / len(y)),
            'normal_ratio': float(np.sum(y == 0) / len(y))
        }
        
        config_path = os.path.join(self.output_dir, 'anomaly_detector_config.txt')
        with open(config_path, 'w') as f:
            f.write("异常检测模型配置\n")
            f.write("=" * 50 + "\n\n")
            for key, value in config.items():
                if isinstance(value, float):
                    f.write(f"{key}: {value:.4f}\n")
                else:
                    f.write(f"{key}: {value}\n")
        
        print(f"   ✅ 配置已保存：{config_path}")

        print("\n" + "=" * 70)
        print("✅ 异常检测器训练完成！")
        print("=" * 70)
        print("\n📌 下一步：")
        print("   1. 运行演示脚本测试模型：")
        print("      python scripts/run_optimized_pipeline.py")
        print("   2. 查看四源融合的异常检测评分")
        print("\n")
        
        return True


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='训练异常检测模型')
    parser.add_argument('csv_path', type=str, default='data/datasets/UNSW_NB15_training-set.csv',
                       nargs='?', help='UNSW-NB15 CSV文件路径')
    parser.add_argument('--contamination', type=float, default=0.1,
                       help='异常样本比例 (默认: 0.1)')
    parser.add_argument('--n_estimators', type=int, default=100,
                       help='IsolationForest树数量 (默认: 100)')
    parser.add_argument('--output_dir', type=str, default='models',
                       help='模型输出目录 (默认: models)')
    
    args = parser.parse_args()
    
    # 检查CSV文件存在
    if not os.path.exists(args.csv_path):
        print(f"❌ 错误：CSV文件不存在 - {args.csv_path}")
        sys.exit(1)
    
    trainer = AnomalyDetectorTrainer(output_dir=args.output_dir)
    success = trainer.train_from_unswnb15(
        csv_path=args.csv_path,
        contamination=args.contamination,
        n_estimators=args.n_estimators
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
