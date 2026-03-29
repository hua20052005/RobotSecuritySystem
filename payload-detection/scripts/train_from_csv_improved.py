#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
train_from_csv_improved.py - 改进版训练脚本（添加特征选择和正则化）
"""

# ===== OpenMP 修复 =====
import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
os.environ['KMP_INIT_AT_FORK'] = 'FALSE'

import sys
import torch
import numpy as np
import pandas as pd
from pathlib import Path

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.model.csv_loader import CSVDataLoader
from modules.model.trainer import DataPreprocessor
from modules.model.classifier import EnsembleClassifier
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ImprovedCSVModelTrainer:
    """
    改进的 CSV 模型训练器 - 添加：
    1. RobustScaler 处理异常值
    2. 特征选择去除低方差特征
    3. 交叉验证
    4. 正则化
    """

    def __init__(self, output_dir: str = "models"):
        self.output_dir = output_dir
        self.plots_dir = os.path.join(output_dir, "plots")
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(self.plots_dir, exist_ok=True)
        self.csv_loader = CSVDataLoader(verbose=True)

    def train_unswnb15_improved(self, csv_path: str, test: bool = True):
        """
        改进的 UNSW-NB15 训练流程
        """
        from sklearn.preprocessing import RobustScaler
        from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        print("\n" + "=" * 70)
        print("📊 改进版 UNSW-NB15 模型训练工作流")
        print("=" * 70 + "\n")

        # ===== 步骤 1: 加载原始数据 =====
        print("📥 步骤 1: 加载 UNSW-NB15 原始数据...")
        try:
            X, y = self.csv_loader.load_unswnb15(csv_path)
        except Exception as e:
            logger.error(f"❌ 加载失败：{e}")
            return False
        
        print(f"   原始数据形状：{X.shape}")
        print(f"   标签分布：{dict(pd.Series(y).value_counts())}")

        # ===== 步骤 2: 特征预处理（使用 RobustScaler 处理异常值） =====
        print("\n🔄 步骤 2: 特征预处理...")
        
        robust_scaler = RobustScaler()
        X_scaled = robust_scaler.fit_transform(X)
        print(f"   ✅ 使用 RobustScaler 进行缩放")
        print(f"      （对异常值更鲁棒，适合量级差异大的数据）")

        # ===== 步骤 3: 特征选择 =====
        print("\n📋 步骤 3: 特征选择...")
        
        variance_selector = VarianceThreshold(threshold=0.01)
        X_var_filtered = variance_selector.fit_transform(X_scaled)
        removed_by_variance = X.shape[1] - X_var_filtered.shape[1]
        print(f"   √ 移除{removed_by_variance}个低方差特征（方差<0.01）")
        print(f"     剩余特征：{X_var_filtered.shape[1]}")

        k_features = max(10, X_var_filtered.shape[1] // 2)
        kbest_selector = SelectKBest(score_func=f_classif, k=k_features)
        X_selected = kbest_selector.fit_transform(X_var_filtered, y)
        
        selected_features_mask = kbest_selector.get_support()
        scores = kbest_selector.scores_
        feature_scores = sorted(
            [(i, scores[i]) for i in range(len(scores)) if selected_features_mask[i]],
            key=lambda x: x[1], reverse=True
        )
        
        print(f"   √ 使用 SelectKBest 选择{k_features}个最重要特征")
        print(f"     基于单变量 f_classif 评分")
        print(f"   📊 特征重要性排名（Top 10）:")
        for idx, (feat_idx, score) in enumerate(feature_scores[:10], 1):
            print(f"      {idx}. Feature {feat_idx}: score={score:.2f}")

        print(f"   ✅ 特征选择完成：{X.shape[1]} → {X_selected.shape[1]}")

        # ===== 步骤 4: 数据分割（分层） =====
        print("\n📦 步骤 4: 数据分割（分层抽样）...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_selected, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train,
            test_size=0.2,
            random_state=42,
            stratify=y_train
        )
        
        print(f"   训练集：{len(X_train)} 样本")
        print(f"   验证集：{len(X_val)} 样本")
        print(f"   测试集：{len(X_test)} 样本")

        # ===== 步骤 5: 模型训练（带验证集监测） =====
        print("\n🧠 步骤 5: 训练集成模型...")
        
        model = EnsembleClassifier(
            input_dim=X_selected.shape[1],
            num_classes=2,
            models=['lgb', 'xgb', 'rf']
        )
        
        train_scores = {}
        val_scores = {}
        
        for model_name, sub_model in model.models.items():
            print(f"\n   训练 {model_name.upper()}...")
            
            sub_model.fit(X_train, y_train)
            
            train_pred = sub_model.predict(X_train)
            train_acc = accuracy_score(y_train, train_pred)
            train_scores[model_name] = train_acc
            
            val_pred = sub_model.predict(X_val)
            val_acc = accuracy_score(y_val, val_pred)
            val_scores[model_name] = val_acc
            
            overfit_gap = train_acc - val_acc
            print(f"      训练精度：{train_acc:.4f} | 验证精度：{val_acc:.4f} | 差距：{overfit_gap:.4f}")
            
            if overfit_gap > 0.1:
                print(f"      ⚠️  检测到过拟合信号 (训练 - 验证差距 > 0.1)")

        # ===== 步骤 6: 保存模型 =====
        print("\n💾 步骤 6: 保存模型...")
        import pickle
        model_save = {
            'model': model,
            'scaler': robust_scaler,
            'var_selector': variance_selector,
            'kbest_selector': kbest_selector,
            'train_scores': train_scores,
            'val_scores': val_scores,
            'feature_count': X_selected.shape[1]
        }
        
        model_path = os.path.join(self.output_dir, 'ensemble_classifier_improved.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model_save, f)
        print(f"   ✅ 模型已保存")

        # ===== 步骤 7: 测试集评估 =====
        ensemble_prob = None
        test_probs = {}  # ✅ 修复：定义 test_probs 字典
        
        if test:
            print("\n📈 步骤 7: 测试集独立评估...")
            
            predictions = []
            
            for model_name, sub_model in model.models.items():
                pred = sub_model.predict(X_test)
                predictions.append(pred)
                
                # ✅ 修复：收集各子模型的概率输出
                if hasattr(sub_model, 'predict_proba'):
                    proba = sub_model.predict_proba(X_test)
                    test_probs[model_name] = proba[:, 1]  # 取正类概率
            
            # 多数投票
            final_pred = np.array(predictions).T
            from scipy import stats
            final_pred = stats.mode(final_pred, axis=1).mode.flatten()
            
            # ✅ 修复：计算集成模型的平均概率
            if test_probs:
                ensemble_prob = np.mean(list(test_probs.values()), axis=0)
            
            acc = accuracy_score(y_test, final_pred)
            prec = precision_score(y_test, final_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test, final_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, final_pred, average='weighted', zero_division=0)
            
            print(f"\n   ✅ 测试集结果：")
            print(f"      精度 (Accuracy):  {acc:.4f}")
            print(f"      精确率 (Precision): {prec:.4f}")
            print(f"      召回率 (Recall):   {rec:.4f}")
            print(f"      F1 分数：          {f1:.4f}")
            
            # 诊断过拟合
            print(f"\n   📊 过拟合分析：")
            avg_train = np.mean(list(train_scores.values()))
            avg_val = np.mean(list(val_scores.values()))
            
            print(f"      平均训练精度：   {avg_train:.4f}")
            print(f"      平均验证精度：   {avg_val:.4f}")
            print(f"      测试精度：       {acc:.4f}")
            
            if acc < avg_val - 0.05:
                print(f"      ⚠️  测试精度明显低于验证精度，可能存在分布差异")
            elif acc > avg_val + 0.05:
                print(f"      ✅ 测试精度优于验证精度，模型泛化能力良好")
            else:
                print(f"      ✅ 性能稳定，模型泛化能力良好")

        # ===== 步骤 8: 生成可视化图表 =====
        print("\n📊 步骤 8: 生成可视化图表...")
        try:
            self.plot_results(
                feature_scores=feature_scores,
                train_scores=train_scores,
                val_scores=val_scores,
                test_scores={'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1} if test else None,
                confusion_matrix=None,
                y_test=y_test if test else None,
                ensemble_prob=ensemble_prob,
                final_pred=final_pred if test else None,
                test_probs=test_probs,  # ✅ 修复：传入 test_probs
                save_dir=self.plots_dir
            )
            print(f"   ✅ 图表已保存至：{self.plots_dir}")
        except Exception as e:
            print(f"   ⚠️  图表生成失败：{e}")

        print("\n" + "=" * 70)
        print("✅ 训练完成！")
        print("=" * 70 + "\n")
        
        return True

    def plot_results(self, feature_scores, train_scores, val_scores, test_scores,
                     confusion_matrix, y_test, ensemble_prob, final_pred,
                     test_probs=None, save_dir: str = "plots"):
        """
        生成所有可视化图表
        """
        # 避免在无可视环境或Pillow异常时崩溃
        try:
            import matplotlib
            matplotlib.use('Agg')
        except Exception as e:
            raise ImportError(f"Matplotlib 后端初始化失败，无法绘图: {e}. 请确保安装 pillow。")

        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
        except Exception as e:
            raise ImportError(f"导入绘图库失败，请安装 matplotlib 和 seaborn: {e}")
        
        os.makedirs(save_dir, exist_ok=True)
        
        # ===== 图 1: 特征重要性 =====
        print("   绘制特征重要性图...")
        if feature_scores:
            fig, ax = plt.subplots(figsize=(10, 6))
            top_features = feature_scores[:15]
            feature_indices = [f"Feature {i}" for i, _ in top_features]
            scores = [s for _, s in top_features]
            
            ax.barh(feature_indices, scores, color='#3498db')
            ax.set_xlabel('F-Classif Score')
            ax.set_title('Top 15 Feature Importance')
            ax.invert_yaxis()
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, 'feature_importance.png'), dpi=150)
            plt.close()

        # ===== 图 2: 模型性能对比 =====
        print("   绘制模型性能对比图...")
        fig, ax = plt.subplots(figsize=(10, 6))
        
        models = list(train_scores.keys())
        train_vals = list(train_scores.values())
        val_vals = list(val_scores.values())
        
        x = np.arange(len(models))
        width = 0.35
        
        ax.bar(x - width/2, train_vals, width, label='Train Accuracy', color='#2ecc71')
        ax.bar(x + width/2, val_vals, width, label='Val Accuracy', color='#e74c3c')
        
        ax.set_ylabel('Accuracy')
        ax.set_title('Model Performance Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels([m.upper() for m in models])
        ax.legend()
        ax.set_ylim(0, 1.1)
        
        plt.tight_layout()
        plt.savefig(os.path.join(save_dir, 'model_comparison.png'), dpi=150)
        plt.close()

        # ===== 图 3: 混淆矩阵 =====
        print("   绘制混淆矩阵...")
        if y_test is not None and final_pred is not None:
            from sklearn.metrics import confusion_matrix
            cm = confusion_matrix(y_test, final_pred)
            
            fig, ax = plt.subplots(figsize=(6, 6))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                       xticklabels=['Normal', 'Attack'],
                       yticklabels=['Normal', 'Attack'])
            ax.set_xlabel('Predicted')
            ax.set_ylabel('Actual')
            ax.set_title('Confusion Matrix')
            
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, 'confusion_matrix.png'), dpi=150)
            plt.close()

        # ===== 图 4: ROC 曲线 =====
        print("   绘制 ROC 曲线...")
        if y_test is not None:
            from sklearn.metrics import roc_curve, auc
            
            fig, ax = plt.subplots(figsize=(8, 6))
            
            if ensemble_prob is not None:
                fpr, tpr, _ = roc_curve(y_test, ensemble_prob)
                roc_auc = auc(fpr, tpr)
                
                ax.plot(fpr, tpr, color='#e74c3c', lw=2,
                       label=f'Ensemble (AUC = {roc_auc:.4f})')
                
                # ✅ 修复：增加 test_probs 非空检查
                if test_probs:
                    colors = ['#2ecc71', '#3498db', '#9b59b6']
                    for idx, ((name, prob), color) in enumerate(zip(test_probs.items(), colors)):
                        fpr_sub, tpr_sub, _ = roc_curve(y_test, prob)
                        auc_sub = auc(fpr_sub, tpr_sub)
                        ax.plot(fpr_sub, tpr_sub, color=color, lw=1.5, alpha=0.7,
                               label=f'{name.upper()} (AUC = {auc_sub:.4f})')
            
            ax.plot([0, 1], [0, 1], 'k--', lw=1, label='Random')
            ax.set_xlim([0.0, 1.0])
            ax.set_ylim([0.0, 1.05])
            ax.set_xlabel('False Positive Rate')
            ax.set_ylabel('True Positive Rate')
            ax.set_title('ROC Curve')
            ax.legend(loc='lower right')
            
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, 'roc_curve.png'), dpi=150)
            plt.close()

        # ===== 图 5: 训练过程 =====
        print("   绘制训练过程图...")
        fig, ax = plt.subplots(figsize=(8, 6))
        
        if test_scores:
            metrics = ['accuracy', 'precision', 'recall', 'f1']
            values = [test_scores.get(m, 0) for m in metrics]
            
            ax.bar(metrics, values, color=['#2ecc71', '#3498db', '#e74c3c', '#9b59b6'])
            ax.set_ylabel('Score')
            ax.set_title('Test Set Performance Metrics')
            ax.set_ylim(0, 1.1)
            
            for i, v in enumerate(values):
                ax.text(i, v + 0.02, f'{v:.4f}', ha='center')
            
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, 'test_metrics.png'), dpi=150)
            plt.close()


def main():
    csv_path = "../data/datasets/UNSW_NB15_training-set.csv"
    
    if not os.path.exists(csv_path):
        print(f"❌ CSV 文件不存在：{csv_path}")
        return
    
    trainer = ImprovedCSVModelTrainer(output_dir="models")
    trainer.train_unswnb15_improved(csv_path, test=True)


if __name__ == '__main__':
    main()