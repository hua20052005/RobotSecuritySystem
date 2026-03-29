# trainer.py - 训练模块

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
import json
import os
from datetime import datetime

class ModelTrainer:
    """
    模型训练器
    """

    def __init__(self, model: nn.Module, device: str = 'auto'):
        self.model = model
        self.device = self._get_device(device)
        self.model.to(self.device)

        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }

    def _get_device(self, device: str) -> torch.device:
        """获取计算设备"""
        if device == 'auto':
            return torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        return torch.device(device)

    def train(self, train_loader: DataLoader, val_loader: Optional[DataLoader] = None,
              epochs: int = 100, lr: float = 1e-3, weight_decay: float = 1e-4,
              patience: int = 10, save_path: Optional[str] = None) -> Dict[str, List[float]]:
        """
        训练模型
        """
        optimizer = optim.Adam(self.model.parameters(), lr=lr, weight_decay=weight_decay)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=patience//2, factor=0.5)
        criterion = nn.CrossEntropyLoss()

        best_val_loss = float('inf')
        patience_counter = 0

        for epoch in range(epochs):
            # 训练阶段
            train_loss, train_acc = self._train_epoch(train_loader, optimizer, criterion)

            # 验证阶段
            val_loss, val_acc = 0, 0
            if val_loader is not None:
                val_loss, val_acc = self._validate_epoch(val_loader, criterion)

            # 记录历史
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_acc'].append(val_acc)

            # 学习率调度
            if val_loader is not None:
                scheduler.step(val_loss)
            else:
                scheduler.step(train_loss)

            # 早停
            if val_loader is not None and val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                if save_path:
                    self.save_model(save_path)
            else:
                patience_counter += 1

            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch+1}")
                break

            # 打印进度
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}")
                print(".4f")
                if val_loader is not None:
                    print(".4f")

        return self.history

    def _train_epoch(self, train_loader: DataLoader, optimizer: optim.Optimizer,
                     criterion: nn.Module) -> Tuple[float, float]:
        """训练一个epoch"""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        for batch in train_loader:
            inputs, targets = batch
            inputs, targets = inputs.to(self.device), targets.to(self.device)

            optimizer.zero_grad()
            outputs = self.model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()

        avg_loss = total_loss / len(train_loader)
        accuracy = correct / total
        return avg_loss, accuracy

    def _validate_epoch(self, val_loader: DataLoader, criterion: nn.Module) -> Tuple[float, float]:
        """验证一个epoch"""
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0

        with torch.no_grad():
            for batch in val_loader:
                inputs, targets = batch
                inputs, targets = inputs.to(self.device), targets.to(self.device)

                outputs = self.model(inputs)
                loss = criterion(outputs, targets)

                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += targets.size(0)
                correct += predicted.eq(targets).sum().item()

        avg_loss = total_loss / len(val_loader)
        accuracy = correct / total
        return avg_loss, accuracy

    def evaluate(self, test_loader: DataLoader) -> Dict[str, float]:
        """评估模型"""
        self.model.eval()
        all_preds = []
        all_targets = []
        all_probs = []

        with torch.no_grad():
            for batch in test_loader:
                inputs, targets = batch
                inputs, targets = inputs.to(self.device), targets.to(self.device)

                outputs = self.model(inputs)
                probs = torch.softmax(outputs, dim=1)
                _, preds = outputs.max(1)

                all_preds.extend(preds.cpu().numpy())
                all_targets.extend(targets.cpu().numpy())
                all_probs.extend(probs.cpu().numpy())

        # 计算指标
        accuracy = accuracy_score(all_targets, all_preds)
        precision = precision_score(all_targets, all_preds, average='weighted')
        recall = recall_score(all_targets, all_preds, average='weighted')
        f1 = f1_score(all_targets, all_preds, average='weighted')

        # AUC (多分类)
        try:
            auc = roc_auc_score(all_targets, all_probs, multi_class='ovr')
        except:
            auc = 0.0

        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc': auc
        }

    def save_model(self, path: str) -> None:
        """保存模型"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'history': self.history,
            'timestamp': datetime.now().isoformat()
        }, path)

    def load_model(self, path: str) -> None:
        """加载模型"""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.history = checkpoint.get('history', {})

class AnomalyTrainer:
    """
    异常检测模型训练器
    """

    def __init__(self, model, device: str = 'auto'):
        self.model = model
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if device == 'auto' else torch.device(device)
        if hasattr(model, 'to'):
            self.model.to(self.device)

    def train(self, X: torch.Tensor, epochs: int = 100, lr: float = 1e-3,
              batch_size: int = 32) -> List[float]:
        """训练异常检测模型"""
        X = X.to(self.device)

        losses = []
        for epoch in range(epochs):
            loss = self.model.fit(X.unsqueeze(0) if X.dim() == 1 else X)
            losses.append(loss)

            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss:.4f}")

        return losses

    def evaluate(self, X_normal: torch.Tensor, X_anomaly: torch.Tensor) -> Dict[str, float]:
        """评估异常检测性能"""
        self.model.eval()

        # 正常样本分数
        normal_scores = self.model.predict(X_normal.to(self.device)).cpu().numpy()

        # 异常样本分数
        anomaly_scores = self.model.predict(X_anomaly.to(self.device)).cpu().numpy()

        # 计算AUC
        y_true = np.concatenate([np.zeros(len(normal_scores)), np.ones(len(anomaly_scores))])
        y_scores = np.concatenate([normal_scores, anomaly_scores])

        auc = roc_auc_score(y_true, y_scores)

        # 找到最佳阈值
        from sklearn.metrics import precision_recall_curve
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)

        # 简单阈值选择 (F1最大化)
        f1_scores = 2 * precision * recall / (precision + recall)
        best_idx = np.argmax(f1_scores)
        best_threshold = thresholds[best_idx]

        return {
            'auc': auc,
            'best_threshold': best_threshold,
            'precision': precision[best_idx],
            'recall': recall[best_idx],
            'f1_score': f1_scores[best_idx]
        }

class DataPreprocessor:
    """
    数据预处理器
    """

    @staticmethod
    def create_dataloaders(X: np.ndarray, y: np.ndarray, batch_size: int = 32,
                          train_ratio: float = 0.7, val_ratio: float = 0.15) -> Tuple[DataLoader, ...]:
        """创建数据加载器"""
        # 分割数据
        X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=1-train_ratio, random_state=42)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=val_ratio/(1-train_ratio), random_state=42)

        # 转换为tensor
        train_dataset = TensorDataset(torch.tensor(X_train, dtype=torch.float32),
                                     torch.tensor(y_train, dtype=torch.long))
        val_dataset = TensorDataset(torch.tensor(X_val, dtype=torch.float32),
                                   torch.tensor(y_val, dtype=torch.long))
        test_dataset = TensorDataset(torch.tensor(X_test, dtype=torch.float32),
                                    torch.tensor(y_test, dtype=torch.long))

        # 创建加载器
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

        return train_loader, val_loader, test_loader

    @staticmethod
    def normalize_features(X: np.ndarray, method: str = 'standard') -> Tuple[np.ndarray, Dict]:
        """特征归一化"""
        if method == 'standard':
            mean = np.mean(X, axis=0)
            std = np.std(X, axis=0)
            std = np.where(std == 0, 1, std)  # 避免除零
            X_norm = (X - mean) / std
            params = {'mean': mean, 'std': std}
        elif method == 'minmax':
            min_val = np.min(X, axis=0)
            max_val = np.max(X, axis=0)
            range_val = max_val - min_val
            range_val = np.where(range_val == 0, 1, range_val)
            X_norm = (X - min_val) / range_val
            params = {'min': min_val, 'max': max_val}
        else:
            X_norm = X
            params = {}

        return X_norm, params

    @staticmethod
    def apply_normalization(X: np.ndarray, params: Dict, method: str = 'standard') -> np.ndarray:
        """应用归一化参数"""
        if method == 'standard':
            return (X - params['mean']) / params['std']
        elif method == 'minmax':
            return (X - params['min']) / (params['max'] - params['min'])
        return X

class ExperimentTracker:
    """
    实验跟踪器
    """

    def __init__(self, log_dir: str = 'logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def log_experiment(self, config: Dict[str, Any], results: Dict[str, Any],
                      model_name: str) -> str:
        """记录实验"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        exp_name = f"{model_name}_{timestamp}"

        exp_data = {
            'config': config,
            'results': results,
            'timestamp': timestamp,
            'model_name': model_name
        }

        filepath = os.path.join(self.log_dir, f"{exp_name}.json")
        with open(filepath, 'w') as f:
            json.dump(exp_data, f, indent=2, default=str)

        return filepath