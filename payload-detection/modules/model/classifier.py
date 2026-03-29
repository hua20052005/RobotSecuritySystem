# classifier.py - 轻量级特征分类模型（LightGBM）

import lightgbm as lgb
import numpy as np
import pickle
from typing import Dict, Optional, Tuple

class LightGBMClassifier:
    """
    LightGBM分类器：基于手工特征的快速分类
    优点：训练快、可解释、支持特征重要性、低延迟推理
    """

    def __init__(self, num_classes: int = 2, max_depth: int = 5, num_leaves: int = 31):
        self.num_classes = num_classes
        self.model = None
        self.feature_names = None
        self.params = {
            'objective': 'binary' if num_classes == 2 else 'multiclass',
            'num_class': num_classes if num_classes > 2 else 1,
            'max_depth': max_depth,
            'num_leaves': num_leaves,
            'learning_rate': 0.05,
            'n_estimators': 100,
            'verbose': -1
        }

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[list] = None, 
              valid_X: Optional[np.ndarray] = None, valid_y: Optional[np.ndarray] = None):
        """训练模型"""
        self.feature_names = feature_names or [f'f_{i}' for i in range(X.shape[1])]
        
        train_data = lgb.Dataset(X, label=y, feature_name=self.feature_names)
        eval_set = None
        if valid_X is not None and valid_y is not None:
            eval_set = [lgb.Dataset(valid_X, label=valid_y, reference=train_data)]
        
        self.model = lgb.train(
            self.params, train_data, num_boost_round=100,
            valid_sets=eval_set,
            callbacks=[lgb.early_stopping(10)] if eval_set else None
        )

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """预测"""
        if self.model is None:
            raise ValueError("Model not trained")
        
        proba = self.model.predict(X, num_iteration=self.model.best_iteration)
        
        if self.num_classes == 2:
            proba = np.column_stack([1 - proba, proba])
        else:
            proba = proba.reshape(-1, self.num_classes)
        
        predictions = np.argmax(proba, axis=1)
        return predictions, proba

    def get_feature_importance(self) -> Dict[str, float]:
        """获取特征重要性"""
        if self.model is None:
            raise ValueError("Model not trained")
        importance = self.model.feature_importance()
        return dict(zip(self.feature_names, importance))

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import lightgbm as lgb
import xgboost as xgb
from sklearn.metrics import accuracy_score, f1_score

class BaseClassifier:
    """
    分类器基类
    """

    def __init__(self):
        pass

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练分类器"""
        raise NotImplementedError

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签"""
        raise NotImplementedError

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        raise NotImplementedError

class LightGBMClassifier(BaseClassifier):
    """
    LightGBM分类器
    """

    def __init__(self, params: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.params = params or {
            'objective': 'multiclass',
            'num_class': 2,
            'metric': 'multi_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'verbose': -1
        }
        self.model = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练LightGBM"""
        train_data = lgb.Dataset(X, label=y)
        self.model = lgb.train(self.params, train_data)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签"""
        if self.model is None:
            raise ValueError("Model not trained")
        return self.model.predict(X).argmax(axis=1).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        if self.model is None:
            raise ValueError("Model not trained")
        return self.model.predict(X)

class XGBoostClassifier(BaseClassifier):
    """
    XGBoost分类器
    """

    def __init__(self, params: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.params = params or {
            'objective': 'multi:softprob',
            'num_class': 2,
            'eval_metric': 'mlogloss',
            'max_depth': 6,
            'learning_rate': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'verbosity': 0
        }
        self.model = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练XGBoost"""
        dtrain = xgb.DMatrix(X, label=y)
        self.model = xgb.train(self.params, dtrain)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签"""
        if self.model is None:
            raise ValueError("Model not trained")
        dtest = xgb.DMatrix(X)
        return self.model.predict(dtest).argmax(axis=1).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        if self.model is None:
            raise ValueError("Model not trained")
        dtest = xgb.DMatrix(X)
        return self.model.predict(dtest)

class RandomForestClassifierWrapper(BaseClassifier):
    """
    随机森林分类器
    """

    def __init__(self, n_estimators: int = 100, max_depth: Optional[int] = None):
        super().__init__()
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练随机森林"""
        self.model.fit(X, y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签"""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        return self.model.predict_proba(X)

class SVMClassifier(BaseClassifier):
    """
    支持向量机分类器
    """

    def __init__(self, kernel: str = 'rbf', C: float = 1.0):
        super().__init__()
        self.model = SVC(kernel=kernel, C=C, probability=True, random_state=42)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练SVM"""
        self.model.fit(X, y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签"""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        return self.model.predict_proba(X)

class MLPClassifier(nn.Module):
    """
    多层感知机分类器 (PyTorch)
    """

    def __init__(self, input_dim: int, hidden_dims: List[int] = [256, 128],
                 num_classes: int = 2, dropout: float = 0.1):
        super().__init__()

        self.input_dim = input_dim
        self.num_classes = num_classes

        # 构建网络层
        layers = []
        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            layers.extend([
                nn.Linear(dims[i], dims[i+1]),
                nn.BatchNorm1d(dims[i+1]),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])

        # 输出层
        layers.append(nn.Linear(hidden_dims[-1], num_classes))

        self.network = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """前向传播"""
        return self.network(x)

    def fit(self, X: torch.Tensor, y: torch.Tensor, epochs: int = 100,
            lr: float = 1e-3, batch_size: int = 32) -> None:
        """训练MLP"""
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss()

        dataset = torch.utils.data.TensorDataset(X, y)
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_X, batch_y in dataloader:
                optimizer.zero_grad()
                outputs = self.forward(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(dataloader):.4f}")

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """预测标签"""
        self.eval()
        with torch.no_grad():
            outputs = self.forward(X)
            _, predicted = torch.max(outputs, 1)
        return predicted

    def predict_proba(self, X: torch.Tensor) -> torch.Tensor:
        """预测概率"""
        self.eval()
        with torch.no_grad():
            outputs = self.forward(X)
            probs = F.softmax(outputs, dim=1)
        return probs

class EnsembleClassifier:
    """
    集成分类器 - 结合多种模型
    """

    def __init__(self, input_dim: int, num_classes: int = 2,
                 models: List[str] = ['lgb', 'xgb', 'rf', 'mlp']):
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.models = {}

        for model_name in models:
            if model_name == 'lgb':
                self.models[model_name] = LightGBMClassifier()
            elif model_name == 'xgb':
                self.models[model_name] = XGBoostClassifier()
            elif model_name == 'rf':
                self.models[model_name] = RandomForestClassifierWrapper()
            elif model_name == 'svm':
                self.models[model_name] = SVMClassifier()
            elif model_name == 'mlp':
                self.models[model_name] = MLPClassifier(input_dim, num_classes=num_classes)

        # 集成权重
        self.weights = np.ones(len(models)) / len(models)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """训练所有模型"""
        X_torch = torch.tensor(X, dtype=torch.float32)
        y_torch = torch.tensor(y, dtype=torch.long)

        for name, model in self.models.items():
            print(f"Training {name}...")
            if isinstance(model, MLPClassifier):
                model.fit(X_torch, y_torch)
            else:
                model.fit(X, y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """集成预测"""
        predictions = []
        X_torch = torch.tensor(X, dtype=torch.float32)

        for name, model in self.models.items():
            if isinstance(model, MLPClassifier):
                pred = model.predict(X_torch).numpy()
            else:
                pred = model.predict(X)
            predictions.append(pred)

        # 加权投票
        pred_matrix = np.array(predictions)
        weighted_pred = np.average(pred_matrix, axis=0, weights=self.weights)
        return np.round(weighted_pred).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """集成概率预测"""
        probabilities = []
        X_torch = torch.tensor(X, dtype=torch.float32)

        for name, model in self.models.items():
            if isinstance(model, MLPClassifier):
                prob = model.predict_proba(X_torch).numpy()
            else:
                prob = model.predict_proba(X)
            probabilities.append(prob)

        # 加权平均
        prob_matrix = np.array(probabilities)
        weighted_prob = np.average(prob_matrix, axis=0, weights=self.weights)
        return weighted_prob

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """评估模型性能"""
        y_pred = self.predict(X)
        accuracy = accuracy_score(y, y_pred)
        f1 = f1_score(y, y_pred, average='weighted')

        return {
            'accuracy': accuracy,
            'f1_score': f1
        }