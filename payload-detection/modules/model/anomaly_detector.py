# anomaly_detector.py - 异常检测模型（前沿算法实现）

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple, List, Dict, Any
import math
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.metrics import roc_auc_score
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EllipticEnvelope
from scipy.spatial.distance import mahalanobis
from scipy.stats import entropy
import warnings
warnings.filterwarnings('ignore')

class BaseAnomalyDetector(nn.Module):
    """
    异常检测基类
    """

    def __init__(self):
        super().__init__()

    def fit(self, X: torch.Tensor) -> None:
        """训练异常检测器"""
        raise NotImplementedError

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """预测异常分数"""
        raise NotImplementedError

class DeepSVDD(BaseAnomalyDetector):
    """
    Deep Support Vector Data Description
    基于深度学习的单类分类
    """

    def __init__(self, input_dim: int = 512, hidden_dims: List[int] = [256, 128],
                 latent_dim: int = 64, dropout: float = 0.1):
        super().__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # 编码器
        layers = []
        dims = [input_dim] + hidden_dims + [latent_dim]
        for i in range(len(dims) - 1):
            layers.extend([
                nn.Linear(dims[i], dims[i+1]),
                nn.BatchNorm1d(dims[i+1]),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])

        self.encoder = nn.Sequential(*layers[:-3])  # 去掉最后一个dropout

        # 中心点参数
        self.center = nn.Parameter(torch.randn(latent_dim))

        # 初始化中心点
        self.register_buffer('nu', torch.tensor(0.1))  # 异常比例

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播，返回重构或latent表示
        """
        z = self.encoder(x)
        return z

    def fit(self, X: torch.Tensor, epochs: int = 100, lr: float = 1e-3) -> None:
        """
        训练DeepSVDD
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        self.train()

        for epoch in range(epochs):
            optimizer.zero_grad()

            z = self.forward(X)
            # SVDD损失：最小化到中心的距离
            dist = torch.sum((z - self.center) ** 2, dim=1)
            loss = torch.mean(dist) + self.nu * torch.mean(torch.relu(torch.sum((z - self.center) ** 2, dim=1) - 1))

            loss.backward()
            optimizer.step()

            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        预测异常分数（到中心的距离）
        """
        self.eval()
        with torch.no_grad():
            z = self.forward(X)
            scores = torch.sum((z - self.center) ** 2, dim=1)
        return scores


class IsolationForestAnomalyDetector(BaseAnomalyDetector):
    """
    基于 sklearn IsolationForest 的异常检测器
    """
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1, random_state: int = 42):
        super().__init__()
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)

    def fit(self, X):
        if isinstance(X, torch.Tensor):
            X = X.detach().cpu().numpy()
        self.model.fit(X)

    def predict(self, X):
        if isinstance(X, torch.Tensor):
            X = X.detach().cpu().numpy()
        # score_samples 越高越正常，取负值为异常分数
        scores = -self.model.score_samples(X)
        return scores


class TransformerAutoencoder(BaseAnomalyDetector):
    """
    基于Transformer的自动编码器异常检测
    """

    def __init__(self, vocab_size: int = 1000, d_model: int = 256, nhead: int = 4,
                 num_layers: int = 3, max_len: int = 512, dropout: float = 0.1):
        super().__init__()

        self.vocab_size = vocab_size
        self.d_model = d_model
        self.max_len = max_len

        # 嵌入层
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_encoding = nn.Parameter(torch.randn(max_len, d_model))

        # Transformer编码器
        encoder_layer = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward=d_model*4, dropout=dropout)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers)

        # Transformer解码器
        decoder_layer = nn.TransformerDecoderLayer(d_model, nhead, dim_feedforward=d_model*4, dropout=dropout)
        self.decoder = nn.TransformerDecoder(decoder_layer, num_layers)

        # 输出层
        self.output_proj = nn.Linear(d_model, vocab_size)

    def encode(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        编码器
        """
        # 嵌入和位置编码
        src = self.embedding(src) + self.pos_encoding[:src.size(1)]
        src = src.transpose(0, 1)  # [seq_len, batch_size, d_model]

        # 编码
        memory = self.encoder(src, src_mask)
        return memory

    def decode(self, memory: torch.Tensor, tgt: torch.Tensor,
               tgt_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        解码器
        """
        # 嵌入和位置编码
        tgt = self.embedding(tgt) + self.pos_encoding[:tgt.size(1)]
        tgt = tgt.transpose(0, 1)  # [seq_len, batch_size, d_model]

        # 解码
        output = self.decoder(tgt, memory, tgt_mask=tgt_mask)
        output = output.transpose(0, 1)  # [batch_size, seq_len, d_model]

        # 输出投影
        logits = self.output_proj(output)
        return logits

    def forward(self, src: torch.Tensor, tgt: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        前向传播
        """
        memory = self.encode(src)

        if tgt is None:
            # 自回归解码用于推理
            batch_size, seq_len = src.size()
            tgt = torch.zeros(batch_size, seq_len, dtype=torch.long, device=src.device)
            tgt[:, 0] = 1  # BOS token

            for i in range(1, seq_len):
                logits = self.decode(memory, tgt[:, :i])
                next_token = logits[:, -1].argmax(dim=-1)
                tgt[:, i] = next_token

            return tgt
        else:
            return self.decode(memory, tgt)

    def fit(self, X: torch.Tensor, epochs: int = 50, lr: float = 1e-3) -> None:
        """
        训练自动编码器
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss(ignore_index=0)  # 忽略padding

        self.train()
        for epoch in range(epochs):
            optimizer.zero_grad()

            # 自监督学习：输入和目标相同
            logits = self.forward(X, X)
            logits = logits.view(-1, self.vocab_size)
            targets = X.view(-1)

            loss = criterion(logits, targets)
            loss.backward()
            optimizer.step()

            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        预测异常分数（重构误差）
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(X, X)
            # 计算重构误差
            probs = F.softmax(logits, dim=-1)
            targets_onehot = F.one_hot(X, num_classes=self.vocab_size).float()

            # 交叉熵作为异常分数
            reconstruction_error = -torch.sum(targets_onehot * torch.log(probs + 1e-10), dim=-1)
            scores = reconstruction_error.mean(dim=-1)  # 平均到序列级别

        return scores

class FlowBasedAnomalyDetector(BaseAnomalyDetector):
    """
    基于流的异常检测 (简化版Normalizing Flow)
    """

    def __init__(self, input_dim: int = 512, hidden_dim: int = 256, num_flows: int = 4):
        super().__init__()

        self.input_dim = input_dim
        self.num_flows = num_flows

        # 简单的仿射耦合层
        self.flows = nn.ModuleList([
            nn.Sequential(
                nn.Linear(input_dim // 2, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, input_dim),
            ) for _ in range(num_flows)
        ])

        # 基分布 (标准正态)
        self.base_dist = torch.distributions.Normal(0, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Flow前向传播，返回变换后的z和log det jacobian
        """
        log_det = torch.zeros(x.size(0), device=x.device)

        for flow in self.flows:
            # 简单的耦合变换
            x1, x2 = x.chunk(2, dim=-1)
            params = flow(x1)
            shift, scale = params.chunk(2, dim=-1)
            scale = F.softplus(scale) + 1e-3

            x2 = x2 * scale + shift
            x = torch.cat([x1, x2], dim=-1)

            log_det += torch.sum(torch.log(scale), dim=-1)

        return x, log_det

    def inverse(self, z: torch.Tensor) -> torch.Tensor:
        """
        逆变换
        """
        x = z
        for flow in reversed(self.flows):
            x1, x2 = x.chunk(2, dim=-1)
            params = flow(x1)
            shift, scale = params.chunk(2, dim=-1)
            scale = F.softplus(scale) + 1e-3

            x2 = (x2 - shift) / scale
            x = torch.cat([x1, x2], dim=-1)

        return x

    def log_prob(self, x: torch.Tensor) -> torch.Tensor:
        """
        计算对数概率
        """
        z, log_det = self.forward(x)
        log_prob = self.base_dist.log_prob(z).sum(dim=-1) + log_det
        return log_prob

    def fit(self, X: torch.Tensor, epochs: int = 100, lr: float = 1e-3) -> None:
        """
        训练Flow模型
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)

        self.train()
        for epoch in range(epochs):
            optimizer.zero_grad()

            log_prob = self.log_prob(X)
            loss = -log_prob.mean()

            loss.backward()
            optimizer.step()

            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        预测异常分数（负对数概率）
        """
        self.eval()
        with torch.no_grad():
            log_prob = self.log_prob(X)
            scores = -log_prob  # 负对数概率作为异常分数

        return scores

class DeepOneClassSVM(BaseAnomalyDetector):
    """
    深度One-Class SVM - 结合深度特征提取和传统OC-SVM
    """

    def __init__(self, input_dim: int = 512, hidden_dims: List[int] = [256, 128],
                 latent_dim: int = 64, svm_kernel: str = 'rbf', svm_nu: float = 0.1):
        super().__init__()

        # 特征提取器
        layers = []
        dims = [input_dim] + hidden_dims + [latent_dim]
        for i in range(len(dims) - 1):
            layers.extend([
                nn.Linear(dims[i], dims[i+1]),
                nn.BatchNorm1d(dims[i+1]),
                nn.ReLU(),
                nn.Dropout(0.1)
            ])

        self.feature_extractor = nn.Sequential(*layers[:-2])  # 去掉dropout

        # One-Class SVM
        self.svm = OneClassSVM(kernel=svm_kernel, nu=svm_nu)

        self.fitted = False

    def extract_features(self, X: torch.Tensor) -> np.ndarray:
        """
        提取深度特征
        """
        self.eval()
        with torch.no_grad():
            features = self.feature_extractor(X)
        return features.cpu().numpy()

    def fit(self, X: torch.Tensor) -> None:
        """
        训练特征提取器和SVM
        """
        # 首先训练特征提取器 (自编码器方式)
        optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        criterion = nn.MSELoss()

        # 简单的自监督训练
        for epoch in range(50):
            optimizer.zero_grad()
            features = self.feature_extractor(X)
            # 重建损失 (简化)
            loss = criterion(features, torch.randn_like(features))
            loss.backward()
            optimizer.step()

        # 提取特征并训练SVM
        features = self.extract_features(X)
        self.svm.fit(features)
        self.fitted = True

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        预测异常分数
        """
        if not self.fitted:
            raise ValueError("Model not fitted")

        features = self.extract_features(X)
        scores = -self.svm.decision_function(features)  # 负决策函数作为异常分数
        return torch.tensor(scores, dtype=torch.float32)

class EnsembleAnomalyDetector(BaseAnomalyDetector):
    """
    高级集成异常检测器 - 结合多种前沿方法
    使用自适应权重学习
    """

    def __init__(self, input_dim: int = 512, 
                 methods: List[str] = ['deep_svdd', 'vae', 'lstm', 'contrastive', 
                                       'energy', 'hybrid', 'statistical']):
        super().__init__()

        self.methods = methods
        self.detectors = {}

        for method in methods:
            try:
                if method == 'deep_svdd':
                    self.detectors[method] = DeepSVDD(input_dim=input_dim)
                elif method == 'autoencoder':
                    self.detectors[method] = TransformerAutoencoder(vocab_size=input_dim)
                elif method == 'flow':
                    self.detectors[method] = FlowBasedAnomalyDetector(input_dim=input_dim)
                elif method == 'oc_svm':
                    self.detectors[method] = DeepOneClassSVM(input_dim=input_dim)
                elif method == 'vae':
                    self.detectors[method] = VariationalAutoencoder(input_dim=input_dim)
                elif method == 'lstm':
                    self.detectors[method] = LSTMAutoencoder(input_dim=input_dim)
                elif method == 'contrastive':
                    self.detectors[method] = ContrastiveAnomalyDetector(input_dim=input_dim)
                elif method == 'energy':
                    self.detectors[method] = EnergyBasedAnomalyDetector(input_dim=input_dim)
                elif method == 'hybrid':
                    self.detectors[method] = HybridAnomalyDetector(input_dim=input_dim)
                elif method == 'statistical':
                    self.detectors[method] = StatisticalAnomalyDetector(input_dim=input_dim)
            except Exception as e:
                print(f"Warning: Failed to initialize {method}: {e}")

        # 自适应权重学习
        self.weights = nn.Parameter(torch.ones(len(self.detectors)))
        self.weight_optimizer = None

    def fit(self, X: torch.Tensor, weight_learning: bool = True) -> None:
        """
        训练所有检测器
        
        Args:
            X: 训练数据
            weight_learning: 是否学习集成权重
        """
        for detector in self.detectors.values():
            try:
                detector.fit(X)
            except Exception as e:
                print(f"Warning: Detector fit failed: {e}")

        # 学习权重（如果启用）
        if weight_learning and len(self.detectors) > 1:
            self._learn_weights(X)

    def _learn_weights(self, X: torch.Tensor, epochs: int = 20, lr: float = 0.1) -> None:
        """
        通过最小化异常检测器之间的差异来学习权重
        """
        self.weight_optimizer = torch.optim.Adam([self.weights], lr=lr)

        for epoch in range(epochs):
            self.weight_optimizer.zero_grad()

            scores_list = []
            for detector in self.detectors.values():
                try:
                    with torch.no_grad():
                        scores = detector.predict(X)
                    scores_list.append(scores)
                except Exception as e:
                    print(f"Weight learning - detector predict failed: {e}")

            if len(scores_list) < 2:
                break

            # 最小化权重之间的方差（鼓励多样性）
            weights = F.softmax(self.weights, dim=0)
            combined_scores = torch.stack(scores_list, dim=0)

            # 方差正则化
            variance = torch.var(combined_scores, dim=0).mean()
            loss = -variance  # 最大化方差

            loss.backward()
            self.weight_optimizer.step()

            if (epoch + 1) % 5 == 0:
                print(f"Weight Learning Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")

    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        集成预测 - 加权组合多个异常检测器
        """
        scores_list = []
        valid_detectors = 0

        for name, detector in self.detectors.items():
            try:
                scores = detector.predict(X)
                
                # 标准化分数到[0,1]范围
                if scores.min() < scores.max():
                    scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
                
                scores_list.append(scores)
                valid_detectors += 1
            except Exception as e:
                print(f"Warning: Detector {name} predict failed: {e}")

        if valid_detectors == 0:
            raise ValueError("No detectors available for prediction")

        # 加权组合
        if valid_detectors == 1:
            return scores_list[0]

        weights = F.softmax(self.weights[:valid_detectors], dim=0)
        combined_scores = torch.stack(scores_list, dim=0)
        final_scores = torch.sum(combined_scores * weights.unsqueeze(-1), dim=0)

        return final_scores

    def get_detector_scores(self, X: torch.Tensor) -> Dict[str, torch.Tensor]:
        """
        获取每个检测器的异常分数
        """
        scores_dict = {}

        for name, detector in self.detectors.items():
            try:
                scores = detector.predict(X)
                scores_dict[name] = scores
            except Exception as e:
                print(f"Warning: Detector {name} predict failed: {e}")

        return scores_dict


# ==================== 前沿异常检测方法 ====================

class VariationalAutoencoder(BaseAnomalyDetector):
    """
    变分自动编码器 (VAE) - 生成式异常检测
    采用变分推断进行概率建模
    """

    def __init__(self, input_dim: int = 512, hidden_dims: List[int] = [256, 128],
                 latent_dim: int = 32, dropout: float = 0.1):
        super().__init__()
        
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        
        # 编码器
        encoder_layers = []
        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            encoder_layers.extend([
                nn.Linear(dims[i], dims[i+1]),
                nn.BatchNorm1d(dims[i+1]),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
        
        self.encoder = nn.Sequential(*encoder_layers)
        
        # 隐空间
        self.fc_mu = nn.Linear(hidden_dims[-1], latent_dim)
        self.fc_logvar = nn.Linear(hidden_dims[-1], latent_dim)
        
        # 解码器
        decoder_layers = []
        decoder_dims = [latent_dim] + hidden_dims[::-1] + [input_dim]
        for i in range(len(decoder_dims) - 1):
            if i < len(decoder_dims) - 2:
                decoder_layers.extend([
                    nn.Linear(decoder_dims[i], decoder_dims[i+1]),
                    nn.BatchNorm1d(decoder_dims[i+1]),
                    nn.ReLU(),
                    nn.Dropout(dropout)
                ])
            else:
                decoder_layers.append(nn.Linear(decoder_dims[i], decoder_dims[i+1]))
        
        self.decoder = nn.Sequential(*decoder_layers)
    
    def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        编码为隐变量
        """
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar
    
    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """
        重参数化技巧
        """
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std
        return z
    
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """
        从隐变量解码
        """
        return self.decoder(z)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        前向传播
        """
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        recon_x = self.decode(z)
        return recon_x, mu, logvar
    
    def fit(self, X: torch.Tensor, epochs: int = 100, lr: float = 1e-3, beta: float = 1.0) -> None:
        """
        训练VAE
        beta: KL散度权重
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        self.train()
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            
            recon_x, mu, logvar = self.forward(X)
            
            # 重构损失
            reconstruction_loss = F.mse_loss(recon_x, X, reduction='mean')
            
            # KL散度
            kl_loss = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
            
            loss = reconstruction_loss + beta * kl_loss
            
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}, "
                      f"Recon: {reconstruction_loss.item():.4f}, KL: {kl_loss.item():.4f}")
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        异常分数 = 重构误差 + 隐空间异常性
        """
        self.eval()
        with torch.no_grad():
            recon_x, mu, logvar = self.forward(X)
            
            # 重构误差
            reconstruction_error = torch.mean((X - recon_x) ** 2, dim=1)
            
            # 隐空间异常性（KL散度）
            kl_divergence = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)
            
            # 综合异常分数
            scores = reconstruction_error + 0.1 * kl_divergence
        
        return scores


class LSTMAutoencoder(BaseAnomalyDetector):
    """
    LSTM自动编码器 - 时间序列异常检测
    """

    def __init__(self, input_dim: int = 512, hidden_dim: int = 128,
                 num_layers: int = 2, dropout: float = 0.1):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        
        # 编码器
        self.encoder_lstm = nn.LSTM(input_dim, hidden_dim, num_layers,
                                    batch_first=True, dropout=dropout)
        
        # 解码器
        self.decoder_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers,
                                    batch_first=True, dropout=dropout)
        
        self.output_layer = nn.Linear(hidden_dim, input_dim)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播 (假设x形状为 [batch_size, seq_len, input_dim])
        """
        # 如果x是2D张量，添加序列维度
        if x.dim() == 2:
            x = x.unsqueeze(1)
        
        # 编码
        _, (h, c) = self.encoder_lstm(x)
        
        # 解码
        batch_size = x.size(0)
        decoder_input = torch.zeros(batch_size, x.size(1), self.hidden_dim, device=x.device)
        decoder_output, _ = self.decoder_lstm(decoder_input, (h, c))
        
        # 输出
        recon_x = self.output_layer(decoder_output)
        
        return recon_x
    
    def fit(self, X: torch.Tensor, epochs: int = 50, lr: float = 1e-3) -> None:
        """
        训练LSTM自动编码器
        """
        if X.dim() == 2:
            X = X.unsqueeze(1)
        
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        criterion = nn.MSELoss()
        
        self.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            
            recon_x = self.forward(X)
            loss = criterion(recon_x, X)
            
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        异常分数 = 时间序列重构误差
        """
        if X.dim() == 2:
            X = X.unsqueeze(1)
        
        self.eval()
        with torch.no_grad():
            recon_x = self.forward(X)
            
            # 计算各个时间步的误差，然后求和或平均
            reconstruction_error = torch.mean((X - recon_x) ** 2, dim=(1, 2))
        
        return reconstruction_error


class ContrastiveAnomalyDetector(BaseAnomalyDetector):
    """
    对比学习异常检测 - 基于样本相似性的异常检测
    使用NT-Xent损失函数
    """

    def __init__(self, input_dim: int = 512, hidden_dims: List[int] = [256, 128],
                 latent_dim: int = 64, temperature: float = 0.07):
        super().__init__()
        
        # 特征提取器
        layers = []
        dims = [input_dim] + hidden_dims + [latent_dim]
        for i in range(len(dims) - 1):
            if i < len(dims) - 2:
                layers.extend([
                    nn.Linear(dims[i], dims[i+1]),
                    nn.BatchNorm1d(dims[i+1]),
                    nn.ReLU()
                ])
            else:
                layers.append(nn.Linear(dims[i], dims[i+1]))
        
        self.feature_extractor = nn.Sequential(*layers)
        self.temperature = temperature
        self.mean = None
        self.std = None
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        提取特征表示
        """
        return self.feature_extractor(x)
    
    def fit(self, X: torch.Tensor, epochs: int = 50, lr: float = 1e-3,
            corruption_factor: float = 0.1) -> None:
        """
        训练对比学习检测器
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        self.train()
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            
            # 原始样本
            z1 = self.forward(X)
            
            # 腐蚀样本（通过添加噪声模拟）
            noise = torch.randn_like(X) * corruption_factor
            z2 = self.forward(X + noise)
            
            # NT-Xent损失
            z1 = F.normalize(z1, dim=1)
            z2 = F.normalize(z2, dim=1)
            
            # 计算相似度矩阵
            sim_matrix = torch.mm(z1, z2.t()) / self.temperature
            
            # 正样本对应角线元素
            pos_mask = torch.eye(z1.size(0), device=z1.device).bool()
            neg_mask = ~pos_mask
            
            # 损失计算
            pos_sim = sim_matrix[pos_mask]
            neg_sim = sim_matrix[neg_mask].view(z1.size(0), -1)
            
            loss = -torch.log(torch.exp(pos_sim).sum(dim=1) / 
                            (torch.exp(pos_sim).sum(dim=1) + 
                             torch.exp(neg_sim).sum(dim=1)))
            loss = loss.mean()
            
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Contrastive Loss: {loss.item():.4f}")
        
        # 计算正常数据的统计量
        with torch.no_grad():
            features = self.forward(X)
            self.mean = features.mean(dim=0)
            self.std = features.std(dim=0)
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        异常分数 = 到中心的Mahalanobis距离
        """
        self.eval()
        with torch.no_grad():
            features = self.forward(X)
            
            # 标准化距离
            normalized = (features - self.mean) / (self.std + 1e-8)
            scores = torch.norm(normalized, dim=1)
        
        return scores


class EnergyBasedAnomalyDetector(BaseAnomalyDetector):
    """
    基于能量的异常检测 - 使用神经网络能量函数
    """

    def __init__(self, input_dim: int = 512, hidden_dims: List[int] = [256, 128]):
        super().__init__()
        
        # 能量函数网络
        layers = []
        dims = [input_dim] + hidden_dims + [1]
        for i in range(len(dims) - 1):
            if i < len(dims) - 2:
                layers.extend([
                    nn.Linear(dims[i], dims[i+1]),
                    nn.BatchNorm1d(dims[i+1]),
                    nn.ReLU(),
                    nn.Dropout(0.1)
                ])
            else:
                layers.append(nn.Linear(dims[i], dims[i+1]))
        
        self.energy_net = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        计算能量分数（负值表示正常，正值表示异常）
        """
        return self.energy_net(x).squeeze(-1)
    
    def fit(self, X: torch.Tensor, epochs: int = 100, lr: float = 1e-3,
            margin: float = 10.0) -> None:
        """
        训练能量模型
        margin: 正常样本能量和异常样本能量之间的边界
        """
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)
        self.train()
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            
            # 正常样本
            energy_normal = self.forward(X)
            
            # 异常样本（通过随机扰动生成）
            noise = torch.randn_like(X)
            energy_abnormal = self.forward(noise)
            
            # 损失函数：使正常样本能量低，异常样本能量高
            loss = torch.mean(F.relu(margin - energy_abnormal)) + \
                   torch.mean(F.relu(energy_normal - margin))
            
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Energy Loss: {loss.item():.4f}")
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        异常分数 = 能量分数（高能量 = 异常）
        """
        self.eval()
        with torch.no_grad():
            scores = self.forward(X)
        
        # 将负分数变为正分数（高分数 = 异常）
        scores = -scores
        scores = torch.relu(scores)
        
        return scores


class HybridAnomalyDetector(BaseAnomalyDetector):
    """
    混合异常检测 - 结合深度学习和传统机器学习
    """

    def __init__(self, input_dim: int = 512):
        super().__init__()
        
        # 深度特征提取器
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Linear(128, 64)
        )
        
        # 传统机器学习模型
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.lof = LocalOutlierFactor(novelty=True)
        self.oc_svm = OneClassSVM(kernel='rbf', nu=0.1)
        
        self.fitted = False
    
    def forward(self, X: torch.Tensor) -> torch.Tensor:
        """
        提取深度特征
        """
        return self.feature_extractor(X)
    
    def fit(self, X: torch.Tensor) -> None:
        """
        训练混合检测器
        """
        # 提取深度特征
        self.eval()
        with torch.no_grad():
            features = self.forward(X).cpu().numpy()
        
        # 训练传统机器学习模型
        self.isolation_forest.fit(features)
        self.lof.fit(features)
        self.oc_svm.fit(features)
        
        self.fitted = True
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        混合异常分数
        """
        if not self.fitted:
            raise ValueError("Model not fitted")
        
        self.eval()
        with torch.no_grad():
            features = self.forward(X).cpu().numpy()
        
        # 获取各个方法的异常分数
        if_scores = -self.isolation_forest.score_samples(features)
        lof_scores = -self.lof.score_samples(features)
        oc_svm_scores = -self.oc_svm.decision_function(features)
        
        # 标准化分数
        if_scores = (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min() + 1e-8)
        lof_scores = (lof_scores - lof_scores.min()) / (lof_scores.max() - lof_scores.min() + 1e-8)
        oc_svm_scores = (oc_svm_scores - oc_svm_scores.min()) / (oc_svm_scores.max() - oc_svm_scores.min() + 1e-8)
        
        # 加权组合
        combined_scores = 0.3 * if_scores + 0.3 * lof_scores + 0.4 * oc_svm_scores
        
        return torch.tensor(combined_scores, dtype=torch.float32)


class StatisticalAnomalyDetector(BaseAnomalyDetector):
    """
    统计异常检测 - 基于多元高斯和Mahalanobis距离
    """

    def __init__(self, input_dim: int = 512):
        super().__init__()
        
        self.input_dim = input_dim
        self.mean = None
        self.cov_matrix = None
        self.cov_inv = None
        self.fitted = False
    
    def fit(self, X: torch.Tensor) -> None:
        """
        拟合多元高斯分布
        """
        # 转换为numpy
        X_np = X.cpu().numpy() if isinstance(X, torch.Tensor) else X
        
        # 计算均值和协方差
        self.mean = np.mean(X_np, axis=0)
        self.cov_matrix = np.cov(X_np.T)
        
        # 添加正则化项以确保可逆
        self.cov_matrix += np.eye(self.input_dim) * 1e-6
        
        try:
            self.cov_inv = np.linalg.inv(self.cov_matrix)
            self.fitted = True
        except np.linalg.LinAlgError:
            # 如果矩阵不可逆，使用伪逆
            self.cov_inv = np.linalg.pinv(self.cov_matrix)
            self.fitted = True
    
    def predict(self, X: torch.Tensor) -> torch.Tensor:
        """
        异常分数 = Mahalanobis距离
        """
        if not self.fitted:
            raise ValueError("Model not fitted")
        
        X_np = X.cpu().numpy() if isinstance(X, torch.Tensor) else X
        
        scores = []
        for x in X_np:
            diff = x - self.mean
            score = np.sqrt(np.dot(diff, np.dot(self.cov_inv, diff.T)))
            scores.append(score)
        
        return torch.tensor(np.array(scores), dtype=torch.float32)