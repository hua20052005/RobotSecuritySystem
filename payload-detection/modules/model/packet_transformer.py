# packet_transformer.py - 轻量Transformer分类模型

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Tuple, Optional

class PacketTransformer(nn.Module):
    """
    轻量级Transformer模型：用于网络包分类
    输入：Token序列 (B, L)
    输出：分类logits (B, num_classes)
    """

    def __init__(self, vocab_size: int = 262, d_model: int = 256, nhead: int = 4,
                 num_layers: int = 3, max_len: int = 512, num_classes: int = 2,
                 dropout: float = 0.1):
        super().__init__()
        self.d_model = d_model
        
        # Embedding层
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_encoding = nn.Parameter(torch.randn(max_len, d_model))
        
        # Transformer Encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=4*d_model,
            dropout=dropout, batch_first=True, activation='relu'
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # 分类head
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(d_model, d_model // 2)
        self.fc2 = nn.Linear(d_model // 2, num_classes)

    def forward(self, token_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """前向传播"""
        seq_len = token_ids.size(1)
        
        # Embedding + Position Encoding
        x = self.embedding(token_ids) * np.sqrt(self.d_model)
        x = x + self.pos_encoding[:seq_len, :].unsqueeze(0)
        
        # Transformer
        x = self.transformer(x)
        
        # 全局平均池化
        if attention_mask is not None:
            x = (x * attention_mask.unsqueeze(-1)).sum(dim=1) / attention_mask.sum(dim=1, keepdim=True).clamp(min=1e-9)
        else:
            x = x.mean(dim=1)
        
        # 分类head
        x = self.dropout(x)
        x = F.relu(self.fc1(x))
        logits = self.fc2(x)
        
        return logits, x

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple, List
import math

class PositionalEncoding(nn.Module):
    """
    位置编码模块
    """

    def __init__(self, d_model: int, max_len: int = 5000):
        super().__init__()
        self.d_model = d_model
        self.max_len = max_len

        # 创建位置编码矩阵
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)

        pe = pe.unsqueeze(0).transpose(0, 1)
        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        添加位置编码
        Args:
            x: [seq_len, batch_size, d_model]
        """
        return x + self.pe[:x.size(0), :]

class MultiHeadAttention(nn.Module):
    """
    多头注意力机制
    """

    def __init__(self, d_model: int, nhead: int, dropout: float = 0.1):
        super().__init__()
        self.d_model = d_model
        self.nhead = nhead
        self.head_dim = d_model // nhead

        assert self.head_dim * nhead == d_model, "d_model must be divisible by nhead"

        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)

        self.dropout = nn.Dropout(dropout)

    def forward(self, query: torch.Tensor, key: torch.Tensor, value: torch.Tensor,
                mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        多头注意力前向传播
        """
        batch_size = query.size(0)

        # 线性变换并分头
        Q = self.q_proj(query).view(batch_size, -1, self.nhead, self.head_dim).transpose(1, 2)
        K = self.k_proj(key).view(batch_size, -1, self.nhead, self.head_dim).transpose(1, 2)
        V = self.v_proj(value).view(batch_size, -1, self.nhead, self.head_dim).transpose(1, 2)

        # 计算注意力权重
        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.head_dim)

        if mask is not None:
            scores = scores.masked_fill(mask == 0, float('-inf'))

        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.dropout(attn_weights)

        # 应用注意力权重
        attn_output = torch.matmul(attn_weights, V)

        # 合并头
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, -1, self.d_model)

        # 输出投影
        output = self.out_proj(attn_output)

        return output, attn_weights

class TransformerEncoderLayer(nn.Module):
    """
    Transformer编码器层
    """

    def __init__(self, d_model: int, nhead: int, dim_feedforward: int = 2048,
                 dropout: float = 0.1, activation: str = "relu"):
        super().__init__()
        self.self_attn = MultiHeadAttention(d_model, nhead, dropout)

        # 前馈网络
        self.linear1 = nn.Linear(d_model, dim_feedforward)
        self.dropout = nn.Dropout(dropout)
        self.linear2 = nn.Linear(dim_feedforward, d_model)

        # 层归一化
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)

        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)

        self.activation = F.relu if activation == "relu" else F.gelu

    def forward(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        编码器层前向传播
        """
        # 自注意力
        src2, _ = self.self_attn(src, src, src, src_mask)
        src = src + self.dropout1(src2)
        src = self.norm1(src)

        # 前馈网络
        src2 = self.linear2(self.dropout(self.activation(self.linear1(src))))
        src = src + self.dropout2(src2)
        src = self.norm2(src)

        return src

class TransformerEncoder(nn.Module):
    """
    Transformer编码器
    """

    def __init__(self, encoder_layer: nn.Module, num_layers: int):
        super().__init__()
        self.layers = nn.ModuleList([encoder_layer for _ in range(num_layers)])
        self.num_layers = num_layers

    def forward(self, src: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        编码器前向传播
        """
        output = src
        for layer in self.layers:
            output = layer(output, mask)
        return output

class PacketTransformer(nn.Module):
    """
    Packet Transformer - 基于Transformer的包内容分类模型
    """

    def __init__(self, vocab_size: int = 1000, d_model: int = 512, nhead: int = 8,
                 num_layers: int = 6, dim_feedforward: int = 2048, max_len: int = 1024,
                 num_classes: int = 2, dropout: float = 0.1):
        super().__init__()

        self.vocab_size = vocab_size
        self.d_model = d_model
        self.max_len = max_len
        self.num_classes = num_classes

        # 嵌入层
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_encoder = PositionalEncoding(d_model, max_len)

        # Transformer编码器
        encoder_layer = TransformerEncoderLayer(d_model, nhead, dim_feedforward, dropout)
        self.transformer_encoder = TransformerEncoder(encoder_layer, num_layers)

        # 分类头
        self.classifier = nn.Sequential(
            nn.Linear(d_model, dim_feedforward // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim_feedforward // 2, num_classes)
        )

        # 初始化参数
        self._init_parameters()

    def _init_parameters(self):
        """参数初始化"""
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)

    def forward(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        前向传播
        Args:
            src: [batch_size, seq_len]
            src_mask: [batch_size, seq_len]
        Returns:
            logits: [batch_size, num_classes]
        """
        # 嵌入
        src = self.embedding(src)  # [batch_size, seq_len, d_model]
        src = src.transpose(0, 1)  # [seq_len, batch_size, d_model]

        # 位置编码
        src = self.pos_encoder(src)

        # Transformer编码
        output = self.transformer_encoder(src, src_mask)  # [seq_len, batch_size, d_model]

        # 池化 (使用CLS token或平均池化)
        if hasattr(self, 'cls_token') and self.cls_token is not None:
            # 如果有CLS token
            cls_output = output[0]  # [batch_size, d_model]
        else:
            # 平均池化
            cls_output = output.mean(dim=0)  # [batch_size, d_model]

        # 分类
        logits = self.classifier(cls_output)  # [batch_size, num_classes]

        return logits

    def get_attention_weights(self, src: torch.Tensor) -> List[torch.Tensor]:
        """
        获取注意力权重 (用于可解释性)
        """
        # 实现注意力权重提取
        attention_weights = []

        src_embed = self.embedding(src).transpose(0, 1)
        src_embed = self.pos_encoder(src_embed)

        for layer in self.transformer_encoder.layers:
            _, attn_weights = layer.self_attn(src_embed, src_embed, src_embed)
            attention_weights.append(attn_weights)
            # 更新输入
            src_embed = layer(src_embed)

        return attention_weights

class PacketTransformerWithCLS(PacketTransformer):
    """
    带CLS token的Packet Transformer
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cls_token = nn.Parameter(torch.randn(1, 1, self.d_model))

    def forward(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        带CLS token的前向传播
        """
        batch_size = src.size(0)

        # 嵌入
        src = self.embedding(src)  # [batch_size, seq_len, d_model]

        # 添加CLS token
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)  # [batch_size, 1, d_model]
        src = torch.cat([cls_tokens, src], dim=1)  # [batch_size, seq_len+1, d_model]

        src = src.transpose(0, 1)  # [seq_len+1, batch_size, d_model]

        # 位置编码
        src = self.pos_encoder(src)

        # Transformer编码
        output = self.transformer_encoder(src, src_mask)  # [seq_len+1, batch_size, d_model]

        # 取CLS token输出
        cls_output = output[0]  # [batch_size, d_model]

        # 分类
        logits = self.classifier(cls_output)

        return logits

class LightweightPacketTransformer(PacketTransformer):
    """
    轻量级Packet Transformer - 适用于边缘设备
    """

    def __init__(self, vocab_size: int = 512, d_model: int = 256, nhead: int = 4,
                 num_layers: int = 3, dim_feedforward: int = 512, max_len: int = 512,
                 num_classes: int = 2, dropout: float = 0.1):
        super().__init__(vocab_size, d_model, nhead, num_layers, dim_feedforward,
                        max_len, num_classes, dropout)

class PacketTransformerWithConv(PacketTransformer):
    """
    带卷积的Packet Transformer - 结合CNN特征提取
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # 卷积特征提取
        self.conv1 = nn.Conv1d(self.d_model, self.d_model, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(self.d_model, self.d_model, kernel_size=5, padding=2)

        # 融合层
        self.fusion = nn.Linear(self.d_model * 3, self.d_model)

    def forward(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        带卷积的前向传播
        """
        # 嵌入
        src_embed = self.embedding(src).transpose(0, 1)  # [seq_len, batch_size, d_model]

        # 位置编码
        src_embed = self.pos_encoder(src_embed)

        # 卷积特征
        src_conv = src_embed.transpose(0, 1).transpose(1, 2)  # [batch_size, d_model, seq_len]

        conv1_out = F.relu(self.conv1(src_conv))  # [batch_size, d_model, seq_len]
        conv2_out = F.relu(self.conv2(src_conv))  # [batch_size, d_model, seq_len]

        # 最大池化
        conv1_pooled = F.adaptive_max_pool1d(conv1_out, 1).squeeze(-1)  # [batch_size, d_model]
        conv2_pooled = F.adaptive_max_pool1d(conv2_out, 1).squeeze(-1)  # [batch_size, d_model]

        # Transformer编码
        transformer_out = self.transformer_encoder(src_embed, src_mask)  # [seq_len, batch_size, d_model]
        transformer_pooled = transformer_out.mean(dim=0)  # [batch_size, d_model]

        # 特征融合
        combined = torch.cat([transformer_pooled, conv1_pooled, conv2_pooled], dim=-1)  # [batch_size, d_model*3]
        fused = self.fusion(combined)  # [batch_size, d_model]

        # 分类
        logits = self.classifier(fused)

        return logits