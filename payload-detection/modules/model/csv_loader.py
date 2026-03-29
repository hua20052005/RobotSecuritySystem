# csv_loader.py - CSV数据加载模块

import pandas as pd
import numpy as np
from typing import Tuple, Optional, List
import os
from sklearn.preprocessing import LabelEncoder
import logging

logger = logging.getLogger(__name__)


class CSVDataLoader:
    """
    CSV 数据加载器 - 支持常见的网络安全数据集
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.label_encoder = LabelEncoder()

    def load_csv(self, filepath: str, label_column: str = None, 
                 drop_columns: List[str] = None, 
                 sample_size: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        从CSV文件加载数据

        Args:
            filepath: CSV文件路径
            label_column: 标签列名（如果为None，假设最后一列是标签）
            drop_columns: 要删除的列列表（如ID, timestamp等）
            sample_size: 采样大小（None表示使用全部）

        Returns:
            X (特征矩阵), y (标签向量)
        """
        try:
            # 读取CSV
            df = pd.read_csv(filepath)
            
            if self.verbose:
                print(f"✅ 加载CSV文件: {filepath}")
                print(f"   数据形状: {df.shape[0]} 行 x {df.shape[1]} 列")

            # 采样（可选）
            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
                if self.verbose:
                    print(f"   采样: {len(df)} 行")

            # 删除指定列
            if drop_columns:
                df = df.drop(columns=[col for col in drop_columns if col in df.columns])
                if self.verbose:
                    print(f"   删除列: {drop_columns}")

            # 处理缺失值
            missing_percent = df.isnull().sum().sum() / (df.shape[0] * df.shape[1])
            if missing_percent > 0:
                if self.verbose:
                    print(f"   缺失值: {missing_percent:.2%}")
                df = df.fillna(df.mean(numeric_only=True))

            # 分离标签和特征
            if label_column and label_column in df.columns:
                X = df.drop(columns=[label_column])
                y = df[label_column]
            else:
                # 假设最后一列是标签
                X = df.iloc[:, :-1]
                y = df.iloc[:, -1]

            if self.verbose:
                print(f"   特征维度: {X.shape[1]}")
                print(f"   标签分布: {dict(pd.Series(y).value_counts())}")

            # 处理非数值标签
            if y.dtype == 'object':
                y = self.label_encoder.fit_transform(y)
                if self.verbose:
                    mapping = dict(zip(self.label_encoder.classes_, self.label_encoder.transform(self.label_encoder.classes_)))
                    print(f"   标签映射: {mapping}")

            # 处理非数值特征
            for col in X.select_dtypes(include=['object']).columns:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))

            # 转换为numpy
            X = X.values.astype(np.float32)
            y = y.astype(np.int64)

            if self.verbose:
                print(f"✅ 数据加载完成！X shape: {X.shape}, y shape: {y.shape}")

            return X, y

        except Exception as e:
            logger.error(f"❌ 加载CSV失败: {str(e)}")
            raise

    def load_cicids2017(self, filepath: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        加载 CICIDS2017 数据集 (特定处理)
        """
        df = pd.read_csv(filepath)
        
        # 处理无穷大值
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # 标签位于最后一列 'Label'
        X = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'])
        y = df['Label']
        
        # 二分类：Normal=0, Attack=1
        y = (y != 'BENIGN').astype(int)
        
        X = X.values.astype(np.float32)
        y = y.values.astype(np.int64)
        
        if self.verbose:
            print(f"✅ 加载 CICIDS2017: {X.shape}")
            print(f"   正常流量: {(y==0).sum()}, 攻击流量: {(y==1).sum()}")
        
        return X, y

    def load_nslkdd(self, filepath: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        加载 NSL-KDD 数据集
        """
        # NSL-KDD 列名
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        df = pd.read_csv(filepath, names=columns, header=None)
        
        # 二分类
        y = (df['label'] != 'normal').astype(int)
        X = df.drop(columns=['label', 'difficulty'])
        
        # 编码分类特征
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
        
        X = X.values.astype(np.float32)
        y = y.values.astype(np.int64)
        
        if self.verbose:
            print(f"✅ 加载 NSL-KDD: {X.shape}")
            print(f"   正常: {(y==0).sum()}, 攻击: {(y==1).sum()}")
        
        return X, y

    def load_unswnb15(self, filepath: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        加载 UNSW-NB15 数据集
        警告: attack_cat列与label直接对应，必须删除以避免数据泄露
        """
        df = pd.read_csv(filepath)
        
        # 标签处理
        y = df['label']
        # 注意：删除'attack_cat'是必需的，因为它与label完全对应，会导致数据泄露
        X = df.drop(columns=['label', 'id', 'attack_cat'])
        
        # 处理无穷大值
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
        
        # 编码分类特征
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
        
        X = X.values.astype(np.float32)
        y = y.values.astype(np.int64)
        
        if self.verbose:
            print(f"✅ 加载 UNSW-NB15: {X.shape}")
            print(f"   标签分布: {dict(pd.Series(y).value_counts())}")
        
        return X, y
