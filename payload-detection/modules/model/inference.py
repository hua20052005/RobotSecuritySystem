# inference.py - 推理模块

import os
import time
import torch
import numpy as np
import yaml
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass
import logging
from enum import Enum

from ..parser import ProtocolParser as PacketParser
from ..rules_engine import RulesEngine
from ..feature import FeatureExtractor
from ..tokenizer import PacketTokenizer as PayloadTokenizer
from .packet_transformer import PacketTransformer

logger = logging.getLogger(__name__)

try:
    from .classifier import EnsembleClassifier
except ImportError:
    logger.warning("EnsembleClassifier 不可用，跳过导入")
    EnsembleClassifier = None

try:
    from .anomaly_detector import EnsembleAnomalyDetector as AnomalyDetector
except ImportError:
    try:
        from .anomaly_detector import DeepSVDD as AnomalyDetector
    except ImportError:
        logger.warning("AnomalyDetector 不可用，跳过导入")
        AnomalyDetector = None

from .trainer import DataPreprocessor


class DetectionResult(Enum):
    """检测结果枚举"""
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class DetectionOutput:
    """检测输出"""
    result: DetectionResult
    confidence: float
    rule_matches: List[str]
    ml_scores: Dict[str, float]
    features: Dict[str, Any]
    processing_time: float
    timestamp: str


class InferenceEngine:
    """
    推理引擎 - 整合所有检测组件
    """

    def __init__(self, config_path: str = 'config/inference_config.yaml'):
        """
        初始化推理引擎

        Args:
            config_path: 配置文件路径
        """
        self.config = self._load_config(config_path)

        # 初始化组件
        self.parser = PacketParser()
        self.rules_engine = RulesEngine()
        self.feature_extractor = FeatureExtractor()
        self.tokenizer = PayloadTokenizer()

        # 初始化ML模型
        self.ml_models = self._load_ml_models()

        # 数据预处理器
        self.preprocessor = DataPreprocessor()

        # 设备
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # 阈值配置
        self.thresholds = self.config.get('thresholds', {
            'rule_confidence': 0.8,
            'ml_confidence': 0.7,
            'combined_confidence': 0.75
        })

        logger.info("推理引擎初始化完成")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"配置文件 {config_path} 不存在，使用默认配置")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'models': {
                'transformer': {'enabled': True, 'weight': 0.4},
                'anomaly_detector': {'enabled': True, 'weight': 0.3},
                'ensemble_classifier': {'enabled': True, 'weight': 0.3}
            },
            'thresholds': {
                'rule_confidence': 0.8,
                'ml_confidence': 0.7,
                'combined_confidence': 0.75
            },
            'feature_normalization': 'standard',
            'max_sequence_length': 512
        }

    def _load_ml_models(self) -> Dict[str, Any]:
        """加载ML模型"""
        models = {}

        # 加载Transformer模型
        if self.config['models']['transformer']['enabled']:
            try:
                transformer = PacketTransformer(
                    vocab_size=self.tokenizer.vocab_size,
                    max_len=self.config['max_sequence_length']
                )
                # 加载预训练权重
                model_path = 'models/transformer_model.pth'
                if os.path.exists(model_path):
                    checkpoint = torch.load(model_path, map_location=self.device)
                    transformer.load_state_dict(checkpoint['model_state_dict'])
                transformer.to(self.device)
                transformer.eval()
                models['transformer'] = transformer
                logger.info("Transformer模型加载成功")
            except Exception as e:
                logger.error(f"Transformer模型加载失败: {e}")

        # 加载异常检测模型
        if self.config['models']['anomaly_detector']['enabled']:
            try:
                anomaly_detector = AnomalyDetector(
                    input_dim=self.feature_extractor.feature_dim,
                    hidden_dims=[128, 64, 32]
                )
                model_path = 'models/anomaly_detector.pth'
                if os.path.exists(model_path):
                    checkpoint = torch.load(model_path, map_location=self.device)
                    anomaly_detector.load_state_dict(checkpoint['model_state_dict'])
                anomaly_detector.to(self.device)
                anomaly_detector.eval()
                models['anomaly_detector'] = anomaly_detector
                logger.info("异常检测模型加载成功")
            except Exception as e:
                logger.error(f"异常检测模型加载失败: {e}")

        # 加载集成分类器
        if self.config['models']['ensemble_classifier']['enabled']:
            try:
                ensemble_classifier = EnsembleClassifier(
                    input_dim=self.feature_extractor.feature_dim,
                    n_classes=4  # normal, suspicious, malicious, unknown
                )
                model_path = 'models/ensemble_classifier.pkl'
                if os.path.exists(model_path):
                    ensemble_classifier.load_model(model_path)
                models['ensemble_classifier'] = ensemble_classifier
                logger.info("集成分类器加载成功")
            except Exception as e:
                logger.error(f"集成分类器加载失败: {e}")

        return models

    def detect_packet(self, packet_data: Union[str, bytes, Dict[str, Any]]) -> DetectionOutput:
        """
        检测单个数据包

        Args:
            packet_data: 数据包数据，可以是原始字节、十六进制字符串或解析后的字典

        Returns:
            DetectionOutput: 检测结果
        """
        start_time = time.time()

        try:
            # 1. 解析数据包
            parsed_packet = self._parse_packet(packet_data)

            # 2. 规则检测
            rule_results = self._apply_rules(parsed_packet)

            # 3. 特征提取
            features = self._extract_features(parsed_packet)

            # 4. ML检测
            ml_scores = self._apply_ml_models(features)

            # 5. 融合决策
            final_result, confidence = self._fuse_decisions(rule_results, ml_scores)

            processing_time = time.time() - start_time

            return DetectionOutput(
                result=final_result,
                confidence=confidence,
                rule_matches=rule_results.get('matches', []),
                ml_scores=ml_scores,
                features=features,
                processing_time=processing_time,
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

        except Exception as e:
            logger.error(f"检测过程中发生错误: {e}")
            return DetectionOutput(
                result=DetectionResult.UNKNOWN,
                confidence=0.0,
                rule_matches=[],
                ml_scores={},
                features={},
                processing_time=time.time() - start_time,
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

    def detect_batch(self, packets: List[Union[str, bytes, Dict[str, Any]]]) -> List[DetectionOutput]:
        """
        批量检测数据包

        Args:
            packets: 数据包列表

        Returns:
            List[DetectionOutput]: 检测结果列表
        """
        results = []
        for packet in packets:
            result = self.detect_packet(packet)
            results.append(result)

        return results

    def _parse_packet(self, packet_data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """解析数据包"""
        if isinstance(packet_data, dict):
            return packet_data  # 已经解析过了

        try:
            # 解析原始数据包
            parsed = self.parser.parse_packet(packet_data)
            return parsed
        except Exception as e:
            logger.warning(f"数据包解析失败: {e}")
            # 返回基本结构
            return {
                'payload': packet_data if isinstance(packet_data, (str, bytes)) else str(packet_data),
                'protocol': 'unknown',
                'src_ip': 'unknown',
                'dst_ip': 'unknown',
                'src_port': 0,
                'dst_port': 0
            }

    def _apply_rules(self, parsed_packet: Dict[str, Any]) -> Dict[str, Any]:
        """应用规则检测"""
        try:
            matches = self.rules_engine.match(parsed_packet)
            # 计算平均置信度
            confidence = 0.0
            if matches:
                confidence = float(sum([m.get('confidence', 0.0) for m in matches]) / len(matches))
            return {'matches': matches, 'confidence': confidence}
        except Exception as e:
            logger.error(f"规则检测失败: {e}")
            return {'matches': [], 'confidence': 0.0}

    def _extract_features(self, parsed_packet: Dict[str, Any]) -> Dict[str, Any]:
        """提取特征"""
        try:
            features = self.feature_extractor.extract(parsed_packet)
            return features
        except Exception as e:
            logger.error(f"特征提取失败: {e}")
            return {}

    def _apply_ml_models(self, features: Dict[str, Any]) -> Dict[str, float]:
        """应用ML模型"""
        scores = {}

        # 转换为numpy数组
        feature_vector = self._features_to_vector(features)
        if feature_vector is None:
            return scores

        # 归一化
        norm_params = self.config.get('normalization_params', {})
        if norm_params:
            feature_vector = self.preprocessor.apply_normalization(
                feature_vector.reshape(1, -1),
                norm_params,
                self.config.get('feature_normalization', 'standard')
            ).flatten()

        # Transformer模型
        if 'transformer' in self.ml_models:
            try:
                # 标记化payload
                payload = features.get('payload', '')
                tokens = self.tokenizer.tokenize_packet({'payload': payload})
                input_tensor = torch.tensor([tokens], dtype=torch.long).to(self.device)

                with torch.no_grad():
                    outputs = self.ml_models['transformer'](input_tensor)
                    probs = torch.softmax(outputs, dim=1)
                    scores['transformer'] = probs.max().item()
            except Exception as e:
                logger.error(f"Transformer模型推理失败: {e}")

        # 异常检测模型
        if 'anomaly_detector' in self.ml_models:
            try:
                input_tensor = torch.tensor(feature_vector, dtype=torch.float32).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    score = self.ml_models['anomaly_detector'](input_tensor)
                    scores['anomaly_detector'] = score.item()
            except Exception as e:
                logger.error(f"异常检测模型推理失败: {e}")

        # 集成分类器
        if 'ensemble_classifier' in self.ml_models:
            try:
                pred, prob = self.ml_models['ensemble_classifier'].predict(feature_vector.reshape(1, -1))
                scores['ensemble_classifier'] = prob.max()
            except Exception as e:
                logger.error(f"集成分类器推理失败: {e}")

        return scores

    def _features_to_vector(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """将特征字典转换为向量"""
        try:
            # 提取数值特征
            numeric_features = []
            for key, value in features.items():
                if isinstance(value, (int, float)):
                    numeric_features.append(float(value))
                elif isinstance(value, list) and value:
                    # 对于列表特征，取平均值
                    if all(isinstance(x, (int, float)) for x in value):
                        numeric_features.append(np.mean(value))

            if not numeric_features:
                return None

            return np.array(numeric_features)
        except Exception as e:
            logger.error(f"特征向量转换失败: {e}")
            return None

    def _fuse_decisions(self, rule_results: Dict[str, Any],
                       ml_scores: Dict[str, float]) -> Tuple[DetectionResult, float]:
        """融合规则和ML的检测结果"""
        # 规则置信度
        rule_confidence = rule_results.get('confidence', 0.0)
        rule_matches = rule_results.get('matches', [])

        # ML置信度加权平均
        ml_confidence = 0.0
        total_weight = 0.0

        for model_name, score in ml_scores.items():
            weight = self.config['models'][model_name]['weight']
            ml_confidence += score * weight
            total_weight += weight

        if total_weight > 0:
            ml_confidence /= total_weight

        # 融合决策
        combined_confidence = (rule_confidence + ml_confidence) / 2

        # 决策逻辑
        if rule_matches and rule_confidence >= self.thresholds['rule_confidence']:
            result = DetectionResult.MALICIOUS
        elif ml_confidence >= self.thresholds['ml_confidence']:
            result = DetectionResult.SUSPICIOUS
        elif combined_confidence >= self.thresholds['combined_confidence']:
            result = DetectionResult.SUSPICIOUS
        else:
            result = DetectionResult.NORMAL

        return result, combined_confidence

    def update_models(self, new_model_paths: Dict[str, str]) -> None:
        """更新模型"""
        for model_name, path in new_model_paths.items():
            if model_name in self.ml_models:
                try:
                    if model_name == 'transformer':
                        checkpoint = torch.load(path, map_location=self.device)
                        self.ml_models[model_name].load_state_dict(checkpoint['model_state_dict'])
                    elif model_name == 'anomaly_detector':
                        checkpoint = torch.load(path, map_location=self.device)
                        self.ml_models[model_name].load_state_dict(checkpoint['model_state_dict'])
                    elif model_name == 'ensemble_classifier':
                        self.ml_models[model_name].load_model(path)

                    logger.info(f"{model_name} 模型更新成功")
                except Exception as e:
                    logger.error(f"{model_name} 模型更新失败: {e}")

    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        info = {
            'device': str(self.device),
            'models_loaded': list(self.ml_models.keys()),
            'thresholds': self.thresholds,
            'config': self.config
        }
        return info


# 便捷函数
def create_inference_engine(config_path: str = None) -> InferenceEngine:
    """创建推理引擎"""
    return InferenceEngine(config_path)


def detect_packet(packet_data: Union[str, bytes, Dict[str, Any]],
                 config_path: str = None) -> DetectionOutput:
    """检测单个数据包的便捷函数"""
    engine = create_inference_engine(config_path)
    return engine.detect_packet(packet_data)


def detect_batch(packets: List[Union[str, bytes, Dict[str, Any]]],
                config_path: str = None) -> List[DetectionOutput]:
    """批量检测数据包的便捷函数"""
    engine = create_inference_engine(config_path)
    return engine.detect_batch(packets)
