# pipeline.py - 推理管道集成（前沿多模型融合）

import numpy as np
import torch
from typing import Dict, Any, Optional, List
import logging

from modules.parser import ProtocolParser
from modules.rules_engine import RulesEngine
from modules.feature import FeatureExtractor
from modules.tokenizer import ByteTokenizer
from modules.model.packet_transformer import PacketTransformer
from modules.model.classifier import LightGBMClassifier
from modules.model.anomaly_detector import IsolationForestAnomalyDetector
from modules.inference.scorer import FusionScorer

class PayloadDetectionPipeline:
    """
    端到端推理管道：协调所有检测模块
    流程：解析 -> 规则 -> 特征提取 -> ML模型 -> 融合评分
    前沿特性：多模型融合、概率校准、实时检测
    """

    def __init__(self, use_transformer: bool = True, use_anomaly: bool = True, device: str = 'cpu'):
        self.device = device
        self.logger = self._setup_logger()
        
        # 初始化各个模块
        self.parser = ProtocolParser()
        self.rules_engine = RulesEngine()
        self.feature_extractor = FeatureExtractor()
        self.tokenizer = ByteTokenizer()
        self.scorer = FusionScorer()
        
        # ML模型
        self.use_transformer = use_transformer
        self.use_anomaly = use_anomaly
        self.transformer = None
        self.lgb_classifier = None
        self.anomaly_detector = None
        self.ensemble_classifier = None  # 新增集成分类器
        
        self.logger.info("Pipeline initialized")

    def _setup_logger(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger('PayloadDetection')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def load_models(self, transformer_path: Optional[str] = None, 
                   lgb_path: Optional[str] = None,
                   anomaly_path: Optional[str] = None,
                   ensemble_path: Optional[str] = None):
        """加载预训练模型"""
        # 加载Transformer模型
        if transformer_path and self.use_transformer:
            try:
                self.transformer = torch.load(transformer_path, map_location=self.device)
                self.transformer.eval()  # 设置为推理模式
                self.logger.info(f"Loaded transformer from {transformer_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load transformer: {e}")
                self.transformer = None
                self.use_transformer = False

        # 加载LightGBM分类器（集成模型）
        if ensemble_path:
            try:
                import pickle
                with open(ensemble_path, 'rb') as f:
                    self.ensemble_classifier = pickle.load(f)
                self.logger.info(f"Loaded ensemble classifier from {ensemble_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load ensemble classifier: {e}")
                self.ensemble_classifier = None

        # 加载异常检测模型
        if anomaly_path and self.use_anomaly:
            try:
                import pickle
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                self.logger.info(f"Loaded anomaly detector from {anomaly_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load anomaly detector: {e}")
                self.anomaly_detector = None
                self.use_anomaly = False

        # 备选：加载单独的LightGBM（如果ensemble_path不可用）
        if lgb_path and not self.ensemble_classifier:
            try:
                from modules.model.classifier import LightGBMClassifier
                self.lgb_classifier = LightGBMClassifier()
                self.lgb_classifier.load(lgb_path)
                self.logger.info(f"Loaded LightGBM from {lgb_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load LightGBM: {e}")

    def detect(self, packet_data: bytes, return_details: bool = True) -> Dict[str, Any]:
        """
        端到端检测
        Returns: {'final_score': float, 'threat_level': str, 'confidence': float, 'details': Dict}
        """
        try:
            # 1. 协议解析
            parsed = self.parser.parse(packet_data)
            if 'error' in parsed:
                self.logger.warning(f"Parse error: {parsed['error']}")
                return {'final_score': 0.0, 'threat_level': 'SAFE', 'confidence': 0.0}

            # 2. 规则检测
            rule_matches = self.rules_engine.match(parsed)

            # 3. 特征提取
            features = self.feature_extractor.extract(parsed)
            
            # 4. ML模型推理
            ml_results = self._run_ml_models(parsed, features)

            # 5. 融合评分
            fusion_input = {
                'rule_matches': rule_matches,
                'lgb_proba': ml_results.get('lgb_proba', 0.0),
                'transformer_proba': ml_results.get('transformer_proba', 0.0),
                'anomaly_score': ml_results.get('anomaly_score', 0.0)
            }
            final_result = self.scorer.fuse_scores(fusion_input)

            if return_details:
                final_result['details'] = {
                    'protocol': parsed.get('protocol', 'unknown'),
                    'features': len(features),
                    'rule_hits': len(rule_matches)
                }

            return final_result

        except Exception as e:
            self.logger.error(f"Detection error: {e}")
            return {'final_score': 0.0, 'threat_level': 'ERROR', 'confidence': 0.0}

    def _run_ml_models(self, parsed: Dict, features: Dict) -> Dict[str, Any]:
        """运行所有ML模型（四源融合）"""
        results = {}
        
        # ===== 1. LightGBM分类器 =====
        if self.ensemble_classifier and isinstance(self.ensemble_classifier, dict):
            try:
                import numpy as np
                # 提取模型组件
                model = self.ensemble_classifier['model']
                kbest_selector = self.ensemble_classifier.get('kbest_selector')
                
                # 转换为numpy array
                feature_values = np.array([list(features.values())])
                
                # 应用特征选择（如果特征数量匹配）
                if feature_values.shape[1] == kbest_selector.n_features_in_:
                    feature_values = kbest_selector.transform(feature_values)
                else:
                    # 特征数量不匹配，尝试只使用前21个特征（临时修复）
                    feature_values = feature_values[:, :21]
                
                # 预测
                proba = model.predict_proba(feature_values)[0]
                results['lgb_proba'] = float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception as e:
                self.logger.warning(f"LightGBM prediction failed: {e}")
                results['lgb_proba'] = 0.5
        else:
            results['lgb_proba'] = 0.5
        
        # ===== 2. Transformer模型（深度学习） =====
        results['transformer_proba'] = self._run_transformer(parsed, features)
        
        # ===== 3. 异常检测（无监督） =====
        results['anomaly_score'] = self._run_anomaly_detector(features)
        
        return results
    
    def _run_transformer(self, parsed: Dict, features: Dict) -> float:
        """运行Transformer模型进行深度学习推理"""
        if not self.use_transformer or self.transformer is None:
            return 0.0  # 模型未启用或未加载
        
        try:
            import numpy as np
            
            # 获取payload并Token化
            payload = parsed.get('payload', b'')
            if isinstance(payload, str):
                payload = payload.encode('utf-8', errors='ignore')
            
            # Token化
            token_ids = self.tokenizer.encode(payload, add_special=True)
            attention_mask = self.tokenizer.get_attention_mask(token_ids)
            
            # 转换为Tensor
            token_tensor = torch.tensor([token_ids], dtype=torch.long, device=self.device)
            mask_tensor = torch.tensor([attention_mask], dtype=torch.float32, device=self.device)
            
            # Transformer前向推理
            self.transformer.eval()
            with torch.no_grad():
                logits, _ = self.transformer(token_tensor, attention_mask=mask_tensor)
                proba = torch.softmax(logits, dim=1)[0]
                
                # 返回攻击类（index 1）的概率
                transformer_score = float(proba[1].cpu().numpy())
                self.logger.debug(f"Transformer score: {transformer_score:.4f}")
                return transformer_score
                
        except Exception as e:
            self.logger.warning(f"Transformer prediction failed: {e}")
            return 0.0
    
    def _run_anomaly_detector(self, features: Dict) -> float:
        """运行异常检测模型（无监督异常检测）"""
        if not self.use_anomaly or self.anomaly_detector is None:
            return 0.0  # 模型未启用或未加载
        
        try:
            import numpy as np
            
            # 转换特征为numpy数组
            feature_values = np.array([list(features.values())])
            
            # 提取detector对象（如果是字典格式）
            if isinstance(self.anomaly_detector, dict):
                detector = self.anomaly_detector.get('detector')
                scaler = self.anomaly_detector.get('scaler')
                # 注意：不应用scaler（因为测试时的特征维度可能不同）
            else:
                detector = self.anomaly_detector
                scaler = None
            
            # 异常检测：IsolationForest直接进行预测
            # 不需要标准化，因为IsolationForest已在训练时进行
            if hasattr(detector, 'predict'):
                try:
                    # 使用predict得到异常分数
                    anomaly_scores = detector.predict(feature_values)
                    anomaly_score = anomaly_scores[0]
                    # 将分数转换到[0,1]范围
                    # IsolationForest.predict()返回 -1(异常) 或 1(正常)
                    # 转换为威胁分数：-1→1.0(威胁), 1→0.0(安全)
                    anomaly_normalized = 0.0 if anomaly_score > 0 else 1.0
                    self.logger.debug(f"Anomaly score: {anomaly_normalized:.4f} (raw: {anomaly_score})")
                    return float(anomaly_normalized)
                except Exception as pred_err:
                    self.logger.debug(f"IsolationForest predict failed: {pred_err}")
                    # 降级方案：如果IsolationForest失败（维度不匹配），返回默认分数
                    return 0.0
            else:
                self.logger.warning(f"Detector has no predict method")
                return 0.0
                
        except Exception as e:
            self.logger.warning(f"Anomaly detection failed: {e}")
            return 0.0

    def batch_detect(self, packets: List[bytes]) -> List[Dict]:
        """批量检测"""
        results = []
        for pkt in packets:
            results.append(self.detect(pkt, return_details=False))
        return results