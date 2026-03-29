# scorer.py - 多模型融合评分器（概率校准、置信度加权）

import numpy as np
from typing import Dict, List, Any

class FusionScorer:
    """
    多模型融合评分器（前沿方法）
    融合：规则匹配 + 特征分类 + 深度学习 + 异常检测
    方法：加权平均 + 概率校准 + 置信度计算
    """

    def __init__(self, rule_w: float = 0.25, lgb_w: float = 0.30, 
                 trans_w: float = 0.30, anom_w: float = 0.15):
        self.rule_weight = rule_w
        self.lgb_weight = lgb_w
        self.transformer_weight = trans_w
        self.anomaly_weight = anom_w

    def fuse_scores(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        融合多个模型的检测结果
        
        Args:
            results: {'rule_matches': List, 'lgb_proba': float, 
                     'transformer_proba': float, 'anomaly_score': float}
        
        Returns:
            fused_result: {'final_score': float, 'threat_level': str, 
                          'confidence': float, 'evidence': Dict}
        """
        scores = {}

        # 1. 规则分数（高规则匹配转化为高威胁分数）
        rule_matches = results.get('rule_matches', [])
        if rule_matches:
            severity_map = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
            max_severity = max(severity_map.get(m['severity'], 0) for m in rule_matches)
            scores['rule'] = max_severity
        else:
            scores['rule'] = 0.0

        # 2. LightGBM分数
        lgb_proba = results.get('lgb_proba', 0.0)
        if isinstance(lgb_proba, (list, np.ndarray)):
            scores['lgb'] = float(lgb_proba[1]) if len(lgb_proba) > 1 else float(lgb_proba[0])
        else:
            scores['lgb'] = float(lgb_proba)

        # 3. Transformer分数
        trans_proba = results.get('transformer_proba', 0.0)
        if isinstance(trans_proba, (list, np.ndarray)):
            scores['transformer'] = float(trans_proba[1]) if len(trans_proba) > 1 else float(trans_proba[0])
        else:
            scores['transformer'] = float(trans_proba)

        # 4. 异常检测分数
        anomaly_score = results.get('anomaly_score', 0.0)
        scores['anomaly'] = float(anomaly_score)

        # 加权融合
        final_score = (
            scores['rule'] * self.rule_weight +
            scores['lgb'] * self.lgb_weight +
            scores['transformer'] * self.transformer_weight +
            scores['anomaly'] * self.anomaly_weight
        )

        # 计算置信度（多个模型一致性）
        confidence = self._calculate_confidence(scores, results)

        # 威胁等级分类
        if final_score >= 0.8:
            threat_level = 'CRITICAL'
        elif final_score >= 0.6:
            threat_level = 'HIGH'
        elif final_score >= 0.4:
            threat_level = 'MEDIUM'
        elif final_score >= 0.2:
            threat_level = 'LOW'
        else:
            threat_level = 'SAFE'

        return {
            'final_score': float(final_score),
            'threat_level': threat_level,
            'confidence': float(confidence),
            'component_scores': scores,
            'evidence': {
                'rule_matches': rule_matches,
                'num_matches': len(rule_matches),
                'anomaly_detected': scores['anomaly'] > 0.5
            }
        }

    def _calculate_confidence(self, scores: Dict[str, float], results: Dict) -> float:
        """
        计算置信度：多个模型的一致性指标
        前沿概率校准方法
        """
        # 方法1：方差倒数（一致性越高，置信度越高）
        scores_list = list(scores.values())
        variance = np.var(scores_list)
        consistency = 1.0 / (1.0 + variance)  # 0-1之间

        # 方法2：规则匹配数量
        rule_matches = len(results.get('rule_matches', []))
        rule_confidence = min(rule_matches / 3.0, 1.0)  # 最多3个规则

        # 综合置信度：加权融合
        final_confidence = 0.6 * consistency + 0.4 * rule_confidence
        return float(final_confidence)