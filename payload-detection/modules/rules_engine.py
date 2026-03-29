# rules_engine.py - 规则引擎模块

import re
import yaml
import os
from typing import Dict, List, Any, Optional
import ast

class RulesEngine:
    """
    规则引擎：基于签名和条件的威胁检测
    """

    def __init__(self, rules_path: str = "data/iocs"):
        self.rules_path = rules_path
        self.rules = self._load_all_rules()
        self.severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }

    def _load_all_rules(self) -> List[Dict]:
        """
        加载所有规则文件
        """
        rules = []
        if os.path.exists(self.rules_path):
            for file in os.listdir(self.rules_path):
                if file.endswith('.yaml'):
                    with open(os.path.join(self.rules_path, file), 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if 'rules' in data:
                            rules.extend(data['rules'])
        return rules

    def match(self, parsed_packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        对解析后的包应用所有规则，返回匹配结果
        """
        matches = []
        payload = self._extract_payload(parsed_packet)

        for rule in self.rules:
            if self._check_rule(rule, parsed_packet, payload):
                matches.append({
                    'rule_id': rule['id'],
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'category': rule['category'],
                    'description': rule['description'],
                    'confidence': self._calculate_confidence(rule, parsed_packet, payload)
                })

        # 按严重性排序
        matches.sort(key=lambda x: self.severity_levels.get(x['severity'], 0), reverse=True)
        return matches

    def _extract_payload(self, parsed_packet: Dict) -> str:
        """
        从解析结果中提取payload用于匹配
        """
        if 'payload' in parsed_packet:
            payload = parsed_packet['payload']
            if isinstance(payload, bytes):
                return payload.decode('utf-8', errors='ignore')
            elif isinstance(payload, str):
                return payload
        return ""

    def _check_rule(self, rule: Dict, parsed_packet: Dict, payload: str) -> bool:
        """
        检查单个规则是否匹配
        """
        # 正则匹配
        pattern = rule.get('pattern', '')
        if pattern and not re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
            return False

        # 条件检查
        condition = rule.get('condition', '')
        if condition and not self._evaluate_condition(condition, parsed_packet):
            return False

        return True

    def _evaluate_condition(self, condition: str, parsed_packet: Dict) -> bool:
        """
        评估条件表达式
        """
        try:
            # 安全评估：只允许特定操作
            allowed_names = {
                'len': len,
                'abs': abs,
                'float': float,
                'int': int,
                'str': str,
                'bool': bool,
                'True': True,
                'False': False,
                'None': None,
            }

            # 添加包字段到命名空间
            namespace = allowed_names.copy()
            namespace.update(parsed_packet)

            # 解析并评估
            tree = ast.parse(condition, mode='eval')
            result = eval(compile(tree, '<string>', 'eval'), {"__builtins__": {}}, namespace)
            return bool(result)
        except:
            return False

    def _calculate_confidence(self, rule: Dict, parsed_packet: Dict, payload: str) -> float:
        """
        计算匹配置信度
        """
        confidence = 0.5  # 基础置信度

        # 基于模式匹配质量
        if 'pattern' in rule and rule['pattern']:
            matches = re.findall(rule['pattern'], payload, re.IGNORECASE)
            if matches:
                confidence += 0.2 * min(len(matches), 5) / 5

        # 基于条件匹配
        if 'condition' in rule and rule['condition']:
            if self._evaluate_condition(rule['condition'], parsed_packet):
                confidence += 0.3

        # 基于协议相关性
        protocol = parsed_packet.get('protocol', '')
        if protocol in rule.get('description', '').lower():
            confidence += 0.1

        return min(confidence, 1.0)

    def add_rule(self, rule: Dict):
        """
        动态添加规则
        """
        self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        """
        移除规则
        """
        self.rules = [r for r in self.rules if r.get('id') != rule_id]

    def get_rules_by_category(self, category: str) -> List[Dict]:
        """
        按类别获取规则
        """
        return [r for r in self.rules if r.get('category') == category]

    def get_rules_by_severity(self, severity: str) -> List[Dict]:
        """
        按严重性获取规则
        """
        return [r for r in self.rules if r.get('severity') == severity]

    def update_rule(self, rule_id: str, updates: Dict):
        """
        更新规则
        """
        for rule in self.rules:
            if rule.get('id') == rule_id:
                rule.update(updates)
                break