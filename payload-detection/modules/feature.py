# feature.py - 特征提取模块

import numpy as np
from typing import Dict, Any, List, Union
from collections import Counter
import math
import re

class FeatureExtractor:
    """
    特征提取器：从解析后的包数据中提取ML特征
    """

    def __init__(self, max_payload_len: int = 1024, ngram_size: int = 2):
        self.max_payload_len = max_payload_len
        self.ngram_size = ngram_size
        # 约定特征维度（可动态扩展）
        self.feature_dim = 43

    def extract(self, parsed_packet: Dict[str, Any]) -> Dict[str, Union[float, int, List]]:
        """
        提取特征，返回特征字典
        """
        features = {}

        # 基础统计特征
        features.update(self._extract_statistical_features(parsed_packet))

        # 协议特定特征
        features.update(self._extract_protocol_features(parsed_packet))

        # 文本/字节级特征
        features.update(self._extract_text_features(parsed_packet))

        # 熵和分布特征
        features.update(self._extract_entropy_features(parsed_packet))

        return features

    def _extract_statistical_features(self, parsed_packet: Dict) -> Dict[str, float]:
        """
        提取统计特征
        """
        features = {}
        payload = self._get_payload_bytes(parsed_packet)

        # 长度特征
        features['payload_len'] = len(payload)
        features['payload_len_log'] = math.log(len(payload) + 1)

        # 字节统计
        if payload:
            payload_array = np.array(payload)
            features['byte_mean'] = np.mean(payload_array)
            features['byte_std'] = np.std(payload_array)
            features['byte_min'] = min(payload)
            features['byte_max'] = max(payload)
            features['byte_median'] = np.median(payload_array)

            # 字节分布
            byte_counts = Counter(payload)
            features['unique_bytes'] = len(byte_counts)
            features['byte_entropy'] = self._calculate_entropy(payload)

            # 特殊字节比例
            features['null_ratio'] = byte_counts.get(0, 0) / len(payload)
            features['printable_ratio'] = sum(1 for b in payload if 32 <= b <= 126) / len(payload)
            features['ascii_ratio'] = sum(1 for b in payload if b < 128) / len(payload)

        else:
            features.update({
                'byte_mean': 0, 'byte_std': 0, 'byte_min': 0, 'byte_max': 0,
                'byte_median': 0, 'unique_bytes': 0, 'byte_entropy': 0,
                'null_ratio': 0, 'printable_ratio': 0, 'ascii_ratio': 0
            })

        return features

    def _extract_protocol_features(self, parsed_packet: Dict) -> Dict[str, Union[float, int]]:
        """
        提取协议特定特征
        """
        features = {}
        protocol = parsed_packet.get('protocol', 'unknown')

        # TCP特征
        if protocol == 'tcp':
            features['tcp_sport'] = parsed_packet.get('src_port', 0)
            features['tcp_dport'] = parsed_packet.get('dst_port', 0)
            features['tcp_seq'] = parsed_packet.get('seq', 0)
            features['tcp_ack'] = parsed_packet.get('ack', 0)
            features['tcp_window'] = parsed_packet.get('window', 0)

            # TCP标志编码
            flags_str = parsed_packet.get('flags', '')
            flags = ['U', 'A', 'P', 'R', 'S', 'F']
            for flag in flags:
                features[f'tcp_flag_{flag.lower()}'] = 1 if flag in flags_str else 0

        # UDP特征
        elif protocol == 'udp':
            features['udp_sport'] = parsed_packet.get('src_port', 0)
            features['udp_dport'] = parsed_packet.get('dst_port', 0)

        # HTTP特征
        elif protocol == 'http':
            request_line = parsed_packet.get('request_line', '')
            headers = parsed_packet.get('headers', {})
            body = parsed_packet.get('body', '')

            # 请求方法编码
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
            for method in methods:
                features[f'http_method_{method.lower()}'] = 1 if request_line.startswith(method) else 0

            # 头数量
            features['http_header_count'] = len(headers)
            features['http_content_length'] = int(headers.get('Content-Length', 0))
            features['http_body_len'] = len(body)

            # 特殊头
            features['http_has_user_agent'] = 1 if 'User-Agent' in headers else 0
            features['http_has_referer'] = 1 if 'Referer' in headers else 0
            features['http_has_cookie'] = 1 if 'Cookie' in headers else 0

        # DNS特征
        elif protocol == 'dns':
            features['dns_id'] = parsed_packet.get('id', 0)
            features['dns_qr'] = parsed_packet.get('qr', 0)
            features['dns_opcode'] = parsed_packet.get('opcode', 0)
            features['dns_query_count'] = len(parsed_packet.get('queries', []))
            features['dns_answer_count'] = len(parsed_packet.get('answers', []))

        # TLS特征
        elif protocol == 'tls':
            features['tls_content_type'] = parsed_packet.get('content_type', 0)
            features['tls_version'] = parsed_packet.get('version', '0').replace('.', '') if isinstance(parsed_packet.get('version'), str) else 0
            features['tls_length'] = parsed_packet.get('length', 0)

        # MQTT特征
        elif protocol == 'mqtt':
            features['mqtt_msg_type'] = parsed_packet.get('msg_type', 0)
            features['mqtt_flags'] = parsed_packet.get('flags', 0)
            features['mqtt_remaining_len'] = parsed_packet.get('remaining_len', 0)

        # Modbus特征
        elif protocol == 'modbus':
            features['modbus_function'] = parsed_packet.get('function_code', 0)
            features['modbus_unit_id'] = parsed_packet.get('unit_id', 0)

        # CAN特征
        elif protocol == 'can':
            features['can_id'] = parsed_packet.get('id', 0)
            features['can_dlc'] = parsed_packet.get('dlc', 0)

        # 未知协议
        else:
            features['protocol_unknown'] = 1

        return features

    def _extract_text_features(self, parsed_packet: Dict) -> Dict[str, Union[float, List]]:
        """
        提取文本级特征
        """
        features = {}
        payload = self._get_payload_str(parsed_packet)

        if payload:
            # 文本统计
            features['text_len'] = len(payload)
            features['word_count'] = len(payload.split())
            features['uppercase_ratio'] = sum(1 for c in payload if c.isupper()) / len(payload)
            features['lowercase_ratio'] = sum(1 for c in payload if c.islower()) / len(payload)
            features['digit_ratio'] = sum(1 for c in payload if c.isdigit()) / len(payload)
            features['special_char_ratio'] = sum(1 for c in payload if not c.isalnum() and not c.isspace()) / len(payload)

            # n-gram特征（简化版）
            ngrams = self._extract_ngrams(payload, self.ngram_size)
            features['ngram_count'] = len(ngrams)
            features['unique_ngrams'] = len(set(ngrams))

            # 关键词检测
            keywords = ['select', 'union', 'script', 'exec', 'system', 'cmd', 'powershell', 'bash']
            for keyword in keywords:
                features[f'keyword_{keyword}'] = 1 if keyword.lower() in payload.lower() else 0

        else:
            features.update({
                'text_len': 0, 'word_count': 0, 'uppercase_ratio': 0,
                'lowercase_ratio': 0, 'digit_ratio': 0, 'special_char_ratio': 0,
                'ngram_count': 0, 'unique_ngrams': 0
            })
            keywords = ['select', 'union', 'script', 'exec', 'system', 'cmd', 'powershell', 'bash']
            for keyword in keywords:
                features[f'keyword_{keyword}'] = 0

        return features

    def _extract_entropy_features(self, parsed_packet: Dict) -> Dict[str, float]:
        """
        提取熵和分布特征
        """
        features = {}
        payload = self._get_payload_bytes(parsed_packet)

        if payload:
            # 字节熵
            features['byte_entropy'] = self._calculate_entropy(payload)

            # 字节频率分布
            byte_freq = np.array([payload.count(i) for i in range(256)]) / len(payload)
            features['byte_freq_std'] = np.std(byte_freq)
            features['byte_freq_skew'] = self._calculate_skewness(byte_freq)

            # 连续字节模式
            features['consecutive_zeros'] = self._count_consecutive(payload, 0)
            features['consecutive_ones'] = self._count_consecutive(payload, 255)

        else:
            features.update({
                'byte_entropy': 0, 'byte_freq_std': 0, 'byte_freq_skew': 0,
                'consecutive_zeros': 0, 'consecutive_ones': 0
            })

        return features

    def _get_payload_bytes(self, parsed_packet: Dict) -> List[int]:
        """
        获取payload字节数据
        """
        if 'payload' in parsed_packet:
            payload = parsed_packet['payload']
            if isinstance(payload, str):
                return list(payload.encode('utf-8', errors='ignore'))
            elif isinstance(payload, bytes):
                return list(payload)
            elif isinstance(payload, list):
                return payload
        return []

    def _get_payload_str(self, parsed_packet: Dict) -> str:
        """
        获取payload字符串数据
        """
        if 'payload' in parsed_packet:
            payload = parsed_packet['payload']
            if isinstance(payload, bytes):
                return payload.decode('utf-8', errors='ignore')
            elif isinstance(payload, str):
                return payload
        return ''

    def _calculate_entropy(self, data: List[int]) -> float:
        """
        计算字节熵
        """
        if not data:
            return 0.0
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _calculate_skewness(self, data: np.ndarray) -> float:
        """
        计算偏度
        """
        if len(data) == 0 or np.std(data) == 0:
            return 0.0
        return np.mean((data - np.mean(data))**3) / (np.std(data)**3)

    def _extract_ngrams(self, text: str, n: int) -> List[str]:
        """
        提取n-gram
        """
        return [text[i:i+n] for i in range(len(text) - n + 1)]

    def _count_consecutive(self, data: List[int], value: int) -> int:
        """
        统计连续相同字节的最大数量
        """
        max_count = 0
        current_count = 0
        for byte in data:
            if byte == value:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def get_feature_names(self) -> List[str]:
        """
        获取所有特征名称（用于模型训练）
        """
        # 使用示例数据获取特征名
        sample_packet = {'protocol': 'tcp', 'payload': b'test'}
        features = self.extract(sample_packet)
        return list(features.keys())