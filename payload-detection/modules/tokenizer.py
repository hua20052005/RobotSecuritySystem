# tokenizer.py - Token化模块 (字节级Token化+位置编码)

import numpy as np
from typing import Union

class ByteTokenizer:
    """
    字节级Token化器：将原始payload转换为Token序列
    支持：固定长度序列、填充、特殊token、位置编码
    """

    def __init__(self, max_len: int = 512, vocab_size: int = 256):
        self.max_len = max_len
        self.vocab_size = vocab_size
        self.PAD_ID = 0
        self.UNK_ID = 1
        self.START_ID = 2
        self.END_ID = 3
        self.CLS_ID = 4
        self.SEP_ID = 5

    def encode(self, payload: Union[bytes, str], add_special=True) -> np.ndarray:
        """编码payload为token序列"""
        if isinstance(payload, str):
            payload = payload.encode('utf-8', errors='ignore')
        
        tokens = []
        if add_special:
            tokens.append(self.CLS_ID)
        
        for byte in payload[:self.max_len - (2 if add_special else 0)]:
            token_id = byte + 6  # 偏移特殊token
            tokens.append(min(token_id, self.vocab_size - 1))
        
        if add_special:
            tokens.append(self.SEP_ID)
        
        while len(tokens) < self.max_len:
            tokens.append(self.PAD_ID)
        
        return np.array(tokens[:self.max_len], dtype=np.int32)

    def get_attention_mask(self, tokens: np.ndarray) -> np.ndarray:
        """生成注意力掩码"""
        return (tokens != self.PAD_ID).astype(np.float32)

    def get_position_ids(self) -> np.ndarray:
        """生成位置ID（用于位置编码）"""
        return np.arange(self.max_len, dtype=np.int32)

import re
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter, defaultdict
import json
import os
import math

class BaseTokenizer:
    """
    基础tokenizer基类
    """

    def __init__(self, vocab_size: int = 256, max_len: int = 1024):
        self.vocab_size = vocab_size
        self.max_len = max_len
        self.pad_token = 0
        self.unk_token = 1
        self.bos_token = 2
        self.eos_token = 3

    def tokenize(self, text: str) -> List[int]:
        """将文本转换为token ids"""
        raise NotImplementedError

    def detokenize(self, tokens: List[int]) -> str:
        """将token ids转换为文本"""
        raise NotImplementedError

    def encode(self, text: str, add_special_tokens: bool = True) -> List[int]:
        """编码文本为token序列"""
        tokens = self.tokenize(text)
        if add_special_tokens:
            tokens = [self.bos_token] + tokens + [self.eos_token]
        return tokens[:self.max_len]

    def decode(self, tokens: List[int], skip_special_tokens: bool = True) -> str:
        """解码token序列为文本"""
        if skip_special_tokens:
            tokens = [t for t in tokens if t not in [self.pad_token, self.bos_token, self.eos_token]]
        return self.detokenize(tokens)

class ByteTokenizer(BaseTokenizer):
    """
    字节级tokenizer - 每个字节作为token
    """

    def __init__(self, vocab_size: int = 256, max_len: int = 1024):
        super().__init__(vocab_size, max_len)
        # 字节0-255作为基础vocab
        self.byte_to_id = {i: i + 4 for i in range(256)}  # 4为特殊token偏移
        self.id_to_byte = {v: k for k, v in self.byte_to_id.items()}

    def tokenize(self, text: str) -> List[int]:
        """将文本按字节tokenize"""
        if isinstance(text, str):
            bytes_data = text.encode('utf-8', errors='ignore')
        elif isinstance(text, bytes):
            bytes_data = text
        else:
            bytes_data = str(text).encode('utf-8', errors='ignore')

        tokens = []
        for byte in bytes_data:
            tokens.append(self.byte_to_id.get(byte, self.unk_token))

        return tokens[:self.max_len]

    def detokenize(self, tokens: List[int]) -> str:
        """将token转换为字节然后解码"""
        bytes_data = []
        for token in tokens:
            if token in self.id_to_byte:
                bytes_data.append(self.id_to_byte[token])
            else:
                bytes_data.append(0)  # 未知token用0填充

        return bytes(bytes_data).decode('utf-8', errors='ignore')

class BPEByteTokenizer(BaseTokenizer):
    """
    字节级BPE tokenizer - 使用字节对编码
    """

    def __init__(self, vocab_size: int = 512, max_len: int = 1024, merges_file: Optional[str] = None):
        super().__init__(vocab_size, max_len)
        self.merges = {}
        self.vocab = {i: bytes([i]) for i in range(256)}

        if merges_file and os.path.exists(merges_file):
            self.load_merges(merges_file)
        else:
            self._build_basic_vocab()

    def _build_basic_vocab(self):
        """构建基础字节vocab"""
        for i in range(256):
            self.vocab[i + 4] = bytes([i])

    def train(self, texts: List[str], num_merges: int = 256):
        """训练BPE合并规则"""
        # 预处理文本为字节序列
        byte_sequences = []
        for text in texts:
            if isinstance(text, str):
                bytes_data = text.encode('utf-8', errors='ignore')
            else:
                bytes_data = text
            byte_sequences.append(list(bytes_data))

        # 统计字节对频率
        pair_counts = Counter()
        for seq in byte_sequences:
            for i in range(len(seq) - 1):
                pair = (seq[i], seq[i + 1])
                pair_counts[pair] += 1

        # 执行合并
        merges = {}
        vocab_id = 256 + 4  # 从256+特殊token开始

        for _ in range(num_merges):
            if not pair_counts:
                break

            # 找到最频繁的字节对
            most_common_pair = pair_counts.most_common(1)[0][0]

            # 创建新token
            new_token = bytes([most_common_pair[0], most_common_pair[1]])
            self.vocab[vocab_id] = new_token
            merges[most_common_pair] = vocab_id
            vocab_id += 1

            # 更新所有序列
            new_pair_counts = Counter()
            for seq in byte_sequences:
                i = 0
                new_seq = []
                while i < len(seq):
                    if i < len(seq) - 1 and (seq[i], seq[i + 1]) == most_common_pair:
                        new_seq.append(merges[most_common_pair])
                        i += 2
                    else:
                        new_seq.append(seq[i])
                        i += 1
                seq[:] = new_seq

                # 重新统计字节对
                for j in range(len(seq) - 1):
                    pair = (seq[j], seq[j + 1])
                    new_pair_counts[pair] += 1

            pair_counts = new_pair_counts

        self.merges = merges

    def tokenize(self, text: str) -> List[int]:
        """BPE tokenization"""
        if isinstance(text, str):
            bytes_data = text.encode('utf-8', errors='ignore')
        elif isinstance(text, bytes):
            bytes_data = text
        else:
            bytes_data = str(text).encode('utf-8', errors='ignore')

        # 初始分割为字节
        tokens = list(bytes_data)

        # 应用合并规则
        while len(tokens) > 1:
            # 找到所有可能的合并
            pairs = [(tokens[i], tokens[i + 1]) for i in range(len(tokens) - 1)]
            pair_to_merge = None
            min_rank = float('inf')

            for pair in pairs:
                if pair in self.merges:
                    rank = list(self.merges.keys()).index(pair)
                    if rank < min_rank:
                        min_rank = rank
                        pair_to_merge = pair

            if pair_to_merge is None:
                break

            # 执行合并
            merge_id = self.merges[pair_to_merge]
            new_tokens = []
            i = 0
            while i < len(tokens):
                if i < len(tokens) - 1 and (tokens[i], tokens[i + 1]) == pair_to_merge:
                    new_tokens.append(merge_id)
                    i += 2
                else:
                    new_tokens.append(tokens[i])
                    i += 1
            tokens = new_tokens

        # 转换为vocab ids
        token_ids = []
        for token in tokens:
            if token < 256:
                token_ids.append(token + 4)  # 基础字节
            else:
                token_ids.append(token)

        return token_ids[:self.max_len]

    def detokenize(self, tokens: List[int]) -> str:
        """BPE解码"""
        bytes_data = b''
        for token in tokens:
            if token in self.vocab:
                bytes_data += self.vocab[token]
            else:
                bytes_data += b'\x00'  # 未知token

        return bytes_data.decode('utf-8', errors='ignore')

    def save_merges(self, filepath: str):
        """保存合并规则"""
        with open(filepath, 'w') as f:
            json.dump({
                'merges': [(list(k), v) for k, v in self.merges.items()],
                'vocab': {k: list(v) for k, v in self.vocab.items()}
            }, f)

    def load_merges(self, filepath: str):
        """加载合并规则"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.merges = {tuple(k): v for k, v in data['merges']}
            self.vocab = {k: bytes(v) for k, v in data['vocab'].items()}

class HybridTokenizer(BaseTokenizer):
    """
    混合tokenizer - 文本token + 字节token
    """

    def __init__(self, vocab_size: int = 1000, max_len: int = 1024):
        super().__init__(vocab_size, max_len)
        self.text_vocab = {}
        self.byte_tokenizer = ByteTokenizer(vocab_size // 2, max_len)
        self._build_text_vocab()

    def _build_text_vocab(self):
        """构建常见文本token vocab"""
        common_tokens = [
            '<unk>', '<pad>', '<bos>', '<eos>',
            'GET', 'POST', 'HTTP', 'Host', 'User-Agent',
            'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE',
            'script', 'alert', 'document', 'window',
            'cmd', 'exec', 'system', 'bash', 'powershell'
        ]

        for i, token in enumerate(common_tokens):
            self.text_vocab[token] = i + 256  # 从256开始

    def tokenize(self, text: str) -> List[int]:
        """混合tokenization"""
        if isinstance(text, bytes):
            text = text.decode('utf-8', errors='ignore')

        tokens = []

        # 首先尝试文本tokenization
        words = re.findall(r'\b\w+\b|[^\w\s]', text)
        for word in words:
            if word in self.text_vocab:
                tokens.append(self.text_vocab[word])
            else:
                # 回退到字节级tokenization
                byte_tokens = self.byte_tokenizer.tokenize(word)
                tokens.extend(byte_tokens)

        return tokens[:self.max_len]

    def detokenize(self, tokens: List[int]) -> str:
        """混合解码"""
        result = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in self.text_vocab.values():
                # 文本token
                word = [k for k, v in self.text_vocab.items() if v == token][0]
                result.append(word)
                i += 1
            else:
                # 字节序列，尝试解码
                byte_tokens = []
                while i < len(tokens) and tokens[i] not in self.text_vocab.values():
                    byte_tokens.append(tokens[i])
                    i += 1
                if byte_tokens:
                    byte_str = self.byte_tokenizer.detokenize(byte_tokens)
                    result.append(byte_str)

        return ' '.join(result)

class ProtocolAwareTokenizer(BaseTokenizer):
    """
    协议感知tokenizer - 结合协议结构信息
    """

    def __init__(self, vocab_size: int = 1000, max_len: int = 1024):
        super().__init__(vocab_size, max_len)
        self.protocol_tokens = {
            'tcp': 1000, 'udp': 1001, 'http': 1002, 'dns': 1003,
            'tls': 1004, 'mqtt': 1005, 'modbus': 1006, 'can': 1007
        }
        self.field_tokens = {
            'src_port': 1100, 'dst_port': 1101, 'flags': 1102,
            'method': 1103, 'headers': 1104, 'body': 1105,
            'query': 1106, 'answer': 1107
        }

    def tokenize(self, parsed_packet: Dict[str, Any]) -> List[int]:
        """协议感知tokenization"""
        tokens = []

        # 协议类型token
        protocol = parsed_packet.get('protocol', 'unknown')
        if protocol in self.protocol_tokens:
            tokens.append(self.protocol_tokens[protocol])

        # 结构化字段tokenization
        for field, value in parsed_packet.items():
            if field in self.field_tokens:
                tokens.append(self.field_tokens[field])
                # 字段值tokenization
                if isinstance(value, (str, bytes)):
                    field_tokens = self._tokenize_field_value(value)
                    tokens.extend(field_tokens)
                elif isinstance(value, (int, float)):
                    tokens.append(int(value) % 1000 + 1200)  # 数值映射
                elif isinstance(value, list):
                    for item in value[:5]:  # 限制长度
                        if isinstance(item, dict):
                            for k, v in item.items():
                                if isinstance(v, str):
                                    tokens.extend(self._tokenize_field_value(v)[:10])
                        elif isinstance(item, str):
                            tokens.extend(self._tokenize_field_value(item)[:10])

        # payload tokenization
        payload = parsed_packet.get('payload', '')
        if isinstance(payload, (str, bytes)):
            payload_tokens = ByteTokenizer().tokenize(payload)
            tokens.extend(payload_tokens[:self.max_len - len(tokens)])

        return tokens[:self.max_len]

    def _tokenize_field_value(self, value: str) -> List[int]:
        """字段值tokenization"""
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='ignore')

        # 简单词分割
        words = re.findall(r'\b\w+\b', value)
        tokens = []
        for word in words:
            # 简单hash映射到vocab范围
            token_id = hash(word) % 500 + 1300
            tokens.append(token_id)

        return tokens

    def detokenize(self, tokens: List[int]) -> str:
        """协议感知解码（简化）"""
        return "Protocol-aware detokenization not implemented"

class PacketTokenizer:
    """
    统一的包tokenizer，支持多种tokenization策略
    """

    def __init__(self, method: str = 'byte', **kwargs):
        self.method = method
        if method == 'byte':
            self.tokenizer = ByteTokenizer(**kwargs)
        elif method == 'bpe':
            self.tokenizer = BPEByteTokenizer(**kwargs)
        elif method == 'hybrid':
            self.tokenizer = HybridTokenizer(**kwargs)
        elif method == 'protocol':
            self.tokenizer = ProtocolAwareTokenizer(**kwargs)
        else:
            raise ValueError(f"Unknown tokenization method: {method}")

    def tokenize_packet(self, parsed_packet: Dict[str, Any]) -> List[int]:
        """Tokenize解析后的包"""
        if self.method == 'protocol':
            return self.tokenizer.tokenize(parsed_packet)
        else:
            # 提取payload进行tokenization
            payload = parsed_packet.get('payload', '')
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            return self.tokenizer.encode(str(payload))

    def train_bpe(self, packets: List[Dict[str, Any]], num_merges: int = 256):
        """训练BPE tokenizer"""
        if self.method == 'bpe':
            texts = []
            for packet in packets:
                payload = packet.get('payload', '')
                if isinstance(payload, bytes):
                    texts.append(payload.decode('utf-8', errors='ignore'))
                else:
                    texts.append(str(payload))
            self.tokenizer.train(texts, num_merges)