# parser.py - 协议解析模块

import scapy.all as scapy
from typing import Dict, Any, Optional
import re
import yaml
import os
import logging
from collections import Counter

class ProtocolParser:
    """
    协议解析器，支持常见协议和自定义协议解析
    """

    def __init__(self, custom_protocols_path: str = "data/protocols"):
        self.custom_protocols_path = custom_protocols_path
        self.parsers = {
            'tcp': self._parse_tcp,
            'udp': self._parse_udp,
            'http': self._parse_http,
            'dns': self._parse_dns,
            'tls': self._parse_tls,
            'mqtt': self._parse_mqtt,
            'modbus': self._parse_modbus,
            'can': self._parse_can,
        }
        self.custom_parsers = self._load_custom_parsers()

    def parse(self, pkt_data: bytes) -> Dict[str, Any]:
        """
        解析包数据，返回结构化字段
        """
        try:
            pkt = scapy.IP(pkt_data)
        except Exception:
            # 如果不是 IP 包，尝试其他
            try:
                pkt = scapy.Ether(pkt_data)
            except Exception:
                return {"error": "Invalid packet data"}

        protocol = self._identify_protocol(pkt)
        if protocol in self.parsers:
            return self.parsers[protocol](pkt)
        elif protocol in self.custom_parsers:
            return self.custom_parsers[protocol](pkt)
        else:
            return self._parse_unknown(pkt)

    def _identify_protocol(self, pkt) -> str:
        """
        识别协议类型
        """
        if scapy.TCP in pkt:
            sport = pkt[scapy.TCP].sport
            dport = pkt[scapy.TCP].dport
            if sport == 80 or dport == 80 or sport == 443 or dport == 443:
                if self._is_http(pkt):
                    return 'http'
                elif self._is_tls(pkt):
                    return 'tls'
            elif sport == 53 or dport == 53:
                return 'dns'
            elif sport == 1883 or dport == 1883:
                return 'mqtt'
            elif sport == 502 or dport == 502:
                return 'modbus'
            else:
                return 'tcp'
        elif scapy.UDP in pkt:
            sport = pkt[scapy.UDP].sport
            dport = pkt[scapy.UDP].dport
            if sport == 53 or dport == 53:
                return 'dns'
            else:
                return 'udp'
        elif hasattr(pkt, 'type') and pkt.type == 0x88:  # CAN
            return 'can'
        else:
            return 'unknown'

    def _is_http(self, pkt) -> bool:
        # 增加安全性检查，防止 payload 为空导致索引错误
        try:
            payload = bytes(pkt.payload.payload.payload)
            return payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HTTP/')
        except Exception:
            return False

    def _is_tls(self, pkt) -> bool:
        try:
            payload = bytes(pkt.payload.payload.payload)
            return len(payload) > 0 and payload[0] in [0x16, 0x14, 0x15]  # TLS handshake
        except Exception:
            return False

    def _parse_tcp(self, pkt) -> Dict[str, Any]:
        tcp = pkt[scapy.TCP]
        return {
            'protocol': 'tcp',
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'flags': str(tcp.flags),
            'window': tcp.window,
            'payload': bytes(tcp.payload),
            'payload_len': len(tcp.payload)
        }

    def _parse_udp(self, pkt) -> Dict[str, Any]:
        udp = pkt[scapy.UDP]
        return {
            'protocol': 'udp',
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'payload': bytes(udp.payload),
            'payload_len': len(udp.payload)
        }

    def _parse_http(self, pkt) -> Dict[str, Any]:
        try:
            payload = bytes(pkt.payload.payload.payload).decode('utf-8', errors='ignore')
        except Exception:
            payload = ""
            
        headers = {}
        body = ""
        lines = payload.split('\n')
        request_line = ""
        if lines:
            request_line = lines[0].strip()
            for i, line in enumerate(lines[1:]):
                if line.strip() == "":
                    body = '\n'.join(lines[i+2:])
                    break
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers[k] = v.strip()
        return {
            'protocol': 'http',
            'request_line': request_line,
            'headers': headers,
            'body': body,
            'payload': payload
        }

    def _parse_dns(self, pkt) -> Dict[str, Any]:
        try:
            dns = pkt[scapy.DNS]
            queries = []
            if dns.qd:
                for q in dns.qd:
                    queries.append({
                        'name': str(q.qname),
                        'type': q.qtype,
                        'class': q.qclass
                    })
            answers = []
            if dns.an:
                for a in dns.an:
                    answers.append({
                        'name': str(a.rrname),
                        'type': a.type,
                        'rdata': str(a.rdata)
                    })
            return {
                'protocol': 'dns',
                'id': dns.id,
                'qr': dns.qr,
                'opcode': dns.opcode,
                'queries': queries,
                'answers': answers
            }
        except Exception:
            return {'protocol': 'dns', 'error': 'Parse failed'}

    def _parse_tls(self, pkt) -> Dict[str, Any]:
        try:
            payload = bytes(pkt.payload.payload.payload)
        except Exception:
            return {'protocol': 'tls', 'error': 'No payload'}
            
        if len(payload) < 5:
            return {'protocol': 'tls', 'error': 'Too short'}
        content_type = payload[0]
        version = payload[1:3]
        length = int.from_bytes(payload[3:5], 'big')
        return {
            'protocol': 'tls',
            'content_type': content_type,
            'version': version.hex(),
            'length': length,
            'payload': payload[5:]
        }

    def _parse_mqtt(self, pkt) -> Dict[str, Any]:
        try:
            payload = bytes(pkt.payload.payload.payload)
        except Exception:
            return {'protocol': 'mqtt', 'error': 'No payload'}

        if len(payload) < 2:
            return {'protocol': 'mqtt', 'error': 'Too short'}
        msg_type = (payload[0] >> 4) & 0x0F
        flags = payload[0] & 0x0F
        remaining_len = self._decode_mqtt_length(payload[1:])
        return {
            'protocol': 'mqtt',
            'msg_type': msg_type,
            'flags': flags,
            'remaining_len': remaining_len,
            'payload': payload
        }

    def _decode_mqtt_length(self, data):
        multiplier = 1
        value = 0
        for byte in data:
            value += (byte & 127) * multiplier
            if byte & 128 == 0:
                break
            multiplier *= 128
        return value

    def _parse_modbus(self, pkt) -> Dict[str, Any]:
        try:
            payload = bytes(pkt.payload.payload.payload)
        except Exception:
            return {'protocol': 'modbus', 'error': 'No payload'}

        if len(payload) < 8:
            return {'protocol': 'modbus', 'error': 'Too short'}
        transaction_id = payload[0:2]
        protocol_id = payload[2:4]
        length = payload[4:6]
        unit_id = payload[6]
        function_code = payload[7]
        data = payload[8:]
        return {
            'protocol': 'modbus',
            'transaction_id': transaction_id.hex(),
            'protocol_id': protocol_id.hex(),
            'length': length.hex(),
            'unit_id': unit_id,
            'function_code': function_code,
            'data': data.hex()
        }

    def _parse_can(self, pkt) -> Dict[str, Any]:
        # 假设 CAN 包格式
        if hasattr(pkt, 'id') and hasattr(pkt, 'data'):
            return {
                'protocol': 'can',
                'id': pkt.id,
                'data': pkt.data.hex() if hasattr(pkt.data, 'hex') else str(pkt.data),
                'dlc': len(pkt.data) if hasattr(pkt.data, '__len__') else 0
            }
        else:
            return {'protocol': 'can', 'error': 'Not a CAN packet'}

    def _load_custom_parsers(self) -> Dict[str, callable]:
        parsers = {}
        if os.path.exists(self.custom_protocols_path):
            for file in os.listdir(self.custom_protocols_path):
                if file.endswith('.yaml'):
                    file_path = os.path.join(self.custom_protocols_path, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            config = yaml.safe_load(f)
                            if config and 'name' in config and 'fields' in config:
                                parsers[config['name']] = self._create_custom_parser(config)
                    except Exception as e:
                        logging.warning(f"加载自定义协议失败：{file_path}, 错误：{e}")
        return parsers

    def _create_custom_parser(self, config):
        def parser(pkt):
            try:
                payload = bytes(pkt.payload.payload.payload)
            except Exception:
                return {'protocol': config['name'], 'error': 'No payload'}
            
            fields = {}
            offset = 0
            for field in config['fields']:
                name = field['name']
                type_ = field['type']
                length = field.get('length', 1)
                if offset + length > len(payload):
                    break
                if type_ == 'int':
                    value = int.from_bytes(payload[offset:offset+length], 'big')
                elif type_ == 'str':
                    value = payload[offset:offset+length].decode('utf-8', errors='ignore')
                elif type_ == 'bytes':
                    value = payload[offset:offset+length]
                else:
                    value = None
                fields[name] = value
                offset += length
            return {'protocol': config['name'], **fields}
        return parser

    def _parse_unknown(self, pkt) -> Dict[str, Any]:
        """
        未知协议，使用简单启发式解析（类似 Netzob 基础）
        """
        try:
            payload = bytes(pkt.payload.payload.payload)
        except Exception:
            payload = b""
            
        # 简单字段分割：假设定长或分隔符
        fields = {}
        # 尝试按固定长度分割
        chunk_size = 4
        for i in range(0, len(payload), chunk_size):
            fields[f'field_{i//chunk_size}'] = payload[i:i+chunk_size].hex()
        return {
            'protocol': 'unknown',
            'raw_payload': payload.hex(),
            'inferred_fields': fields,
            'entropy': self._calculate_entropy(payload)
        }

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * (p.bit_length() - 1)  # 近似
        return entropy