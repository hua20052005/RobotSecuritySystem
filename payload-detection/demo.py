# demo.py - 系统演示脚本

import sys
import os
import time
import json
from typing import List, Dict, Any
import logging

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.model.inference import InferenceEngine, DetectionResult, detect_packet
from modules.parser import ProtocolParser as PacketParser
from modules.rules_engine import RulesEngine
from modules.feature import FeatureExtractor
from modules.tokenizer import PacketTokenizer as PayloadTokenizer

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PayloadDetectionDemo:
    """
    载荷检测系统演示
    """

    def __init__(self):
        """初始化演示"""
        self.inference_engine = None
        self.parser = PacketParser()
        self.rules_engine = RulesEngine()
        self.feature_extractor = FeatureExtractor()
        self.tokenizer = PayloadTokenizer()

        logger.info("演示系统初始化完成")

    def initialize_inference_engine(self):
        """初始化推理引擎"""
        try:
            self.inference_engine = InferenceEngine()
            logger.info("推理引擎初始化成功")
            return True
        except Exception as e:
            logger.error(f"推理引擎初始化失败: {e}")
            return False

    def demo_basic_components(self):
        """演示基础组件功能"""
        print("\n" + "="*60)
        print("1. 基础组件功能演示")
        print("="*60)

        # 测试数据包
        test_packets = [
            # 正常HTTP请求
            {
                'payload': 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80
            },
            # SQL注入攻击
            {
                'payload': "SELECT * FROM users WHERE id='1' OR '1'='1';",
                'protocol': 'TCP',
                'src_ip': '192.168.1.101',
                'dst_ip': '10.0.0.1',
                'src_port': 12346,
                'dst_port': 3306
            },
            # XSS攻击
            {
                'payload': '<script>alert("XSS Attack")</script>',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.102',
                'dst_ip': '10.0.0.1',
                'src_port': 12347,
                'dst_port': 80
            }
        ]

        for i, packet in enumerate(test_packets, 1):
            print(f"\n--- 测试数据包 {i} ---")
            print(f"协议: {packet['protocol']}")
            print(f"载荷: {packet['payload'][:100]}{'...' if len(packet['payload']) > 100 else ''}")

            # 规则检测
            print("\n规则检测结果:")
            rule_results = self.rules_engine.match(packet)
            rule_names = [r.get('name') for r in rule_results]
            print(f"  匹配规则: {rule_names}")
            print(f"  规则置信度: {sum([r.get('confidence', 0.0) for r in rule_results]) / max(len(rule_results), 1):.3f}")

            # 特征提取
            print("\n特征提取结果:")
            features = self.feature_extractor.extract(packet)
            print(f"  提取特征数: {len(features)}")
            for key, value in list(features.items())[:5]:  # 只显示前5个特征
                print(f"    {key}: {value}")

            # 标记化
            print("\n标记化结果:")
            tokens = self.tokenizer.tokenize_packet(packet)
            print(f"  标记数量: {len(tokens)}")
            print(f"  词汇表大小: {self.tokenizer.tokenizer.vocab_size}")

    def demo_ml_models(self):
        """演示ML模型功能"""
        print("\n" + "="*60)
        print("2. ML模型功能演示")
        print("="*60)

        if not self.initialize_inference_engine():
            print("推理引擎初始化失败，跳过ML演示")
            return

        # 测试数据包
        test_packets = [
            {
                'payload': 'GET /admin.php?user=admin&pass=123456 HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80
            },
            {
                'payload': 'POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=admin123',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.101',
                'dst_ip': '10.0.0.1',
                'src_port': 12346,
                'dst_port': 80
            },
            {
                'payload': '\x00\x01\x02\x03\xff\xfe\xfd' * 10,  # 异常字节模式
                'protocol': 'TCP',
                'src_ip': '192.168.1.102',
                'dst_ip': '10.0.0.1',
                'src_port': 12347,
                'dst_port': 443
            }
        ]

        for i, packet in enumerate(test_packets, 1):
            print(f"\n--- ML检测测试 {i} ---")
            print(f"载荷: {packet['payload'][:100]}{'...' if len(packet['payload']) > 100 else ''}")

            start_time = time.time()
            result = self.inference_engine.detect_packet(packet)
            processing_time = time.time() - start_time

            print(f"检测结果: {result.result.value}")
            print(".3f")
            print(".4f")
            print(f"规则匹配: {result.rule_matches}")
            print(f"ML分数: {result.ml_scores}")

    def demo_batch_processing(self):
        """演示批量处理功能"""
        print("\n" + "="*60)
        print("3. 批量处理演示")
        print("="*60)

        if not self.initialize_inference_engine():
            print("推理引擎初始化失败，跳过批量演示")
            return

        # 生成测试数据包
        test_packets = []
        for i in range(10):
            packet = {
                'payload': f'GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
                'protocol': 'HTTP',
                'src_ip': f'192.168.1.{100+i}',
                'dst_ip': '10.0.0.1',
                'src_port': 12345 + i,
                'dst_port': 80
            }
            test_packets.append(packet)

        # 添加一些可疑数据包
        suspicious_packets = [
            {
                'payload': "UNION SELECT * FROM information_schema.tables--",
                'protocol': 'TCP',
                'src_ip': '192.168.1.200',
                'dst_ip': '10.0.0.1',
                'src_port': 12350,
                'dst_port': 3306
            },
            {
                'payload': '<img src=x onerror=alert(1)>',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.201',
                'dst_ip': '10.0.0.1',
                'src_port': 12351,
                'dst_port': 80
            }
        ]
        test_packets.extend(suspicious_packets)

        print(f"批量处理 {len(test_packets)} 个数据包...")

        start_time = time.time()
        results = self.inference_engine.detect_batch(test_packets)
        total_time = time.time() - start_time

        # 统计结果
        result_counts = {}
        for result in results:
            key = result.result.value
            result_counts[key] = result_counts.get(key, 0) + 1

        print("\n批量处理结果统计:")
        print(f"  总处理时间: {total_time:.4f} 秒")
        for result_type, count in result_counts.items():
            print(f"  {result_type}: {count} 个")

        print("\n详细结果:")
        for i, result in enumerate(results):
            if result.result != DetectionResult.NORMAL:  # 只显示异常结果
                print(f"  数据包 {i+1}: {result.result.value} (置信度: {result.confidence:.3f})")

    def demo_performance_benchmark(self):
        """性能基准测试"""
        print("\n" + "="*60)
        print("4. 性能基准测试")
        print("="*60)

        if not self.initialize_inference_engine():
            print("推理引擎初始化失败，跳过性能测试")
            return

        # 生成大量测试数据
        packet_sizes = [100, 1000, 10000]
        results = {}

        for size in packet_sizes:
            print(f"\n测试 {size} 个数据包...")

            test_packets = []
            for i in range(size):
                packet = {
                    'payload': f'GET /test{i}.html HTTP/1.1\r\nHost: example.com\r\n\r\n' + 'x' * (i % 100),
                    'protocol': 'HTTP',
                    'src_ip': f'192.168.{i//256}.{i%256}',
                    'dst_ip': '10.0.0.1',
                    'src_port': 10000 + i,
                    'dst_port': 80
                }
                test_packets.append(packet)

            # 测量处理时间
            start_time = time.time()
            results_batch = self.inference_engine.detect_batch(test_packets)
            end_time = time.time()

            processing_time = end_time - start_time
            avg_time_per_packet = processing_time / size
            packets_per_second = size / processing_time

            results[size] = {
                'total_time': processing_time,
                'avg_time_per_packet': avg_time_per_packet,
                'packets_per_second': packets_per_second
            }

            print(f"  总时间: {processing_time:.4f} 秒")
            print(f"  平均每个数据包: {avg_time_per_packet:.6f} 秒")
            print(f"  处理速率: {packets_per_second:.2f} 个/秒")

        print("\n性能汇总:")
        print("数据包数量 | 总时间(秒) | 平均时间(秒) | 处理速度(个/秒)")
        print("-" * 60)
        for size in packet_sizes:
            r = results[size]
            print(f"{size} | {r['total_time']:.4f} | {r['avg_time_per_packet']:.6f} | {r['packets_per_second']:.2f}")

    def demo_attack_scenarios(self):
        """演示攻击场景检测"""
        print("\n" + "="*60)
        print("5. 攻击场景演示")
        print("="*60)

        if not self.initialize_inference_engine():
            print("推理引擎初始化失败，跳过攻击演示")
            return

        # 各种攻击场景
        attack_scenarios = {
            'SQL注入': [
                "SELECT * FROM users WHERE id='1' OR '1'='1'",
                "UNION SELECT username, password FROM admin--",
                "'; DROP TABLE users; --"
            ],
            'XSS攻击': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert(1)>',
                'javascript:alert(document.cookie)'
            ],
            '命令注入': [
                '; rm -rf /',
                '| cat /etc/passwd',
                '`whoami`'
            ],
            '路径遍历': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '/../../../../etc/shadow'
            ],
            '缓冲区溢出': [
                'A' * 1000,
                '\x90' * 500 + '\xCC' * 4,
                '\x00' * 256 + 'shellcode'
            ]
        }

        for attack_type, payloads in attack_scenarios.items():
            print(f"\n--- {attack_type}检测 ---")

            for payload in payloads:
                packet = {
                    'payload': payload,
                    'protocol': 'TCP',
                    'src_ip': '192.168.1.100',
                    'dst_ip': '10.0.0.1',
                    'src_port': 12345,
                    'dst_port': 80
                }

                result = self.inference_engine.detect_packet(packet)

                status = "✓ 检测到" if result.result in [DetectionResult.SUSPICIOUS, DetectionResult.MALICIOUS] else "✗ 未检测到"
                print(f"  {status}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                print(".3f")

    def run_full_demo(self):
        """运行完整演示"""
        print("RoboGuard4 - 通信包载荷安全检测系统演示")
        print("="*60)

        try:
            # 演示基础组件
            self.demo_basic_components()

            # 演示ML模型
            self.demo_ml_models()

            # 演示批量处理
            self.demo_batch_processing()

            # 性能基准测试
            self.demo_performance_benchmark()

            # 攻击场景演示
            self.demo_attack_scenarios()

            print("\n" + "="*60)
            print("演示完成！")
            print("="*60)

        except Exception as e:
            logger.error(f"演示过程中发生错误: {e}")
            print(f"\n演示失败: {e}")

def main():
    """主函数"""
    demo = PayloadDetectionDemo()
    demo.run_full_demo()

if __name__ == "__main__":
    main()