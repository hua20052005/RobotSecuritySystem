#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
detect_from_pcap.py - 从 pcap 文件批量检测通信包载荷内容
"""
import argparse
import os
import sys
import csv
import time
import json
from collections import Counter

# 确保包含上级目录，能够 import modules
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from scapy.all import rdpcap
except ImportError as e:
    raise ImportError("请先安装 scapy: pip install scapy") from e

from modules.inference.pipeline import PayloadDetectionPipeline


def parse_args():
    parser = argparse.ArgumentParser(description='从PCAP文件执行载荷检测')
    parser.add_argument('pcap_path', type=str, help='输入PCAP文件路径')
    parser.add_argument('--transformer', type=str, default=None, help='Transformer模型路径')
    parser.add_argument('--lgb', type=str, default=None, help='LightGBM模型路径')
    parser.add_argument('--anomaly', type=str, default=None, help='Anomaly模型路径')
    parser.add_argument('--ensemble', type=str, default=r'D:\学习\信安赛\Roboguard4\Roboguard\payload-detection\models\ensemble_classifier_improved.pkl', help='集成分类器模型路径')
    parser.add_argument('--output', type=str, default='detect_results.csv', help='结果CSV输出路径')
    parser.add_argument('--summary-output', type=str, default=None, help='整体汇总JSON输出路径（默认: 与CSV同目录同名前缀_summary.json）')
    parser.add_argument('--limit', type=int, default=None, help='最多检测包数')
    parser.add_argument('--verbose', action='store_true', help='显示详细日志')
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.isfile(args.pcap_path):
        raise FileNotFoundError(f"PCAP文件不存在: {args.pcap_path}")

    print(f"[INFO] 读取PCAP: {args.pcap_path}")
    packets = rdpcap(args.pcap_path)
    total_packets = len(packets)
    print(f"[INFO] 读取到 {total_packets} 个包")

    pipeline = PayloadDetectionPipeline(
        use_transformer=bool(args.transformer),
        use_anomaly=bool(args.anomaly),
        device='cpu'
    )
    pipeline.load_models(transformer_path=args.transformer, lgb_path=args.lgb, anomaly_path=args.anomaly, ensemble_path=args.ensemble)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    fieldnames = [
        'packet_index', 'protocol', 'final_score', 'threat_level', 'confidence',
        'rule_hits', 'lgb_proba', 'transformer_proba', 'anomaly_score', 'elapsed_ms'
    ]

    with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        count = 0
        start_total = time.time()
        score_sum = 0.0
        confidence_sum = 0.0
        threat_counter = Counter()
        protocol_counter = Counter()
        rule_counter = Counter()
        non_safe_count = 0
        high_or_critical_count = 0
        top_packet = {'packet_index': -1, 'final_score': -1.0, 'threat_level': 'SAFE', 'protocol': 'unknown'}

        for i, pkt in enumerate(packets):
            if args.limit and count >= args.limit:
                break

            try:
                raw_bytes = bytes(pkt)
            except Exception as e:
                if args.verbose:
                    print(f"[WARN] 跳过包{i}，无法转换为字节: {e}")
                continue

            begin = time.time()
            result = pipeline.detect(raw_bytes, return_details=True)
            elapsed = (time.time() - begin) * 1000.0

            row = {
                'packet_index': i,
                'protocol': result.get('details', {}).get('protocol', 'unknown'),
                'final_score': result.get('final_score', 0.0),
                'threat_level': result.get('threat_level', 'UNKNOWN'),
                'confidence': result.get('confidence', 0.0),
                'rule_hits': result.get('details', {}).get('rule_hits', 0),
                'lgb_proba': result.get('lgb_proba', 0.0),
                'transformer_proba': result.get('transformer_proba', 0.0),
                'anomaly_score': result.get('anomaly_score', 0.0),
                'elapsed_ms': f"{elapsed:.2f}"
            }
            writer.writerow(row)

            # 累计文件级统计信息
            score = float(row['final_score'])
            confidence = float(row['confidence'])
            threat_level = row['threat_level']
            protocol = row['protocol']

            score_sum += score
            confidence_sum += confidence
            threat_counter[threat_level] += 1
            protocol_counter[protocol] += 1

            if threat_level != 'SAFE':
                non_safe_count += 1
            if threat_level in ('HIGH', 'CRITICAL'):
                high_or_critical_count += 1

            if score > top_packet['final_score']:
                top_packet = {
                    'packet_index': i,
                    'final_score': score,
                    'threat_level': threat_level,
                    'protocol': protocol
                }

            for m in result.get('evidence', {}).get('rule_matches', []):
                rule_key = m.get('id') or m.get('name') or 'unknown_rule'
                rule_counter[rule_key] += 1

            if args.verbose:
                print(f"[{i}] {row['protocol']} -> {row['threat_level']} score={row['final_score']:.4f} conf={row['confidence']:.4f} {row['elapsed_ms']} ms")

            count += 1

        total_time = time.time() - start_total

    print(f"[OK] 检测完成: {count} / {total_packets} 个包，耗时 {total_time:.2f}s")
    print(f"结果已保存: {args.output}")

    # 输出文件级汇总
    processed_packets = max(count, 1)
    summary_output = args.summary_output
    if not summary_output:
        base, _ = os.path.splitext(args.output)
        summary_output = f"{base}_summary.json"

    summary = {
        'pcap_path': args.pcap_path,
        'output_csv': args.output,
        'processed_packets': count,
        'total_packets_in_file': total_packets,
        'processing_time_sec': round(total_time, 4),
        'avg_packet_time_ms': round((total_time * 1000.0) / processed_packets, 4),
        'avg_final_score': round(score_sum / processed_packets, 6),
        'avg_confidence': round(confidence_sum / processed_packets, 6),
        'non_safe_ratio': round(non_safe_count / processed_packets, 6),
        'high_or_critical_ratio': round(high_or_critical_count / processed_packets, 6),
        'max_score_packet': top_packet,
        'threat_level_distribution': dict(threat_counter),
        'protocol_distribution': dict(protocol_counter),
        'top_rule_hits': [
            {'rule': rule, 'hits': hits}
            for rule, hits in rule_counter.most_common(10)
        ]
    }

    summary_dir = os.path.dirname(summary_output)
    if summary_dir:
        os.makedirs(summary_dir, exist_ok=True)
    with open(summary_output, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"汇总已保存: {summary_output}")
    print(
        "文件级总评: "
        f"avg_score={summary['avg_final_score']:.4f}, "
        f"non_safe_ratio={summary['non_safe_ratio']:.2%}, "
        f"high_or_critical_ratio={summary['high_or_critical_ratio']:.2%}"
    )


if __name__ == '__main__':
    main()
