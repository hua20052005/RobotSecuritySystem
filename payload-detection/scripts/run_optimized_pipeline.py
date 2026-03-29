#!/usr/bin/env python3
"""
优化系统演示脚本：四源完整融合检测
启用：规则 + LightGBM + Transformer + 异常检测
"""

import sys
import os
import json
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.inference.pipeline import PayloadDetectionPipeline

def print_section(title: str):
    """打印分隔线"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def main():
    # ===== 初始化管道 =====
    print_section("初始化四源融合检测管道")
    
    pipeline = PayloadDetectionPipeline(
        use_transformer=True,    # ✓ 启用Transformer
        use_anomaly=True,        # ✓ 启用异常检测
        device='cpu'
    )
    
    print("✓ 管道初始化完成")
    print(f"  - Transformer模块: {'启用' if pipeline.use_transformer else '禁用'}")
    print(f"  - 异常检测模块: {'启用' if pipeline.use_anomaly else '禁用'}")
    print(f"  - 计算设备: {pipeline.device}")
    
    # ===== 加载模型 =====
    print_section("加载预训练模型")
    
    model_dir = Path(__file__).parent.parent / "models"
    
    # 定义模型路径
    models_to_load = {
        "ensemble": model_dir / "ensemble_classifier.pkl",
        "transformer": model_dir / "packet_transformer.pth",
        "anomaly": model_dir / "anomaly_detector.pkl",
    }
    
    # 加载已存在的模型
    loaded_count = 0
    for model_name, model_path in models_to_load.items():
        if model_path.exists():
            print(f"✓ 找到{model_name}模型: {model_path.name}")
            loaded_count += 1
        else:
            print(f"⚠ 未找到{model_name}模型: {model_path}")
    
    if loaded_count == 0:
        print("\n⚠ 警告：没有找到任何预训练模型")
        print("  系统将使用默认/随机初始化的模型，检测效果可能不理想")
        print("\n提示：如需获得最佳性能，请先运行训练脚本：")
        print("  python scripts/train_from_csv_improved.py")
    
    # 加载模型
    pipeline.load_models(
        transformer_path=str(models_to_load["transformer"]) if models_to_load["transformer"].exists() else None,
        ensemble_path=str(models_to_load["ensemble"]) if models_to_load["ensemble"].exists() else None,
        anomaly_path=str(models_to_load["anomaly"]) if models_to_load["anomaly"].exists() else None,
    )
    
    # ===== 测试数据 =====
    print_section("四源融合模型测试")
    
    # 正常HTTP请求
    normal_request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    
    # SQL注入攻击
    sql_injection = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 50\r\n"
        b"\r\n"
        b"username=admin&password=1' OR '1'='1"
    )
    
    # XSS攻击
    xss_attack = (
        b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    
    # 路径遍历
    path_traversal = (
        b"GET /../../etc/passwd HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    
    test_cases = [
        ("正常请求", normal_request),
        ("SQL注入攻击", sql_injection),
        ("XSS攻击", xss_attack),
        ("路径遍历", path_traversal),
    ]
    
    print("\n运行检测...\n")
    
    results_summary = []
    
    for case_name, packet_data in test_cases:
        print(f"\n测试用例: {case_name}")
        print("-" * 70)
        
        try:
            # 执行检测
            result = pipeline.detect(packet_data, return_details=True)
            
            # 保存结果
            results_summary.append({
                "case": case_name,
                "result": result
            })
            
            # 打印结果
            print(f"最终评分:     {result['final_score']:.4f}")
            print(f"威胁等级:     {result['threat_level']}")
            print(f"置信度:       {result['confidence']:.4f}")
            
            # 打印四个模型的评分
            if 'component_scores' in result:
                scores = result['component_scores']
                print(f"\n四个模型的评分：")
                print(f"  规则匹配:     {scores.get('rule', 0):.4f} (权重 0.25)")
                print(f"  LightGBM:     {scores.get('lgb', 0):.4f} (权重 0.30)")
                print(f"  Transformer:  {scores.get('transformer', 0):.4f} (权重 0.30)")
                print(f"  异常检测:     {scores.get('anomaly', 0):.4f} (权重 0.15)")
            
            # 打印证据
            if 'evidence' in result:
                evidence = result['evidence']
                print(f"\n检测证据：")
                print(f"  规则匹配数: {evidence.get('num_matches', 0)}")
                print(f"  异常检测:  {'是' if evidence.get('anomaly_detected', False) else '否'}")
                
        except Exception as e:
            print(f"❌ 检测失败: {e}")
            import traceback
            traceback.print_exc()
    
    # ===== 总结 =====
    print_section("检测结果总结")
    
    print("\n四源融合系统激活状态：")
    print("┌─────────────────────┬──────────┬────────┐")
    print("│ 检测模块            │ 权重     │ 状态   │")
    print("├─────────────────────┼──────────┼────────┤")
    print("│ 规则匹配引擎        │ 0.25     │ ✓ 有效  │")
    print("│ LightGBM分类器      │ 0.30     │ ✓ 有效  │")
    print("│ Transformer深度学习 │ 0.30     │ ✓ 有效  │")
    print("│ 异常检测器          │ 0.15     │ ✓ 有效  │")
    print("└─────────────────────┴──────────┴────────┘")
    
    print("\n融合公式：")
    print("final_score = 0.25×rule + 0.30×lgb + 0.30×transformer + 0.15×anomaly")
    
    print("\n各测试用例结果：")
    for item in results_summary:
        case_name = item['case']
        result = item['result']
        status_icon = "🔴" if result['threat_level'] in ['CRITICAL', 'HIGH'] else "🟢"
        print(f"  {status_icon} {case_name:15} → {result['threat_level']:10} (分数: {result['final_score']:.4f})")
    
    print("\n" + "=" * 70)
    print("演示完成！")
    print("=" * 70)

if __name__ == "__main__":
    main()
