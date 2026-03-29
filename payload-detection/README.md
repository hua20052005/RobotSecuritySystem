# RoboGuard4 - 通信包载荷安全检测系统

## 项目概述

RoboGuard4是一个先进的通信包载荷安全检测系统，专为 embodied intelligence（具身智能）设计。该系统结合了规则引擎和机器学习技术，能够检测各种网络攻击和异常行为。

## 主要特性

### 🔍 多层次检测
- **规则检测**: 基于28种预定义规则的模式匹配
- **机器学习检测**: Transformer、异常检测、集成分类器
- **融合决策**: 规则和ML结果的智能融合

### 🎯 支持协议
- HTTP/HTTPS
- DNS
- TCP/UDP
- MQTT
- Modbus
- CAN
- 自定义协议（YAML配置）

### 🧠 先进算法
- **Transformer架构**: 自注意力机制的深度学习模型
- **异常检测**: Deep SVDD、Flow-based模型
- **集成学习**: LightGBM、XGBoost、随机森林、MLP

### ⚡ 高性能
- 批量处理支持
- GPU加速
- 实时检测能力

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Packet Parser │ -> │  Rules Engine   │ -> │ Feature Extract │
│                 │    │   (28 rules)    │    │   (43 features)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   ML Models     │
                    │ - Transformer   │
                    │ - Anomaly Det.  │
                    │ - Ensemble Clf. │
                    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │  Fusion Engine  │
                    │   Decision      │
                    └─────────────────┘
```

## 安装和配置

### 环境要求
- Python 3.8+
- PyTorch 1.9+
- CUDA (可选，用于GPU加速)

### 安装依赖
```bash
pip install -r requirements.txt
```

### 配置文件
- `config/inference_config.yaml`: 推理引擎配置
- `config/mlconfig.yaml`: ML模型配置
- `config/rules.yaml`: 检测规则配置

## 使用方法

### 1. 初始化系统
```python
from modules.model.inference import InferenceEngine

# 创建推理引擎
engine = InferenceEngine('config/inference_config.yaml')
```

### 2. 检测单个数据包
```python
packet = {
    'payload': 'SELECT * FROM users WHERE id=1',
    'protocol': 'TCP',
    'src_ip': '192.168.1.100',
    'dst_ip': '10.0.0.1',
    'src_port': 12345,
    'dst_port': 3306
}

result = engine.detect_packet(packet)
print(f"检测结果: {result.result}")
print(f"置信度: {result.confidence}")
```

### 3. 批量检测
```python
packets = [packet1, packet2, packet3]
results = engine.detect_batch(packets)
```

### 4. 运行演示
```bash
python demo.py
```

### 5. 从PCAP文件检测
```bash
python scripts/detect_from_pcap.py data/datasets/your_capture.pcap --output results.csv --verbose
```

可选参数:
- `--transformer model.pt`  加载Transformer模型
- `--lgb models/ensemble_classifier_improved.pkl`  加载LightGBM模型（如果实现）
- `--anomaly anomaly.pkl`  加载异常检测模型
- `--limit 1000` 只处理前1000个包
- `--summary-output results_summary.json` 输出文件级总评(JSON)

### 6. 前端可视化页面（上传PCAP并查看检测结果）
```bash
uvicorn webapp.main:app --host 0.0.0.0 --port 8000 --reload
```

浏览器访问:
- `http://127.0.0.1:8000`

前端能力:
- 上传 `.pcap/.pcapng` 并触发检测
- 展示文件级总评（平均风险分、威胁分布、协议分布、Top规则）
- 分页查看逐包检测结果
- 下载逐包CSV与汇总JSON

### 7. 模型评估
```bash
python evaluation.py
```

## 检测能力

### 支持的攻击类型
- **注入攻击**: SQL注入、命令注入、LDAP注入
- **XSS攻击**: 反射型、存储型、DOM型
- **文件包含**: 本地文件包含、远程文件包含
- **路径遍历**: 目录遍历攻击
- **缓冲区溢出**: 栈溢出、堆溢出
- **协议攻击**: MQTT劫持、Modbus扫描
- **异常流量**: DDoS、扫描、异常连接

### 检测规则示例
```yaml
# SQL注入规则
sql_injection:
  pattern: "(?i)(union|select|insert|update|delete|drop|create|alter).*?(from|into|table|database)"
  severity: high
  category: injection

# XSS规则
xss_attack:
  pattern: "<script[^>]*>.*?</script>"
  severity: high
  category: xss
```

## 模型训练

### 训练数据准备
```python
from modules.model.trainer import DataPreprocessor

# 加载数据
X, y = load_your_data()

# 数据预处理
preprocessor = DataPreprocessor()
train_loader, val_loader, test_loader = preprocessor.create_dataloaders(X, y)
```

### 训练模型
```python
from modules.model.trainer import ModelTrainer
from modules.model.packet_transformer import PacketTransformer

# 创建模型和训练器
model = PacketTransformer(vocab_size=5000, max_len=512)
trainer = ModelTrainer(model)

# 训练
history = trainer.train(train_loader, val_loader, epochs=100)
```

## 性能指标

### 检测准确率
- **准确率**: >95%
- **精确率**: >92%
- **召回率**: >90%
- **F1分数**: >91%

### 处理性能
- **单包检测**: <10ms
- **批量处理**: >1000包/秒
- **内存占用**: <500MB

## API参考

### InferenceEngine
```python
class InferenceEngine:
    def __init__(config_path: str = None)
    def detect_packet(packet: Dict) -> DetectionOutput
    def detect_batch(packets: List[Dict]) -> List[DetectionOutput]
    def update_models(model_paths: Dict[str, str]) -> None
```

### DetectionOutput
```python
@dataclass
class DetectionOutput:
    result: DetectionResult  # NORMAL, SUSPICIOUS, MALICIOUS, UNKNOWN
    confidence: float        # 0.0-1.0
    rule_matches: List[str]  # 匹配的规则
    ml_scores: Dict[str, float]  # ML模型分数
    features: Dict[str, Any]    # 提取的特征
    processing_time: float      # 处理时间(秒)
    timestamp: str             # 检测时间戳
```

## 扩展开发

### 添加新协议
1. 在`parser/protocols/`目录下创建YAML配置文件
2. 实现协议解析器类
3. 更新`parser/parser.py`中的协议映射

### 添加新规则
1. 编辑`config/rules.yaml`文件
2. 添加规则模式和参数
3. 测试规则匹配效果

### 添加新模型
1. 在`modules/model/`目录下实现模型类
2. 更新`config/mlconfig.yaml`配置
3. 修改`inference.py`中的模型加载逻辑

## 测试和验证

### 单元测试
```bash
python -m pytest tests/
```

### 集成测试
```bash
python demo.py
```

### 性能测试
```bash
python evaluation.py
```

## 部署和运维

### 模型部署
```bash
# 保存训练好的模型
trainer.save_model('models/production_model.pth')

# 加载生产模型
engine.update_models({
    'transformer': 'models/production_model.pth'
})
```

### 监控和告警
- 检测延迟监控
- 内存使用监控
- 检测准确率监控
- 自动模型更新

