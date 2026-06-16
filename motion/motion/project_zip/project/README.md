# Robot Traffic Action Fingerprinting

这个工程实现一个小样本可用的 `pcap -> 动作标签` 原型，目标是从机器狗通信流量中识别 `stand / walk / sit` 这类动作。

方法参考论文 `On the Feasibility of Fingerprinting Collaborative Robot Network Traffic` 的核心思路：

1. 从 pcap 提取 `timestamp / packet_length / direction`。
2. 构造有方向的时间序列信号：`signal[t] = direction * packet_length`。
3. 对每个动作构建平均模板。
4. 对待识别样本和每个动作模板做卷积、相关匹配。
5. 从匹配结果中提取峰值、均值、方差、分位数、聚类数量、时间跨度、平均时间间隔等特征。
6. 使用 RandomForest 训练动作分类器。

## 目录结构

```text
.
├── data/
│   ├── stand/
│   │   ├── stand_01.pcap
│   │   └── ...
│   ├── walk/
│   │   ├── walk_01.pcap
│   │   └── ...
│   └── sit/
│       ├── sit_01.pcap
│       └── ...
├── models/
│   └── action_model.joblib
├── src/
│   └── robot_traffic_action/
│       ├── cli.py
│       ├── features.py
│       ├── model.py
│       ├── pcap_signal.py
│       └── templates.py
├── pyproject.toml
└── requirements.txt
```

你需要把已有 pcap 按动作类别放到 `data/<动作名>/` 下，例如：

```text
data/stand/*.pcap
data/walk/*.pcap
data/sit/*.pcap
```

`pcapng` 也可以尝试，Scapy 通常能读。

## 安装

建议在项目目录创建虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .
```

如果你想用 XGBoost：

```powershell
pip install -e ".[xgboost]"
```

## 训练

基础训练：

```powershell
robot-action train --data-dir data --model-out models/action_model.joblib
```

如果你的 pcap 里有多组通信，建议指定机器狗或控制端 IP 来稳定方向。比如把机器狗发出的包记为正方向：

```powershell
robot-action train --data-dir data --model-out models/action_model.joblib --positive-ip 192.168.1.20
```

只看 UDP：

```powershell
robot-action train --data-dir data --model-out models/action_model.joblib --protocol udp
```

调整时间窗口，默认每 `20ms` 聚合一次：

```powershell
robot-action train --data-dir data --model-out models/action_model.joblib --bin-size 0.02
```

训练时会自动做一个小样本 leave-one-out 验证，给出准确率和混淆矩阵。

## 预测

```powershell
robot-action predict --model models/action_model.joblib --pcap new_action.pcap
```

带方向 IP：

```powershell
robot-action predict --model models/action_model.joblib --pcap new_action.pcap --positive-ip 192.168.1.20
```

输出类似：

```text
predicted=walk
confidence=0.8732
proba:
  sit: 0.0310
  stand: 0.0958
  walk: 0.8732
```

## 检查单个 pcap 的信号

```powershell
robot-action inspect --pcap data/walk/walk_01.pcap --positive-ip 192.168.1.20
```

这个命令会输出包数量、持续时间、信号长度、正负方向包数量等信息，适合先排查 pcap 是否读对了。

## 参数建议

小样本阶段可以先保持默认：

- `--bin-size 0.02`
- `--length-mode packet`
- `--protocol all`
- `--classifier rf`

如果动作持续时间明显较长或包比较稀疏，可以试：

```powershell
robot-action train --data-dir data --bin-size 0.05 --model-out models/action_model.joblib
```

如果方向不稳定，分类效果会明显变差。优先使用 `--positive-ip` 固定方向。
