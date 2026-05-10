# RobotSecuritySystem - 机器人安全检测系统

一个综合性的网络安全检测平台，包含侧通道分析、载荷检测、运动识别等多项检测能力，支持前后端分离的架构。

## 📋 项目概览

### 核心功能

| 功能模块 | 描述 | 主要文件 |
|---------|------|--------|
| **侧通道分析** | 基于 IsolationForest 的网络流量异常检测 | `backend/side_channel_api.py` |
| **载荷检测** | 通过特征工程和机器学习检测恶意载荷 | `payload-detection/` |
| **运动识别** | 基于 PCAP 包的运动模式识别 | `motion/` |
| **任务管理** | 后台任务调度和执行 | `backend/tasks_api.py` |
| **AI 报告** | 自动生成检测分析报告 | `backend/ai_report.py` |
| **身份认证** | 用户认证和授权管理 | `backend/auth.py`, `backend/auth_api.py` |

### 架构概览

```
RobotSecuritySystem
├── 前端
│   ├── Vue 3 + Vite (web/)              新版前后端分离
│   └── Streamlit (app.py, pages/)       旧版兼容入口
│
├── 后端 (FastAPI)
│   ├── 侧通道分析 API
│   ├── 载荷检测 API
│   ├── 运动识别 API
│   ├── 任务管理 API
│   └── 认证系统
│
└── 核心模块
    ├── 特征工程
    ├── 异常检测
    └── 数据库管理
```

---

## 📁 项目结构详解

```
RobotSecuritySystem/
│
├── app.py                           # Streamlit 主入口
├── requirements.txt                 # 项目依赖
├── README.md                        # 本文档
│
├── web/                             # 前端 (Vue 3 + Vite)
│   ├── src/
│   │   ├── App.vue                  # 主应用组件
│   │   ├── main.js                  # 启动文件
│   │   ├── api/                     # API 调用模块
│   │   ├── components/              # UI 组件库
│   │   ├── router/                  # 路由配置
│   │   └── views/                   # 页面视图
│   ├── package.json
│   └── vite.config.js
│
├── backend/                         # 后端服务 (FastAPI)
│   ├── __init__.py
│   ├── auth.py                      # 认证逻辑
│   ├── auth_api.py                  # 认证 API
│   ├── db.py                        # 数据库连接
│   ├── ai_report.py                 # AI 报告生成
│   ├── side_channel_api.py          # 侧通道分析 API
│   ├── motion_api.py                # 运动识别 API
│   ├── tasks_api.py                 # 任务管理 API
│   └── payload_api/                 # 载荷检测 API
│       ├── __init__.py
│       └── main.py                  # FastAPI 主应用
│
├── core/                            # 核心模块
│   ├── detector.py                  # 异常检测器
│   ├── feature_eng.py               # 特征工程
│   └── payload_backend_bootstrap.py # 后端自启动
│
├── payload-detection/               # 载荷检测子系统
│   ├── requirements.txt
│   ├── config/                      # 配置文件
│   │   ├── mlconfig.yaml
│   │   └── inference_config.yaml
│   ├── models/                      # 模型资产
│   ├── modules/                     # 检测模块
│   │   ├── feature.py               # 特征提取
│   │   ├── parser.py                # 协议解析
│   │   ├── tokenizer.py             # Token 化
│   │   ├── rules_engine.py          # 规则引擎
│   │   ├── inference/               # 推理模块
│   │   ├── model/                   # 模型模块
│   │   └── utils/                   # 工具函数
│   ├── scripts/                     # 脚本工具
│   │   ├── detect_from_pcap.py      # PCAP 检测
│   │   ├── train.py                 # 模型训练
│   │   ├── eval.py                  # 模型评估
│   │   └── infer.py                 # 推理脚本
│   └── data/                        # 数据集
│       ├── datasets/
│       ├── iocs/                    # 指标库
│       └── protocols/               # 协议定义
│
├── motion/                          # 运动识别系统
│   ├── motion/
│   │   ├── inference.py             # 推理模块
│   │   ├── model_motion_sequences.py # 运动模型
│   │   ├── task_sequences_example.json
│   │   ├── hello/                   # 测试数据
│   │   ├── jump/
│   │   ├── walk/
│   │   ├── step/
│   │   ├── scapy/
│   │   └── outputs_motion_model*/   # 模型输出
│   └── api_runs/                    # API 运行记录
│
├── pages/                           # Streamlit 多页面
│   ├── 1_side_channel_analysis.py   # 侧通道分析页
│   └── 2_payload_detection.py       # 载荷检测页
│
├── data/                            # 数据集目录
│   ├── Backdoor_Malware.pcap
│   ├── test_mixed.pcap
│   ├── test.pcapng
│   └── temp_upload.pcap
│
├── injector.py                      # 依赖注入
├── _fix_theme.py                    # 主题修复
└── [其他配置文件]
```

---

## 🔧 环境要求

- **操作系统**: Windows 10+ (或 Linux/macOS 需调整命令)
- **Python**: 3.10 或更高版本（推荐 3.11）
- **包管理**: pip / conda
- **可选**: Wireshark/TShark (用于 PCAP 高级分析)

### 主要依赖库

| 库 | 用途 |
|----|------|
| FastAPI / Uvicorn | 后端 Web 框架 |
| Streamlit | 前端 UI 框架（旧版） |
| Vue 3 / Vite | 前端框架（新版） |
| NumPy / Pandas | 数据处理 |
| Scikit-learn / XGBoost / LightGBM | 机器学习 |
| Scapy / Pyshark | 网络包处理 |
| PyTorch | 深度学习 |
| Matplotlib / Seaborn | 可视化 |

---

## 🚀 快速开始

### 1️⃣ 创建虚拟环境（首次运行）

```powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
python -m venv venv
```

### 2️⃣ 激活虚拟环境

```powershell
.\venv\Scripts\Activate.ps1
```

> 激活成功后，命令行前缀会显示 `(venv)`

### 3️⃣ 安装所有依赖

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r .\payload-detection\requirements.txt
```

### 4️⃣ 启动系统


#### **方案 B: 手动启动前后端分离（推荐新版）**

**终端 1 - 启动后端**:
```powershell
python -m uvicorn backend.payload_api.main:app --host 127.0.0.1 --port 8010
```

**终端 2 - 启动前端**:
```powershell
cd web
npm install
npm run dev
```

访问 `http://localhost:5173`（或 Vite 显示的地址）

---

## 📡 API 文档

### 后端服务默认地址

- **Payload API**: `http://127.0.0.1:8010`
- **Swagger 文档**: `http://127.0.0.1:8010/docs`
- **ReDoc 文档**: `http://127.0.0.1:8010/redoc`

### 主要 API 端点

| 端点 | 方法 | 功能 |
|-----|------|------|
| `/health` | GET | 健康检查 |
| `/api/side-channel/analyze` | POST | 侧通道分析 |
| `/api/payload/detect` | POST | 载荷检测 |
| `/api/motion/recognize` | POST | 运动识别 |
| `/api/tasks/` | GET/POST | 任务管理 |
| `/api/auth/login` | POST | 用户登录 |

---

## 📊 功能说明

### 侧通道分析 (Side-Channel Analysis)

- **用途**: 检测网络流量中的异常行为
- **算法**: Isolation Forest
- **输入**: PCAP 文件或网络流
- **输出**: 异常分数、风险等级、详细报告

### 载荷检测 (Payload Detection)

- **用途**: 识别网络包中的恶意载荷
- **方法**: 特征工程 + 多种机器学习模型
- **支持模型**: XGBoost, LightGBM, 深度学习模型
- **输出**: 检测结果、置信度、风险类别

### 运动识别 (Motion Recognition)

- **用途**: 基于行为特征识别机器人/设备运动模式
- **支持**: 行走、跳跃、步进等运动类型
- **算法**: 序列模型、RBM 等

---

## 🛠️ 常见操作

### 添加新的 PCAP 测试数据

1. 将 `.pcap` 或 `.pcapng` 文件放入 `data/` 目录
2. 在 UI 中选择文件进行分析
3. 查看分析结果和报告

### 训练新的载荷检测模型

```powershell
cd payload-detection
python scripts/train_from_csv_improved.py --config config/mlconfig.yaml
```

### 评估模型性能

```powershell
cd payload-detection
python scripts/eval.py --model models/model.pkl --test-data data/datasets/test.csv
```

### 运行载荷检测脚本（命令行）

```powershell
cd payload-detection
python scripts/detect_from_pcap.py --pcap data/sample.pcap
```

---

## 📝 配置文件

### 主要配置位置

| 文件 | 用途 |
|-----|------|
| `payload-detection/config/mlconfig.yaml` | ML 模型配置 |
| `payload-detection/config/inference_config.yaml` | 推理配置 |
| `payload-detection/consul/mlconfig.yaml` | Consul 配置 |

### 环境变量

创建 `.env` 文件（如需要）：

```env
DATABASE_URL=sqlite:///./test.db
LOG_LEVEL=INFO
DEBUG=False
```

---

## 🐛 故障排查

### Q: 启动时提示"port 8010 already in use"

```powershell
# 查找占用 8010 端口的进程
Get-NetTCPConnection -LocalPort 8010

# 强制关闭（谨慎使用）
Stop-Process -Id <PID> -Force
```

### Q: 依赖安装失败

```powershell
# 清理 pip 缓存
pip cache purge

# 重新安装
pip install --no-cache-dir -r requirements.txt
```

### Q: Streamlit 启动但无法自动启动后端

检查 `core/payload_backend_bootstrap.py` 中的健康检查逻辑，确保后端路径正确。

### Q: PCAP 文件无法解析

- 确认文件格式为 `.pcap` 或 `.pcapng`
- 检查 Scapy 是否正确安装
- 可选：安装 TShark 提升解析能力

---

## 📚 开发指南

### 项目 Git 分支策略

- `main`: 稳定发布版本
- `dev`: 开发分支
- `feature/*`: 功能开发分支

### 代码规范

- Python: PEP 8
- JavaScript/Vue: ESLint + Prettier
- 提交前运行 `black` 格式化

### 添加新 API

1. 在 `backend/` 中创建新模块
2. 使用 FastAPI 装饰器定义路由
3. 在 `backend/payload_api/main.py` 中注册路由
4. 编写单元测试

---

## 📄 文档参考

- **Payload 检测**: 见 `payload-detection/README.md`
- **运动识别**: 见 `motion/README.md` (如存在)
- **API 文档**: `http://127.0.0.1:8010/docs`

---

## 📧 技术支持

- 项目位置: `D:\桌面\study\信安赛\RobotSecuritySystem - 副本`
- 遇到问题请检查项目 wiki 或提交 issue

---

**最后更新**: 2026 年 5 月

浏览器访问：

- http://localhost:8501

### 3.5 启动新版前后端（推荐）

先启动 FastAPI 后端：

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m uvicorn backend.payload_api.main:app --host 127.0.0.1 --port 8010
~~~

再启动 Vue 前端：

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本\web
npm install
npm run dev
~~~

浏览器访问：

- http://localhost:5173

如需修改后端地址，请在 `web/.env` 设置：

~~~text
VITE_API_BASE_URL=http://127.0.0.1:8010
~~~

首页将展示顶端导航与两个功能入口：

- 首页
- 侧信道分析
- 通信包载荷检测

页面切换方式：

- 顶部导航栏（首页 / 侧信道分析 / 通信包载荷检测）
- 首页功能入口按钮

说明：默认侧边页面导航已关闭，两个功能页仅保留侧边控制面板。

---

## 4. 使用说明

### 4.1 主检测页面

- 上传 `.pcap`
- 选择特征维度
- 点击开始审计
- 查看异常散点图、重点目标和异常清单

### 4.2 Payload-Detection 页面

- 确认后端地址为 `http://127.0.0.1:8010`
- 上传 `.pcap` 或 `.pcapng`
- 点击开始执行载荷检测
- 查看汇总指标、逐包预览
- 可下载 CSV/JSON 结果

---

## 5. 常见问题排查

### Q1: 输入 `run app.py` 报错

原因：`run` 不是 PowerShell 命令。

正确命令：

~~~powershell
python -m streamlit run app.py
~~~

### Q2: Payload 页面一直在加载

按顺序检查：

1. 启动后看侧边栏后端状态，确认是否显示“已在运行/已自动启动”
2. 页面后端地址是否正确（默认 `http://127.0.0.1:8010`）
3. 上传文件是否过大（首次检测会更慢）
4. 是否在同一个虚拟环境安装了两份依赖
5. 若提示启动超时，检查 `uvicorn` 是否已安装、8010 端口是否被占用

### Q3: Streamlit 提示 `use_container_width` 将弃用

这是兼容性提示，不是致命错误，不影响当前使用。

### Q4: 端口占用

- 后端端口 `8010` 占用：换成 `8011` 启动，并在页面里同步改地址
- 前端端口 `8501` 占用：Streamlit 启动时会提示新端口

---

## 6. 结果输出位置

Payload 后端的中间文件与结果默认写入：

- `payload-detection/data/api_runs/`

主要包含：

- 上传的 pcap/pcapng 临时文件
- 检测结果 CSV
- 汇总 JSON

---

## 7. 开发建议（可选）

- 初学阶段建议先使用一个虚拟环境，跑通全流程后再拆分双环境
- 提交前建议清理大体积临时输出文件
- 若要做双后端完全隔离，可继续把主检测逻辑也抽成 FastAPI 服务

---

## 8. 最小可运行命令清单

### 单终端启动（前端 + 自动后端）

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m streamlit run app.py
~~~

运行后打开：

- http://localhost:8501
