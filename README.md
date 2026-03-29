# RobotSecuritySystem

本项目目前包含两套检测能力，并统一到一个 Streamlit 前端中：

- 主检测页面：基于 IsolationForest 的流量异常审计（原始功能）
- Payload-Detection 页面：调用独立后端服务执行载荷检测（新增功能）

两套功能互不影响：

- 页面层面：在同一个 Streamlit 里切换
- 执行层面：Payload 检测通过独立 FastAPI 后端运行

---

## 1. 项目结构（关键入口）

- `app.py`：Streamlit 主页面入口
- `pages/2_payload_detection.py`：Streamlit 第二页（Payload 检测页）
- `backends/payload_backend/main.py`：Payload 独立后端
- `requirements.txt`：根项目依赖
- `payload-detection/requirements.txt`：Payload 子项目依赖
- `payload-detection/scripts/detect_from_pcap.py`：Payload 检测脚本

---

## 2. 环境要求

- Windows + PowerShell（当前文档按 Windows 写）
- Python 3.10 及以上（建议 3.11）
- 可联网安装依赖
- 可选：Wireshark/TShark（如果后续使用 pyshark 相关能力）

---

## 3. 从零开始运行（一步一步）

以下命令都在项目根目录执行：

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
~~~

### 3.1 创建虚拟环境（首次）

~~~powershell
python -m venv venv
~~~

### 3.2 激活虚拟环境

~~~powershell
.\venv\Scripts\Activate.ps1
~~~

激活成功后，命令行前面会出现 `(venv)`。

### 3.3 安装依赖

~~~powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r .\payload-detection\requirements.txt
~~~

### 3.4 启动 Payload 独立后端（终端 A）

新开一个 PowerShell 窗口，执行：

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m uvicorn backends.payload_backend.main:app --host 127.0.0.1 --port 8010 --reload
~~~

可选健康检查（另一个终端执行）：

~~~powershell
Invoke-RestMethod http://127.0.0.1:8010/health
~~~

### 3.5 启动 Streamlit 前端（终端 B）

再开一个 PowerShell 窗口，执行：

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m streamlit run app.py
~~~

浏览器访问：

- http://localhost:8501

在左侧 Pages 导航切换页面：

- 主检测页面
- Payload-Detection 页面

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

1. Payload 后端是否已启动（终端 A 必须一直运行）
2. 页面后端地址是否正确（默认 `http://127.0.0.1:8010`）
3. 上传文件是否过大（首次检测会更慢）
4. 是否在同一个虚拟环境安装了两份依赖
5. 终端 A 是否有报错日志（优先看 uvicorn 输出）

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

### 终端 A（后端）

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m uvicorn backends.payload_backend.main:app --host 127.0.0.1 --port 8010 --reload
~~~

### 终端 B（前端）

~~~powershell
cd D:\桌面\study\信安赛\RobotSecuritySystem - 副本
.\venv\Scripts\Activate.ps1
python -m streamlit run app.py
~~~

运行后打开：

- http://localhost:8501
