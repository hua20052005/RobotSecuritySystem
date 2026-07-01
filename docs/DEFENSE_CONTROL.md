# 系统集成防御控制台

## 功能范围

网页 `/defense` 通过后端的受控 SSH 接口管理机器狗实验环境，支持：

1. 检查远程脚本、Python 环境、进程和端口。
2. 启动透明转发对照组。
3. 启动 ET-BERT、载荷桥接、侧信道桥接和 UDP 防御代理。
4. 停止上述实验进程。
5. 向固定入口 `127.0.0.1:43894` 发送白名单测试指令。
6. 读取透明转发、防御处置、检测结果和组件日志。

网页不提供任意 Shell 输入，SSH 密码不会写入浏览器本地存储。

## 机器狗端前置文件

以下文件应部署到机器狗：

```text
/opt/robot_security/.venv/bin/python
/opt/robot_security/udp_defense_proxy.py
/opt/robot_security/etbert_payload_bridge.py
/opt/robot_security/side_channel_realtime_bridge.py
/opt/robot_security/send_robot_udp_command.py
/opt/robot_security/github_RobotSecuritySystem/backend/etbert_api/main.py
```

缺少 `send_robot_udp_command.py` 只会影响网页测试指令，不影响代理启动。缺少其他核心组件时，页面会阻止对应模式启动并列出缺失项。

## 启动系统

后端：

```powershell
cd C:\Users\Mojo0108\Desktop\system\RobotSecuritySystem
python run_backend.py
```

前端：

```powershell
cd C:\Users\Mojo0108\Desktop\system\RobotSecuritySystem\web
npm run dev
```

打开：

```text
http://127.0.0.1:5173/defense
```

## 推荐操作顺序

1. 控制电脑连接机器狗 AP。
2. 在页面填写 `192.168.2.1`、用户 `ysc` 和 SSH 密码。
3. 点击“检查环境”，确认代理、桥接和 Python 环境已就绪。
4. 先发送 `HEARTBEAT` 验证链路。
5. 对照实验点击“启动透明转发”，测试后点击“停止全部实验进程”。
6. 防御实验点击“启动完整防御”，再发送相同测试流量。
7. 刷新对应日志，对比 `FORWARD/PASS` 与 `DROP/LEVEL2/LEVEL3`。
8. 实验结束后停止全部实验进程。

完整防御固定使用机器狗本地 `http://127.0.0.1:8010`。系统会等待 ET-BERT 健康检查成功，再依次启动两个桥接和 UDP 代理。

每次启动会清空对应模式的历史日志，避免上一轮记录干扰本轮判断。若代理已进入完整防御模式但某个检测组件退出，页面会显示“完整防御（组件异常）”。

网页启动完整防御时，会为 ET-BERT API、载荷桥接、侧信道桥接和 UDP 代理分别创建独立 SSH 会话。每个会话都执行 `source /opt/robot_security/.venv/bin/activate`，与手工打开四个终端窗口的运行环境一致。

## 安全约束

- `STAND_UP` 和 `STAND_DOWN` 必须先勾选场地安全确认，并再次确认弹窗。
- 测试流量固定进入 `43894`，不会直接绕过代理发送到 `43893`。
- 透明转发会绕过检测和拦截，只用于对照实验。
- 页面不包含“注入高危结果”按钮，避免将演示注入误当成真实检测结果。
