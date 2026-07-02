# 异常连接识别防火墙部署与使用

## 文件说明

- `udp_firewall.py`：依据正常连接来源基线识别异常连接，并通过内核规则实时拦截异常访问。
- `udp_mitm_sniffer.py`：被动采集和解析 UDP 43893 流量，不执行拦截，可用于验证和留存 PCAP。
- `firewall.log`：防火墙运行后自动生成的处置日志，不需要部署到机器狗。

## 部署到机器狗

控制电脑连接机器狗 AP 后，在 PowerShell 中执行：

```powershell
ssh ysc@192.168.2.1 "mkdir -p /home/ysc/packet"

scp "C:\Users\Mojo0108\Desktop\system\RobotSecuritySystem\deployment\robot\udp_firewall.py" ysc@192.168.2.1:/home/ysc/packet/udp_firewall.py
scp "C:\Users\Mojo0108\Desktop\system\RobotSecuritySystem\deployment\robot\udp_mitm_sniffer.py" ysc@192.168.2.1:/home/ysc/packet/udp_mitm_sniffer.py

ssh ysc@192.168.2.1 "chmod 755 /home/ysc/packet/udp_firewall.py /home/ysc/packet/udp_mitm_sniffer.py"
```

验证新版本支持正常来源参数：

```powershell
ssh ysc@192.168.2.1 "/opt/robot_security/.venv/bin/python /home/ysc/packet/udp_firewall.py --help"
```

输出中应包含：

```text
--allow-ip
--port
--log-file
```

## 确定正常控制端地址

正常连接基线应使用实际发送控制指令的设备地址。当前系统后端固定使用 `192.168.2.67`，无需在前端重复填写。控制电脑连接机器狗 AP 后，可运行：

```powershell
ipconfig
```

找到连接机器狗 AP 的无线网卡 IPv4 地址。不要直接照抄脚本原来的 `192.168.2.15`，除非它确实是当前遥控器或控制端地址。

## 手工验证

SSH 进入机器狗：

```bash
cd /home/ysc/packet
sudo /opt/robot_security/.venv/bin/python udp_firewall.py --allow-ip 192.168.2.15
```

将示例地址替换为实际控制端 IP。按 `Ctrl+C` 停止后，脚本会清理 `JUEYING_FW`。

检查是否仍有残留规则：

```bash
sudo iptables -S JUEYING_FW
sudo iptables -S INPUT | grep JUEYING_FW
```

正常停止后不应存在该链或 INPUT 引用。

## 离线依赖检查

脚本只使用 Python 标准库，不需要安装 pip 软件包。机器狗需要具备：

```text
/opt/robot_security/.venv/bin/python
iptables
root/sudo 权限
Linux AF_PACKET raw socket
```

检查命令：

```bash
/opt/robot_security/.venv/bin/python --version
/opt/robot_security/.venv/bin/python /home/ysc/packet/udp_firewall.py --help
command -v iptables
sudo iptables --version
```

`python` 命令不存在并不代表没有 Python 3。不要使用 `pip install python`，pip 只能安装 Python 软件包，不能安装 Python 解释器。

## 从 RoboGuard 前端运行

1. 启动 RoboGuard 前后端并打开“系统集成防御”。
2. 填写机器狗地址、SSH 用户和密码；当前实现使用同一密码执行 sudo。
3. 点击“检查远程环境”，确认“异常连接防火墙”已就绪。
4. 在“异常连接识别防御”中填写允许控制机器狗的 IPv4 地址。
5. 点击“启动连接防御”并确认。
6. 在“运行日志”中选择“连接防火墙日志”查看被拦截来源。
7. 实验结束后点击“停止当前模式”，系统会停止进程并显式清理 iptables 规则。

异常连接防火墙、透明转发和完整防御是互斥模式。切换模式时，RoboGuard 会先停止上一模式并清理相关规则。
