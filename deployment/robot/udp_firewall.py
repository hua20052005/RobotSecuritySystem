#!/usr/bin/env python3
"""
UDP Firewall for JueyingX30 HeartbeatListener (Port 43893)

原理:
  1. 启动时设置 iptables 规则: 白名单 IP 放行, 其余全部 DROP
  2. 被动嗅探监控流量, 记录所有被拦截/放行的包
  3. 支持动态添加/移除黑名单 IP
  4. 检测规则可扩展 (频率异常、命令码异常等)

无需任何第三方库, 纯 Python + iptables 基本规则。

使用方式 (在机器狗上以 root 执行):
  sudo python3 udp_firewall.py
"""

import argparse
import ipaddress
import socket
import struct
import subprocess
import sys
import time
import os
import signal
from datetime import datetime

# ═══════════════════════════════════════════════════════
#  配置
# ═══════════════════════════════════════════════════════

TARGET_PORT = 43893
LOG_FILE = "firewall.log"
CHAIN_NAME = "JUEYING_FW"

# IP 白名单 — 只有这些 IP 的包会被放行
ALLOWED_IPS = {
    "192.168.2.15",   # 官方遥控器/APP
}

class Firewall:
    def __init__(self, allowed_ips):
        self.allowed_ips = allowed_ips
        self.blocked_ips = set()
        self.pkt_accept = 0
        self.pkt_drop = 0

    def setup(self):
        """创建自定义链并设置白名单规则"""
        # 创建自定义链 (如果已存在先清理)
        self.cleanup()
        self._iptables("-N", CHAIN_NAME)

        # 白名单 IP 放行
        for ip in self.allowed_ips:
            self._iptables("-A", CHAIN_NAME, "-p", "udp", "--dport", str(TARGET_PORT), "-s", ip, "-j", "ACCEPT")
            print(f"    [+] ACCEPT {ip}")

        # 最后一条: 其余全部 DROP
        self._iptables("-A", CHAIN_NAME, "-p", "udp", "--dport", str(TARGET_PORT), "-j", "DROP")
        print(f"    [+] DROP all others")

        # 将自定义链挂到 INPUT
        self._iptables("-I", "INPUT", "-p", "udp", "--dport", str(TARGET_PORT), "-j", CHAIN_NAME)
        print(f"[+] 防火墙规则已生效\n")

    def cleanup(self):
        """清理所有防火墙规则"""
        # 从 INPUT 移除引用
        self._iptables("-D", "INPUT", "-p", "udp", "--dport", str(TARGET_PORT), "-j", CHAIN_NAME, check=False)
        # 清空并删除自定义链
        self._iptables("-F", CHAIN_NAME, check=False)
        self._iptables("-X", CHAIN_NAME, check=False)

    @staticmethod
    def _iptables(*args, check=True):
        return subprocess.run(
            ["iptables", *args],
            check=check,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def block_ip(self, ip):
        """动态拉黑一个 IP"""
        if ip not in self.blocked_ips and ip not in self.allowed_ips:
            # 在 DROP-all 规则之前插入 (位置 1 即链头部)
            self._iptables("-I", CHAIN_NAME, "-p", "udp", "--dport", str(TARGET_PORT), "-s", ip, "-j", "DROP")
            self.blocked_ips.add(ip)

    def unblock_ip(self, ip):
        """解除拉黑"""
        if ip in self.blocked_ips:
            self._iptables(
                "-D", CHAIN_NAME, "-p", "udp", "--dport", str(TARGET_PORT), "-s", ip, "-j", "DROP", check=False
            )
            self.blocked_ips.discard(ip)


# ═══════════════════════════════════════════════════════
#  检测规则引擎 (可扩展)
# ═══════════════════════════════════════════════════════

CMD_NAMES = {
    0x21040001: "HEARTBEAT",
    0x21010202: "STAND_TOGGLE",
    0x21000202: "STAND_UP",
    0x21000203: "STAND_DOWN",
    0x21000501: "SQUAT",
    0x21000406: "HEIGHT",
    0x21000300: "TROT",
    0x21000302: "BOUND",
    0x21000304: "PACE",
    0x21000306: "PRONK",
    0x21000305: "TROT_RUN",
    0x2100030A: "JOG",
    0x21000502: "BACKFLIP",
    0x21000503: "SIDEFLIP",
    0x21000504: "FLIP",
    0x2100050A: "JUMPLONG",
    0x2100050C: "JUMPHIGH",
    0x21000528: "RL_ENTER",
    0x2100052B: "RL_EXIT",
    0x21000C01: "EMERGENCY",
    0x21000C0E: "SOFT_EMERG",
    0x21000C0B: "STOP_MOVE",
}


class RuleEngine:
    """
    异常检测引擎。check() 返回 (allow, reason)。
    后续可扩展:
      - 命令码白名单
      - 频率限制 (单位时间内非心跳包数量)
      - 包长度校验
      - 危险命令限制 (空翻等需额外确认)
    """

    def __init__(self, allowed_ips):
        self.allowed_ips = allowed_ips

    def check(self, src_ip, payload):
        # 规则 1: IP 白名单
        if src_ip not in self.allowed_ips:
            return False, f"IP not in whitelist"

        # --- 后续扩展规则在此添加 ---
        return True, "OK"


# ═══════════════════════════════════════════════════════
#  网络嗅探
# ═══════════════════════════════════════════════════════

def parse_udp_from_frame(frame):
    if len(frame) < 14:
        return None
    eth_proto = struct.unpack('!H', frame[12:14])[0]
    if eth_proto != 0x0800:
        return None
    ip_hdr = frame[14:]
    if len(ip_hdr) < 20:
        return None
    ihl = (ip_hdr[0] & 0x0F) * 4
    if ip_hdr[9] != 17:
        return None
    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])
    udp_hdr = ip_hdr[ihl:]
    if len(udp_hdr) < 8:
        return None
    src_port, dst_port = struct.unpack('!HH', udp_hdr[0:4])
    payload = udp_hdr[8:]
    return src_ip, dst_ip, src_port, dst_port, payload


def decode_cmd(payload):
    if len(payload) >= 4:
        cmd = struct.unpack('<I', payload[:4])[0]
        return cmd, CMD_NAMES.get(cmd, "UNKNOWN")
    return None, "SHORT"


# ═══════════════════════════════════════════════════════
#  主逻辑
# ═══════════════════════════════════════════════════════

def main():
    global TARGET_PORT, LOG_FILE
    parser = argparse.ArgumentParser(description="UDP 43893 source whitelist firewall")
    parser.add_argument(
        "--allow-ip",
        action="append",
        dest="allowed_ips",
        help="允许访问控制端口的 IPv4 地址，可重复指定",
    )
    parser.add_argument("--port", type=int, default=TARGET_PORT)
    parser.add_argument("--log-file", default=LOG_FILE)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("端口必须在 1-65535 范围内")

    try:
        allowed_ips = {
            str(ipaddress.IPv4Address(value))
            for value in (args.allowed_ips or sorted(ALLOWED_IPS))
        }
    except ipaddress.AddressValueError as exc:
        parser.error(f"无效的白名单 IPv4 地址: {exc}")

    TARGET_PORT = args.port
    LOG_FILE = args.log_file

    if os.geteuid() != 0:
        print("[!] 需要 root 权限: sudo python3 udp_firewall.py")
        sys.exit(1)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║   JueyingX30 UDP Firewall                               ║
║   保护端口: {TARGET_PORT}                                     ║
║   白名单 IP: {', '.join(sorted(allowed_ips)):<40}║
║   日志: {LOG_FILE:<48}║
╚══════════════════════════════════════════════════════════╝
""")

    fw = Firewall(allowed_ips)
    rule_engine = RuleEngine(allowed_ips)

    print("[*] 设置 iptables 规则:")
    fw.setup()

    # raw socket 被动嗅探 (用于监控和日志)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        print("[!] raw socket 创建失败")
        fw.cleanup()
        sys.exit(1)

    log_f = open(LOG_FILE, "a")

    def shutdown(sig, frame):
        print(f"\n[*] 统计: accept={fw.pkt_accept} drop={fw.pkt_drop}")
        print(f"[*] 被拦截的 IP: {fw.blocked_ips or '无'}")
        fw.cleanup()
        print("[*] 防火墙规则已清理")
        log_f.close()
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("[*] 防火墙运行中 (Ctrl+C 停止)")
    print("[*] 白名单外的 IP 将被拦截并记录\n")

    while True:
        raw_frame, _ = sock.recvfrom(65535)
        parsed = parse_udp_from_frame(raw_frame)
        if parsed is None:
            continue

        src_ip, dst_ip, src_port, dst_port, payload = parsed
        if dst_port != TARGET_PORT:
            continue

        # 跳过心跳包的日志输出
        cmd_code, cmd_name = decode_cmd(payload)
        if cmd_code == 0x21040001:
            fw.pkt_accept += 1
            continue

        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        allow, reason = rule_engine.check(src_ip, payload)

        if allow:
            fw.pkt_accept += 1
            print(f"  \033[92m[ACCEPT]\033[0m {ts} {src_ip}:{src_port}  {cmd_name}")
        else:
            fw.pkt_drop += 1
            fw.block_ip(src_ip)
            line = f"  \033[91m[DROP]\033[0m   {ts} {src_ip}:{src_port}  {cmd_name}  ({reason})"
            print(line)
            cmd_text = f"0x{cmd_code:08X}" if cmd_code is not None else "SHORT"
            log_f.write(f"[{ts}] DROP {src_ip}:{src_port} cmd={cmd_text} {reason}\n")
            log_f.flush()


if __name__ == "__main__":
    main()
