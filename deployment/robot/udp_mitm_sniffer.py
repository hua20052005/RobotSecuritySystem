#!/usr/bin/env python3
"""
UDP Passive Sniffer for JueyingX30 HeartbeatListener (Port 43893)

原理:
  使用 AF_PACKET raw socket 被动嗅探所有到达 UDP:43893 的报文。
  不拦截、不重定向、不影响原始服务。无需 iptables。

使用方式 (在机器狗上以 root 执行):
  sudo python3 udp_mitm_sniffer.py
"""

import socket
import struct
import sys
import time
import os
import signal
from datetime import datetime

TARGET_PORT = 43893
LOG_FILE = "captured_packets.log"
PCAP_FILE = "captured_packets.pcap"

CMD_NAMES = {
    0x21040001: "HEARTBEAT",
    0x21000202: "STAND_UP",
    0x21000203: "STAND_DOWN",
    0x21000501: "SQUAT",
    0x21000406: "HEIGHT",
    0x21000C05: "ZERO_POS",
    0x21000D05: "TWIST_BODY",
    0x21000D06: "MOVE_MODE",
    0x21000300: "TROT",
    0x21000302: "BOUND",
    0x21000304: "PACE",
    0x21000306: "PRONK",
    0x21000305: "TROT_RUN",
    0x2100030A: "JOG",
    0x2100030C: "WALK_PG",
    0x21000401: "STAIR_TROT",
    0x21000402: "SLOPE_TROT",
    0x21000407: "HI_STAIR",
    0x21000502: "BACKFLIP",
    0x21000503: "SIDEFLIP",
    0x21000504: "FLIP",
    0x2100050A: "JUMPLONG",
    0x2100050B: "JUMPLONG2",
    0x2100050C: "JUMPHIGH",
    0x2100020E: "JUMPBACK",
    0x2100020D: "JUMPROT",
    0x21000205: "TURNOVER",
    0x21000506: "GREETING1",
    0x21000507: "GREETING2",
    0x21000508: "GREETING3",
    0x21000522: "DANCE",
    0x21000309: "DANCE2",
    0x21000521: "CUSTOM_DANCE",
    0x21000528: "RL_ENTER",
    0x2100052B: "RL_EXIT",
    0x21000529: "RL_CZ",
    0x2100052A: "RL_LSC",
    0x2100052C: "RL_HSTAND",
    0x21000C01: "EMERGENCY",
    0x21000C0E: "SOFT_EMERG",
    0x21000C0B: "STOP_MOVE",
    0x21000C06: "KEEPRUN",
}


def write_pcap_header(f):
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB


def write_pcap_packet(f, raw_frame):
    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    f.write(struct.pack('<IIII', ts_sec, ts_usec, len(raw_frame), len(raw_frame)))
    f.write(raw_frame)
    f.flush()


def decode_packet(data):
    if len(data) < 9:
        return f"[短包 len={len(data)}] raw={data.hex()}"

    cmd_code, cmd_val = struct.unpack('<II', data[:8])
    flag = data[8]
    cmd_name = CMD_NAMES.get(cmd_code, "UNKNOWN")

    result = f"cmd=0x{cmd_code:08X} ({cmd_name})  val={cmd_val}  flag={flag}"
    if len(data) > 9:
        result += f"  extra={data[9:].hex()}"
    return result



def parse_udp_from_frame(frame):
    """从以太网帧中解析 IP + UDP, 返回 (src_ip, src_port, dst_port, payload) 或 None"""
    if len(frame) < 14:
        return None
    eth_proto = struct.unpack('!H', frame[12:14])[0]
    if eth_proto != 0x0800:  # 非 IPv4
        return None

    ip_hdr = frame[14:]
    if len(ip_hdr) < 20:
        return None
    ihl = (ip_hdr[0] & 0x0F) * 4
    proto = ip_hdr[9]
    if proto != 17:  # 非 UDP
        return None

    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])

    udp_hdr = ip_hdr[ihl:]
    if len(udp_hdr) < 8:
        return None
    src_port, dst_port = struct.unpack('!HH', udp_hdr[0:4])
    payload = udp_hdr[8:]

    return src_ip, dst_ip, src_port, dst_port, payload


def main():
    verbose = "--quiet" not in sys.argv
    hide_heartbeat = "--no-hb" not in sys.argv  # 默认隐藏心跳

    print(f"""
╔══════════════════════════════════════════════════════╗
║   JueyingX30 UDP Passive Sniffer (raw socket)       ║
║   嗅探端口: {TARGET_PORT}  (被动, 不影响原始服务)        ║
║   日志: {LOG_FILE:<20}                       ║
║   PCAP: {PCAP_FILE:<20}                       ║
║   隐藏心跳: {'ON (默认)' if hide_heartbeat else 'OFF'} (--no-hb 显示心跳)          ║
╚══════════════════════════════════════════════════════╝
""")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        print("[!] 需要 root 权限: sudo python3 udp_mitm_sniffer.py")
        sys.exit(1)
    except OSError as e:
        print(f"[!] 创建 raw socket 失败: {e}")
        sys.exit(1)

    log_f = open(LOG_FILE, "a")

    pcap_exists = os.path.exists(PCAP_FILE) and os.path.getsize(PCAP_FILE) > 0
    pcap_f = open(PCAP_FILE, "ab")
    if not pcap_exists:
        write_pcap_header(pcap_f)

    pkt_count = 0

    def shutdown(sig, frame):
        print(f"\n[*] 捕获 {pkt_count} 个包, 退出...")
        log_f.close()
        pcap_f.close()
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[*] 嗅探所有到达 UDP:{TARGET_PORT} 的报文...")
    print(f"[*] Ctrl+C 停止\n")

    while True:
        raw_frame, _ = sock.recvfrom(65535)

        parsed = parse_udp_from_frame(raw_frame)
        if parsed is None:
            continue

        src_ip, dst_ip, src_port, dst_port, payload = parsed

        # 只关注目标端口
        if dst_port != TARGET_PORT:
            continue

        pkt_count += 1
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        decoded = decode_packet(payload)

        # 过滤心跳包的屏幕输出
        is_heartbeat = len(payload) >= 4 and struct.unpack('<I', payload[:4])[0] == 0x21040001
        line = f"[{ts}] #{pkt_count:>5} {src_ip}:{src_port} -> {dst_ip}:{dst_port}  len={len(payload):>4}  {decoded}"

        if verbose and not (hide_heartbeat and is_heartbeat):
            print(line)

        log_f.write(line + "\n")
        log_f.flush()

        write_pcap_packet(pcap_f, raw_frame)


if __name__ == "__main__":
    main()
