from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import math

def calculate_entropy(data):
    """计算载荷信息熵：明文指令(3~5)，加密/压缩流(>7.5)"""
    if not data or len(data) == 0: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def pcap_to_dataframe(pcap_path):
    print(f"[*] 正在深度扫描流量包并建立序号索引: {pcap_path} ...")
    packets = rdpcap(pcap_path)
    rows = []
    last_time_map = {}

    # enumerate(packets, 1) 确保序号与 Wireshark 的 No. 完全一致
    for idx, pkt in enumerate(packets, 1):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            time = float(pkt.time)
            size = len(pkt)
            
            # 计算发包间隔
            interval = time - last_time_map.get(src_ip, time)
            last_time_map[src_ip] = time
            
            # 提取负载与熵值
            payload = bytes(pkt[IP].payload)
            entropy = calculate_entropy(payload)
            
            # 提取端口
            port = 0
            if TCP in pkt: port = pkt[TCP].dport
            elif UDP in pkt: port = pkt[UDP].dport

            # IP 数值化画像 (利用哈希将字符串转为特征值)
            src_num = hash(src_ip) % 10000
            dst_num = hash(dst_ip) % 10000

            rows.append({
                'idx': idx,               # 报文序号 (定位核心)
                'timestamp': time,
                'src': src_ip,
                'dst': dst_ip,
                'src_ip_num': src_num,    # 特征1
                'dst_ip_num': dst_num,    # 特征2
                'port': port,             # 特征3
                'size': size,             # 特征4
                'interval': interval,     # 特征5
                'entropy': entropy,        # 特征6
                'raw_hex_head': payload[:20].hex() # 方便肉眼预览
            })
    
    df = pd.DataFrame(rows)
    print(f"[+] 成功提取 {len(df)} 条报文。")
    return df