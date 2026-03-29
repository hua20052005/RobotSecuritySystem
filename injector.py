from scapy.all import rdpcap, wrpcap, IP, TCP, Raw, Ether
import os

def inject_pagespy_packets(input_pcap, output_pcap, inject_time=3.0):
    print(f"[*] 正在读取原始背景流量: {input_pcap}...")
    if not os.path.exists(input_pcap):
        print(f"错误：找不到输入文件 {input_pcap}")
        return
        
    packets = rdpcap(input_pcap)
    
    if not packets:
        print("错误：Pcap 文件为空")
        return
    
    # 修正点 1: 确保获取的是第一包的绝对时间戳
    start_time = float(packets[0].time)
    print(f"[*] 背景流起始时间: {start_time}")
    
    attack_packets = []
    print(f"[*] 正在构造 10 个带有以太网层的模拟包...")
    
    for i in range(10):
        payload = '{"method":"PageSpy.get_robot_status","id":' + str(100+i) + ',"params":{}}'
        
        # 修正点 2: 必须添加 Ether() 层，否则某些 Wireshark 版本无法通过 IP 过滤
        # 同时确保 src/dst MAC 地址存在（Scapy 会默认填充）
        pkt = (Ether() / 
               IP(src="192.168.1.100", dst="10.4.0.3") / 
               TCP(sport=8888, dport=6752, flags="PA") / 
               Raw(load=payload))
        
        # 修正点 3: 绝对时间戳计算
        pkt.time = start_time + inject_time + (i * 0.1)  # 每包间隔 0.1 秒
        attack_packets.append(pkt)
    
    # 合并
    mixed_packets = list(packets) + attack_packets
    
    # 修正点 4: 严格按时间戳重新排序
    print("[*] 正在执行全量时间排序...")
    mixed_packets.sort(key=lambda x: x.time)
    
    # 导出
    wrpcap(output_pcap, mixed_packets)
    print(f"[+] 成功生成: {output_pcap}")
    print(f"[!] 注入目标 IP: 10.4.0.3, 注入时间点: 相对起始时间 {inject_time}s 处")

if __name__ == "__main__":
    # 确保路径正确
    inject_pagespy_packets("data/test.pcapng", "data/test_mixed.pcap")