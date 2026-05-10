"""
Motion Anomaly Detection Inference Engine

这是一个独立的推理脚本，负责：
1. 加载离线训练生成的模型参数（中心点、均值、方差、模板、阈值）
2. 对单个或多个 pcap 文件进行实时异常判定
3. 输出详细的决策报告

核心流程：
  pcap_file -> extract_features -> symbolize -> PAPB_predict -> RMB_match -> output
"""

import argparse
import csv
import json
import socket
import struct
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np


# ============================================================================
# 第一部分：基础函数（从 model_motion_sequences.py 复用）
# ============================================================================

def read_pcap_packets(path):
    """Yield packet timestamp and raw captured bytes without loading the pcap into memory."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"M<\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<M"):
            endian = ">"
        else:
            raise ValueError(f"{path} is not a classic pcap file")
        nano = magic in (b"M<\xb2\xa1", b"\xa1\xb2<M")
        scale = 1_000_000_000 if nano else 1_000_000

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            payload = f.read(incl_len)
            if len(payload) < incl_len:
                break
            yield ts_sec + ts_frac / scale, orig_len, payload


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def parse_ipv4_packet(frame):
    """Parse Ethernet + IPv4 + TCP/UDP enough for metadata features."""
    if len(frame) < 34:
        return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if eth_type == 0x8100 and len(frame) >= 38:
        eth_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if eth_type != 0x0800 or len(frame) < offset + 20:
        return None

    version_ihl = frame[offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < offset + ihl:
        return None

    proto = frame[offset + 9]
    src = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16 : offset + 20])
    src_port = None
    dst_port = None
    l4 = offset + ihl
    if proto in (6, 17) and len(frame) >= l4 + 4:
        src_port, dst_port = struct.unpack("!HH", frame[l4 : l4 + 4])
    return {
        "proto": proto,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def packet_allowed(meta, include_ports=None, exclude_ports=None):
    if not meta:
        return False
    ports = {p for p in (meta["src_port"], meta["dst_port"]) if p is not None}
    if include_ports and not ports.intersection(include_ports):
        return False
    if exclude_ports and ports.intersection(exclude_ports):
        return False
    return True


def extract_window_features(path, local_ips, window_ms=100, include_ports=None, exclude_ports=None):
    """提取窗口特征（关键：使用前置的 local_ips）"""
    window_s = window_ms / 1000.0
    windows = defaultdict(lambda: {
        "pkt_count": 0,
        "byte_count": 0,
        "up_pkt_count": 0,
        "down_pkt_count": 0,
        "up_bytes": 0,
        "down_bytes": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "small_count": 0,
        "large_count": 0,
        "sizes": [],
        "times": [],
    })
    first_ts = None
    raw_packets = 0
    kept_packets = 0

    for ts, length, frame in read_pcap_packets(path):
        raw_packets += 1
        meta = parse_ipv4_packet(frame)
        if not packet_allowed(meta, include_ports, exclude_ports):
            continue
        kept_packets += 1
        if first_ts is None:
            first_ts = ts
        idx = int((ts - first_ts) / window_s)
        w = windows[idx]
        w["pkt_count"] += 1
        w["byte_count"] += length
        if meta["src"] in local_ips and meta["dst"] not in local_ips:
            direction = "up"
        elif meta["dst"] in local_ips and meta["src"] not in local_ips:
            direction = "down"
        elif ip_to_int(meta["src"]) <= ip_to_int(meta["dst"]):
            direction = "up"
        else:
            direction = "down"
        w[f"{direction}_pkt_count"] += 1
        w[f"{direction}_bytes"] += length
        if meta["proto"] == 6:
            w["tcp_count"] += 1
        elif meta["proto"] == 17:
            w["udp_count"] += 1
        if length <= 128:
            w["small_count"] += 1
        if length >= 1000:
            w["large_count"] += 1
        w["sizes"].append(length)
        w["times"].append(ts)

    rows = []
    if not windows:
        return rows, {"raw_packets": raw_packets, "kept_packets": kept_packets, "duration_s": 0}

    max_idx = max(windows)
    for idx in range(max_idx + 1):
        w = windows[idx]
        sizes = w["sizes"]
        times = w["times"]
        iats = np.diff(times) * 1000 if len(times) > 1 else np.array([0.0])
        pkt_count = w["pkt_count"]
        rows.append({
            "window_idx": idx,
            "t_start_s": idx * window_s,
            "pkt_count": pkt_count,
            "byte_count": w["byte_count"],
            "up_pkt_count": w["up_pkt_count"],
            "down_pkt_count": w["down_pkt_count"],
            "up_bytes": w["up_bytes"],
            "down_bytes": w["down_bytes"],
            "tcp_count": w["tcp_count"],
            "udp_count": w["udp_count"],
            "small_count": w["small_count"],
            "large_count": w["large_count"],
            "mean_len": float(np.mean(sizes)) if sizes else 0.0,
            "std_len": float(np.std(sizes)) if sizes else 0.0,
            "mean_iat_ms": float(np.mean(iats)) if pkt_count else 0.0,
            "std_iat_ms": float(np.std(iats)) if pkt_count else 0.0,
            "byte_rate": float(w["byte_count"] / window_s) if window_s else 0.0,
            "direction_balance": float((w["up_pkt_count"] - w["down_pkt_count"]) / max(pkt_count, 1)),
            "len_cv": float(np.std(sizes) / max(np.mean(sizes), 1.0)) if sizes else 0.0,
            "iat_cv": float(np.std(iats) / max(np.mean(iats), 1.0)) if pkt_count else 0.0,
            "small_ratio": float(w["small_count"] / max(pkt_count, 1)),
            "large_ratio": float(w["large_count"] / max(pkt_count, 1)),
        })
    duration_s = (max_idx + 1) * window_s
    return rows, {"raw_packets": raw_packets, "kept_packets": kept_packets, "duration_s": duration_s}


FEATURE_COLUMNS = [
    "pkt_count", "byte_count", "up_pkt_count", "down_pkt_count", "up_bytes", "down_bytes",
    "tcp_count", "udp_count", "small_count", "large_count", "mean_len", "std_len",
    "mean_iat_ms", "std_iat_ms", "byte_rate", "direction_balance", "len_cv", "iat_cv",
    "small_ratio", "large_ratio",
]


def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def sequence_similarity(a, b):
    denom = max(len(a), len(b), 1)
    return 1.0 - levenshtein(a, b) / denom


def compress_sequence(labels, max_run=3):
    seq = []
    last = None
    run = 0
    for label in labels:
        token = chr(ord("A") + int(label))
        if token == last:
            run += 1
            if run <= max_run:
                seq.append(token)
        else:
            last = token
            run = 1
            seq.append(token)
    return "".join(seq)


# ============================================================================
# 第二部分：模型加载器 - 这是推理与训练的核心分离点
# ============================================================================

class MotionAnomalyModel:
    """
    离线训练的模型容器。一旦初始化，参数就被冻结。
    这确保每个推理都使用同一套参考基准。
    """
    
    def __init__(self, model_dir):
        """
        Args:
            model_dir: 包含以下文件的目录（由 model_motion_sequences.py 生成）
              - model_params.npz: centroids, mean, std
              - action_templates.csv: 黄金模板
              - leave_one_out_template_scores.csv: 阈值和其他元数据
              - task_transition_graph.csv: 动作转移图
        """
        self.model_dir = Path(model_dir)
        
        # 加载 K-Means 参数（这些是固定的、不再更新的）
        params = np.load(self.model_dir / "model_params.npz")
        self.centroids = params["centroids"]  # shape: (k, num_features)
        self.mu = params["mean"]              # shape: (num_features,)
        self.sigma = params["std"]            # shape: (num_features,)
        self.k = len(self.centroids)
        
        # 加载动作模板（每个动作的"正常"代表序列）
        self.templates = self._load_templates()
        
        # 加载每个动作的异常阈值
        self.action_thresholds = self._load_thresholds()
        
        # 加载动作转移图（允许的后继动作）
        self.adjacency = self._load_adjacency()
        
        print(f"✓ 模型已加载: {len(self.templates)} 个动作模板")
        print(f"✓ 动作转移图: {len(self.adjacency)} 个转移规则")

    def _load_templates(self):
        """Load action templates from CSV"""
        templates = {}
        with open(self.model_dir / "action_templates.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row["label"]
                if label not in templates:
                    templates[label] = []
                templates[label].append({
                    "template_sequence": row["template_sequence"],
                    "template_sample": row["template_sample"],
                    "template_rank": int(row["template_rank"]),
                    "template_length": int(row["template_length"]),
                    "action_avg_length": float(row["action_avg_length"]),
                    "template_similarity": float(row["template_similarity"]),
                    "template_support": int(row["template_support"]),
                })
        return templates

    def _load_thresholds(self):
        """Load per-action anomaly thresholds"""
        thresholds = {}
        with open(self.model_dir / "leave_one_out_template_scores.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            seen = set()
            for row in reader:
                label = row["label"]
                if label not in seen:
                    thresholds[label] = float(row.get("action_threshold", 0.5))
                    seen.add(label)
        return thresholds

    def _load_adjacency(self):
        """Load action adjacency (legal next actions)"""
        adjacency = defaultdict(set)
        with open(self.model_dir / "task_transition_graph.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                prefix = row["prefix"]
                next_action = row["next_action"]
                # 简化处理：如果 prefix 为空，说明是开始状态
                if prefix:
                    # 提取最后一个动作作为当前状态
                    actions = prefix.split("->")
                    if actions[-1]:
                        adjacency[actions[-1]].add(next_action)
        
        # 如果没有显式的转移图，构建简单的全连接
        if not adjacency:
            labels = list(self.templates.keys())
            for label in labels:
                adjacency[label] = set(labels) - {label}
        
        return {k: sorted(v) for k, v in adjacency.items()}

    def symbolize(self, feature_row):
        """
        将一个窗口特征向量映射到符号 (A, B, C, ...)
        
        这是推理与训练的第一个关键分离点：
        - 训练：动态计算中心点
        - 推理：使用固定的 self.centroids
        """
        x = np.array([feature_row[col] for col in FEATURE_COLUMNS], dtype=float)
        
        # 使用离线保存的均值和方差进行标准化
        x_normalized = np.log1p(x)
        x_standardized = (x_normalized - self.mu) / (self.sigma + 1e-8)
        
        # 使用离线保存的中心点进行分配
        distances = ((x_standardized - self.centroids) ** 2).sum(axis=1)
        cluster = int(distances.argmin())
        
        return chr(ord("A") + cluster)

    def predict_valid_next_actions(self, executed_sequence, start_actions=None):
        """
        PAPB 逻辑：预测当前合法的后继动作
        （这部分与 model_motion_sequences.py 的 predict_valid_next_actions 相同）
        """
        start_actions = set(start_actions or [])
        cleaned = [action for action in executed_sequence if action]
        if not cleaned:
            return start_actions, set(), 0

        n = len(cleaned)
        dp = [1] * n
        subseq_actions = [{action} for action in cleaned]

        for i in range(1, n):
            for j in range(i):
                yi, yj = cleaned[i], cleaned[j]
                if yi in self.adjacency.get(yj, []):
                    candidate_len = dp[j] + 1
                    candidate_actions = subseq_actions[j] | {yi}
                    if candidate_len > dp[i]:
                        dp[i] = candidate_len
                        subseq_actions[i] = candidate_actions
                    elif candidate_len == dp[i]:
                        subseq_actions[i] |= candidate_actions

        max_len = max(dp)
        matched_actions = set()
        for i, length in enumerate(dp):
            if length == max_len:
                matched_actions |= subseq_actions[i]

        valid_next = set()
        for action in matched_actions:
            valid_next |= set(self.adjacency.get(action, []))
        valid_next -= matched_actions
        return valid_next, matched_actions, max_len

    def best_template_match(self, sequence, label):
        """RMB：找到最相似的模板"""
        if label not in self.templates:
            return None
        
        scored = [
            {
                "template": template,
                "similarity": sequence_similarity(sequence, template["template_sequence"]),
            }
            for template in self.templates[label]
        ]
        if not scored:
            return None
        return max(scored, key=lambda item: item["similarity"])


# ============================================================================
# 第三部分：推理引擎核心
# ============================================================================

class InferenceEngine:
    """
    实时推理引擎：将单个 pcap 转换为异常判定
    
    核心流程：
      1. 提取窗口特征
      2. 符号化为动作序列
      3. PAPB 动作预测（验证转移合理性）
      4. RMB 模板匹配（验证内容相似性）
      5. 逐步决策输出
    """
    
    def __init__(self, model_dir, local_ips=None, window_ms=100, exclude_ports=None, enable_papb=True):
        self.model = MotionAnomalyModel(model_dir)
        self.window_ms = window_ms
        self.exclude_ports = exclude_ports or {22}
        self.enable_papb = enable_papb
        
        # 关键：local_ips 必须从训练时推导，这里假设已知
        self.local_ips = local_ips or {"192.168.1.10"}
        
        # 用于跨文件的动作链追踪（可选）
        self.action_sequence = []  # 已执行的动作列表
        self.violations = []  # 记录的违规

    def detect_from_pcap(self, pcap_path):
        """
        对单个 pcap 文件进行完整异常检测
        
        核心流程：
        1. RMB（模板匹配）：检查序列是否与某个动作相似
        2. PAPB（动作转移验证）：检查该动作是否是合法的后继[可选]
        
        返回：{
            "status": "NORMAL" | "ANOMALY",
            "confidence": 0.0-1.0,
            "details": {...}
        }
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            return {"status": "ERROR", "error": f"File not found: {pcap_path}"}
        
        print(f"\n📊 开始分析: {pcap_path.name}")
        
        # 第一步：特征提取
        feature_rows, metadata = extract_window_features(
            pcap_path,
            self.local_ips,
            self.window_ms,
            exclude_ports=self.exclude_ports
        )
        
        if not feature_rows:
            return {
                "status": "NO_DATA",
                "error": "No valid IPv4 packets found in pcap"
            }
        
        print(f"  ✓ 提取了 {len(feature_rows)} 个时间窗口")
        
        # 第二步：符号化
        symbols = [self.model.symbolize(row) for row in feature_rows]
        compressed_seq = compress_sequence([ord(s) - ord("A") for s in symbols])
        
        print(f"  ✓ 动作序列: {compressed_seq}")
        
        # 第三步：RMB 模板匹配（符号序列级别的异常检测）
        # 策略：检查该序列是否与任何动作的模板相似度满足该动作的判定条件
        # 
        # 阈值理解：threshold 是针对 anomaly_score 的
        #   anomaly_score = 1.0 - similarity
        #   是否异常 = (1.0 - similarity) > threshold
        #          = similarity < (1.0 - threshold)
        
        match_results = []
        for label, templates_list in self.model.templates.items():
            threshold = self.model.action_thresholds.get(label, 0.5)
            best_sim = 0.0
            best_template = None
            
            for template in templates_list:
                sim = sequence_similarity(compressed_seq, template["template_sequence"])
                if sim > best_sim:
                    best_sim = sim
                    best_template = template
            
            # 判定：相似度是否足够高（即 anomaly_score 是否足够低）
            # is_match = (1.0 - best_sim) <= threshold
            # 等价于 = best_sim >= (1.0 - threshold)
            similarity_threshold = 1.0 - threshold
            is_match = best_sim >= similarity_threshold
            
            match_results.append({
                "label": label,
                "best_similarity": best_sim,
                "anomaly_score": 1.0 - best_sim,
                "anomaly_threshold": threshold,
                "similarity_threshold": similarity_threshold,
                "best_template": best_template,
                "is_match": is_match
            })
        
        # 找到所有匹配的动作和最接近的匹配
        matched_labels = [r["label"] for r in match_results if r["is_match"]]
        best_match = max(match_results, key=lambda x: x["best_similarity"])
        
        # 第四步：PAPB 动作转移验证（可选）
        papb_violations = []
        papb_decision = "PASS"
        
        if self.enable_papb and matched_labels:
            # 获得该文件的主要动作标签
            primary_action = best_match["label"]
            
            # 使用PAPB验证这个动作是否是合法的后继
            valid_next_actions, executed_actions, max_len = self.model.predict_valid_next_actions(
                self.action_sequence
            )
            
            print(f"  📋 当前动作链: {' → '.join(self.action_sequence or ['(起始)'])}")
            print(f"    已执行最长子序列长度: {max_len}")
            print(f"    合法的后继动作: {valid_next_actions or '(任意动作)'}")
            
            # 检查该动作是否合法
            is_valid_successor = (not valid_next_actions) or (primary_action in valid_next_actions)
            
            if not is_valid_successor:
                papb_violations.append({
                    "reason": f"'{primary_action}' is not a legal next action",
                    "expected": sorted(valid_next_actions),
                    "actual": primary_action
                })
                papb_decision = "REJECT"
            
            # 更新动作链
            if is_valid_successor:
                self.action_sequence.append(primary_action)
                print(f"  ✅ 动作序列扩展: {' → '.join(self.action_sequence)}")
            else:
                print(f"  ⚠️  动作转移违规: {primary_action} 不在合法后继中")
        
        # 综合判定
        is_normal = len(matched_labels) > 0  # RMB: 至少匹配一个动作
        if self.enable_papb:
            is_normal = is_normal and papb_decision == "PASS"  # 同时通过PAPB
        
        is_anomaly = not is_normal
        
        # 生成详细报告
        template_violations = []
        if not matched_labels:
            # 如果没有匹配任何动作，列出所有未通过的模板
            for result in match_results:
                template_violations.append({
                    "label": result["label"],
                    "best_similarity": float(result["best_similarity"]),
                    "anomaly_score": float(result["anomaly_score"]),
                    "anomaly_threshold": float(result["anomaly_threshold"]),
                    "reason": f"RMB mismatch: similarity {result['best_similarity']:.3f} < threshold {result['similarity_threshold']:.3f}"
                })
        
        # 第五步：生成最终判定
        # 置信度：最接近的匹配与其阈值的距离
        margin = best_match["best_similarity"] - best_match["similarity_threshold"]
        confidence = abs(margin)  # 离边界有多远
        
        result = {
            "status": "ANOMALY" if is_anomaly else "NORMAL",
            "confidence": float(confidence),
            "details": {
                "pcap_file": str(pcap_path),
                "raw_packets": metadata["raw_packets"],
                "kept_packets": metadata["kept_packets"],
                "duration_s": metadata["duration_s"],
                "action_sequence": compressed_seq,
                "sequence_length": len(compressed_seq),
                "primary_action": best_match["label"],
                "matched_actions": matched_labels,
                "matches": [
                    {
                        "label": r["label"],
                        "best_similarity": float(r["best_similarity"]),
                        "anomaly_score": float(r["anomaly_score"]),
                        "anomaly_threshold": float(r["anomaly_threshold"]),
                        "similarity_threshold": float(r["similarity_threshold"]),
                        "passed": r["is_match"]
                    }
                    for r in match_results
                ],
                "rbm_anomalies": template_violations,
                "papb_anomalies": papb_violations if self.enable_papb else [],
                "papb_enabled": self.enable_papb,
                "papb_decision": papb_decision if self.enable_papb else "DISABLED"
            }
        }
        
        return result
    
    def reset_action_sequence(self):
        """重置动作链追踪（用于分析新的任务流程）"""
        self.action_sequence = []
        self.violations = []
        print("🔄 动作序列已重置")


# ============================================================================
# 第四部分：CLI 接口
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Motion Anomaly Detection - Inference Engine"
    )
    parser.add_argument(
        "--model-dir",
        required=True,
        help="Directory containing pre-trained model (output of model_motion_sequences.py)"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="PCAP file to analyze (for single file) or directory with .pcap files"
    )
    parser.add_argument(
        "--local-ips",
        default="192.168.1.10",
        help="Comma-separated local IPs (used during training)"
    )
    parser.add_argument(
        "--window-ms",
        type=int,
        default=100,
        help="Window size in milliseconds (must match training)"
    )
    parser.add_argument(
        "--enable-papb",
        action="store_true",
        default=False,
        help="Enable PAPB (action transition coherence checking) for multi-pcap sequences"
    )
    parser.add_argument(
        "--output",
        default="inference_results.json",
        help="Output file for results"
    )
    
    args = parser.parse_args()
    
    # 初始化推理引擎
    local_ips = set(args.local_ips.split(","))
    engine = InferenceEngine(
        args.model_dir,
        local_ips=local_ips,
        window_ms=args.window_ms,
        enable_papb=args.enable_papb
    )
    
    # 处理输入
    pcap_path = Path(args.pcap)
    results = []
    
    if pcap_path.is_file() and pcap_path.suffix.lower() == ".pcap":
        # 单个文件
        result = engine.detect_from_pcap(pcap_path)
        results.append(result)
    elif pcap_path.is_dir():
        # 目录
        pcap_files = sorted(pcap_path.glob("**/*.pcap"))
        if args.enable_papb:
            print(f"\n🔗 启用连贯检测模式：将验证多个PCAP文件间的动作转移合理性\n")
        for pcap_file in pcap_files:
            result = engine.detect_from_pcap(pcap_file)
            results.append(result)
    else:
        print(f"❌ Invalid path: {pcap_path}")
        return
    
    # 输出结果
    output_file = Path(args.output)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\n✅ 分析完成")
    print(f"  总共处理: {len(results)} 个文件")
    anomalies = [r for r in results if r.get("status") == "ANOMALY"]
    print(f"  异常检测: {len(anomalies)} 个")
    print(f"  结果保存: {output_file.resolve()}")
    
    # 打印摘要
    for result in results:
        pcap_name = Path(result["details"]["pcap_file"]).name
        status = result["status"]
        confidence = result["confidence"]
        primary_action = result["details"].get("primary_action", "?")
        print(f"\n  {pcap_name:30} -> {status:10} ({primary_action:6}) confidence: {confidence:.3f}")
        
        # 显示PAPB异常
        if result["details"].get("papb_anomalies"):
            for anomaly in result["details"]["papb_anomalies"]:
                print(f"    ⚠️  {anomaly['reason']}")
        
        # 显示RMB异常
        if result["details"].get("rbm_anomalies"):
            for anomaly in result["details"]["rbm_anomalies"][:2]:  # 只显示前两个
                print(f"    💥 {anomaly['reason']}")


if __name__ == "__main__":
    main()
