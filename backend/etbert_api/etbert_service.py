"""ET-BERT 推理服务 —— 加载模型驻留内存，提供 detect_pcap() 接口。"""

from __future__ import annotations

import collections, importlib.util, logging, os, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import numpy as np
import scapy.all as scapy
import torch, torch.nn as nn

logger = logging.getLogger(__name__)

# ── 路径 ────────────────────────────────────────────
_ETBERT_ROOT = Path(__file__).resolve().parents[2] / "ET-BERT-main"
_FINETUNE_DIR = _ETBERT_ROOT / "fine-tuning"

sys.path.insert(0, str(_ETBERT_ROOT))
sys.path.insert(0, str(_FINETUNE_DIR))

from uer.utils.constants import CLS_TOKEN
from uer.utils import str2tokenizer
from uer.utils.config import load_hyperparam
from uer.model_loader import load_model as uer_load_model
from uer.opts import infer_opts

# ── 常量 ────────────────────────────────────────────
PAD_LEN     = 12            # 12B 控制指令协议
SEQ_LEN     = 32            # 流级窗口 32 包
FLOW_GAP_MS = 500.0

PACKET_LABELS = {
    0: "正常", 1: "指令码异常", 2: "参数值异常", 3: "格式违规",
}
FLOW_LABELS = {
    0: "正常流", 1: "注入流异常", 2: "速率泛洪",
    3: "方向振荡", 4: "指令码扫描",
}

MODEL_DEFS = {
    "packet": {
        "model_file": "packet_finetune.bin",
        "labels_num": 4, "labels": PACKET_LABELS,
        "type": "packet",
    },
    "flow": {
        "model_file": "flow_finetune.bin",
        "labels_num": 5, "labels": FLOW_LABELS,
        "type": "flow",
        "sampling": {"bytes_per_pkt": 12},
    },
}


def _load_classifier():
    """动态加载 fine-tuning/run_classifier.py 中的 Classifier 类"""
    path = _FINETUNE_DIR / "run_classifier.py"
    spec = importlib.util.spec_from_file_location("et_bert_run_classifier", path)
    if spec is None or spec.loader is None:
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Classifier


Classifier = _load_classifier()


@dataclass
class DetectionResult:
    model_type: str
    total_samples: int
    predictions: list[dict]            # per-sample: {label_id, label_name, confidence, all_probs}
    summary: dict[str, int]           # label_name → count
    abnormal_ratio: float
    proto_stats: dict                 # protocol distribution, ports, sizes


class ETBertService:
    """ET-BERT 推理服务，模型常驻内存"""

    def __init__(self):
        self._models: dict[str, object] = {}
        self._args_cache: dict[str, object] = {}
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"ETBertService device: {self._device}")

    @property
    def available_models(self) -> list[str]:
        return list(MODEL_DEFS)

    def _build_args(self, key: str):
        import argparse
        cfg = MODEL_DEFS[key]
        parser = argparse.ArgumentParser()
        infer_opts(parser)
        args = parser.parse_args(["--test_path", "_x.tsv", "--prediction_path", "_x.txt"])
        args.load_model_path = str(_ETBERT_ROOT / "models" / cfg["model_file"])
        args.vocab_path       = str(_ETBERT_ROOT / "models" / "encryptd_vocab.txt")
        args.config_path      = str(_ETBERT_ROOT / "models" / "bert_base_config.json")
        args.spm_model_path   = None
        args.labels_num       = cfg["labels_num"]
        args.embedding        = "word_pos_seg"
        args.encoder          = "transformer"
        args.mask             = "fully_visible"
        args.pooling          = "first"
        args.tokenizer        = "bert"
        args.batch_size       = 32
        args.seq_length       = 512
        args.soft_targets     = False
        args.soft_alpha       = False
        args = load_hyperparam(args)
        args.tokenizer = str2tokenizer["bert"](args)
        return args

    def load_model(self, key: str):
        if key in self._models:
            return
        cfg = MODEL_DEFS[key]
        args = self._build_args(key)
        model = Classifier(args)
        model = uer_load_model(model, args.load_model_path)
        model = model.to(self._device)
        model.eval()
        self._models[key] = model
        self._args_cache[key] = args
        logger.info(f"Loaded {cfg['model_file']} → {self._device}")

    def _encode_texts(self, key: str, texts: list[str]):
        args = self._args_cache[key]
        dataset = []
        for text_a in texts:
            tokens = [CLS_TOKEN] + args.tokenizer.tokenize(text_a)
            src = args.tokenizer.convert_tokens_to_ids(tokens)
            seg = [1] * len(src)
            sl = args.seq_length
            if len(src) > sl: src, seg = src[:sl], seg[:sl]
            while len(src) < sl: src.append(0); seg.append(0)
            dataset.append((src, seg))
        return dataset

    def _predict(self, key: str, texts: list[str]) -> list[dict]:
        model = self._models[key]
        args  = self._args_cache[key]
        labels = MODEL_DEFS[key]["labels"]
        ds = self._encode_texts(key, texts)
        src = torch.LongTensor([s[0] for s in ds])
        seg = torch.LongTensor([s[1] for s in ds])
        results = []
        for i in range(0, len(ds), args.batch_size):
            sb = src[i:i+args.batch_size].to(self._device)
            sg = seg[i:i+args.batch_size].to(self._device)
            with torch.no_grad():
                _, logits = model(sb, None, sg)
            probs = nn.Softmax(dim=1)(logits)
            preds = torch.argmax(probs, dim=1)
            for j in range(len(preds)):
                pid = int(preds[j])
                prob = float(probs[j][pid])
                results.append({
                    "pred_label": pid,
                    "pred_name": labels.get(pid, str(pid)),
                    "confidence": round(prob * 100, 2),
                    "all_probs": {labels.get(k, str(k)): round(float(probs[j][k]) * 100, 2)
                                  for k in range(args.labels_num)},
                })
        return results

    # ── pcap 解析 ────────────────────────────────────
    def _parse_pcap(self, pcap_path: str, max_pkts: int):
        """解析 pcap，返回 (payloads, timestamps, proto_stats)"""
        payloads, timestamps = [], []
        proto_counts = {"UDP": 0, "TCP": 0, "Other": 0}
        port_counts = collections.Counter()
        size_dist = []
        skipped_non_udp = 0
        skipped_empty = 0
        total_read = 0

        for i, pkt in enumerate(scapy.PcapReader(pcap_path)):
            if i >= max_pkts: break
            total_read += 1

            # 协议统计
            if pkt.haslayer(scapy.UDP):
                proto_counts["UDP"] += 1
                port_counts[pkt[scapy.UDP].dport] += 1
            elif pkt.haslayer(scapy.TCP):
                proto_counts["TCP"] += 1
                port_counts[pkt[scapy.TCP].dport] += 1
                skipped_non_udp += 1
                continue
            else:
                proto_counts["Other"] += 1
                skipped_non_udp += 1
                continue

            try:
                pl = bytes(pkt[scapy.Raw].load) if pkt.haslayer(scapy.Raw) else bytes(pkt[scapy.UDP].payload)
            except Exception:
                skipped_non_udp += 1
                continue
            if len(pl) == 0:
                skipped_empty += 1
                continue
            original_len = len(pl)
            size_dist.append(original_len)
            pl = pl + b"\x00" * (PAD_LEN - len(pl)) if len(pl) < PAD_LEN else pl[:PAD_LEN]
            payloads.append(np.frombuffer(pl, dtype=np.uint8))
            timestamps.append(float(pkt.time))

        # 包大小分布统计
        size_bins = {"<50B": 0, "50-200B": 0, "200-380B": 0, "=380B": 0, ">380B": 0}
        for s in size_dist:
            if s < 50: size_bins["<50B"] += 1
            elif s < 200: size_bins["50-200B"] += 1
            elif s < 380: size_bins["200-380B"] += 1
            elif s == 380: size_bins["=380B"] += 1
            else: size_bins[">380B"] += 1

        proto_stats = {
            "total_read": total_read,
            "udp_with_payload": len(payloads),
            "skipped_non_udp": skipped_non_udp,
            "skipped_empty": skipped_empty,
            "protocol_distribution": dict(proto_counts),
            "top_ports": dict(port_counts.most_common(5)),
            "payload_size_distribution": size_bins,
        }
        return payloads, timestamps, proto_stats

    def _pkt_to_bigram(self, p: np.ndarray) -> str:
        hs = p.astype(np.uint8).tobytes().hex()
        return " ".join(hs[i:i+2] for i in range(0, len(hs), 2))

    def _flow_to_bigram(self, seq: np.ndarray, bytes_per_pkt: int = 12) -> str:
        bigrams = []
        for pkt in seq:
            hs = pkt[:bytes_per_pkt].astype(np.uint8).tobytes().hex()
            bigrams.extend([hs[i:i+2] for i in range(0, len(hs), 2)])
        return " ".join(bigrams)

    # ── 公开接口 ──────────────────────────────────────
    def detect_pcap(self, key: str, pcap_path: str, max_packets: int = 5000) -> DetectionResult:
        cfg = MODEL_DEFS[key]
        self.load_model(key)
        labels = cfg["labels"]
        payloads, timestamps, proto_stats = self._parse_pcap(pcap_path, max_packets)

        if cfg["type"] == "packet":
            texts = [self._pkt_to_bigram(p) for p in payloads]
            preds = self._predict(key, texts)
        else:
            # 流级：32 包窗口 × 12 字节/包
            sampling = cfg.get("sampling", {})
            bpp = sampling.get("bytes_per_pkt", 12)
            flows = self._segment_flows(timestamps, payloads)
            texts, meta = [], []
            for fid, (s, e) in enumerate(flows):
                arr = np.stack(payloads[s:e], axis=0)
                for w in range(0, arr.shape[0] - SEQ_LEN + 1, 8):
                    texts.append(self._flow_to_bigram(arr[w:w+SEQ_LEN], bpp))
                    meta.append(fid)
            preds = self._predict(key, texts)

        summary = collections.Counter(r["pred_label"] for r in preds)
        abnormal = sum(v for k, v in summary.items() if k != 0)
        return DetectionResult(
            model_type=key,
            total_samples=len(preds),
            predictions=preds,
            summary={labels.get(k, str(k)): v for k, v in summary.items()},
            abnormal_ratio=round(abnormal / len(preds) * 100, 2) if preds else 0.0,
            proto_stats=proto_stats,
        )

    def _segment_flows(self, timestamps, payloads):
        flows, start = [], 0
        for i in range(1, len(timestamps)):
            if (timestamps[i] - timestamps[i-1]) * 1000 > FLOW_GAP_MS:
                if i - start >= SEQ_LEN:
                    flows.append((start, i))
                start = i
        if len(timestamps) - start >= SEQ_LEN:
            flows.append((start, len(timestamps)))
        return flows


# 全局单例
etbert = ETBertService()
