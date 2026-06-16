from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

import numpy as np


Protocol = Literal["all", "tcp", "udp"]
LengthMode = Literal["packet", "ip", "transport", "payload"]


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    length: int
    direction: int
    src: str
    dst: str
    protocol: str


@dataclass(frozen=True)
class TrafficSignal:
    signal: np.ndarray
    timestamps: np.ndarray
    events: tuple[PacketEvent, ...]
    bin_size: float
    duration: float
    positive_endpoint: str | None


def pcap_to_signal(
    pcap_path: str | Path,
    *,
    bin_size: float = 0.02,
    protocol: Protocol = "all",
    positive_ip: str | None = None,
    length_mode: LengthMode = "packet",
    min_packets: int = 1,
) -> TrafficSignal:
    """Convert a PCAP trace to a signed packet-length time series.

    The signal follows the paper-style directional representation:
    positive direction packets contribute +length, negative direction packets
    contribute -length within fixed-width time bins.
    """

    pcap_path = Path(pcap_path)
    events = _read_packet_events(
        pcap_path,
        protocol=protocol,
        positive_ip=positive_ip,
        length_mode=length_mode,
    )
    if len(events) < min_packets:
        raise ValueError(f"{pcap_path} has only {len(events)} matching packets")

    start = events[0].timestamp
    end = events[-1].timestamp
    duration = max(0.0, end - start)
    bins = max(1, int(np.ceil(duration / bin_size)) + 1)
    signal = np.zeros(bins, dtype=np.float64)

    for event in events:
        idx = min(bins - 1, int((event.timestamp - start) / bin_size))
        signal[idx] += event.direction * event.length

    timestamps = np.arange(bins, dtype=np.float64) * bin_size
    positive_endpoint = positive_ip or (events[0].src if events else None)
    return TrafficSignal(
        signal=signal,
        timestamps=timestamps,
        events=tuple(events),
        bin_size=bin_size,
        duration=duration,
        positive_endpoint=positive_endpoint,
    )


def signal_summary(ts: TrafficSignal) -> dict[str, float | int | str | None]:
    directions = np.array([event.direction for event in ts.events], dtype=np.int8)
    lengths = np.array([event.length for event in ts.events], dtype=np.float64)
    return {
        "packets": len(ts.events),
        "duration_sec": round(ts.duration, 6),
        "signal_bins": int(ts.signal.size),
        "bin_size_sec": ts.bin_size,
        "positive_packets": int(np.sum(directions > 0)),
        "negative_packets": int(np.sum(directions < 0)),
        "mean_packet_length": round(float(lengths.mean()), 6) if lengths.size else 0,
        "std_packet_length": round(float(lengths.std()), 6) if lengths.size else 0,
        "positive_endpoint": ts.positive_endpoint,
    }


def _read_packet_events(
    pcap_path: Path,
    *,
    protocol: Protocol,
    positive_ip: str | None,
    length_mode: LengthMode,
) -> list[PacketEvent]:
    try:
        from scapy.all import IP, TCP, UDP, PcapReader, Raw
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required to parse pcap files. Run: pip install -e ."
        ) from exc

    events: list[PacketEvent] = []
    auto_positive_ip: str | None = None

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP not in packet:
                continue

            proto = _packet_protocol(packet, TCP, UDP)
            if protocol != "all" and proto != protocol:
                continue

            src = str(packet[IP].src)
            dst = str(packet[IP].dst)
            if auto_positive_ip is None:
                auto_positive_ip = positive_ip or src

            direction = 1 if src == (positive_ip or auto_positive_ip) else -1
            length = _packet_length(packet, IP, TCP, UDP, Raw, mode=length_mode)
            events.append(
                PacketEvent(
                    timestamp=float(packet.time),
                    length=int(length),
                    direction=direction,
                    src=src,
                    dst=dst,
                    protocol=proto,
                )
            )

    events.sort(key=lambda event: event.timestamp)
    return events


def _packet_protocol(packet, TCP, UDP) -> str:
    if TCP in packet:
        return "tcp"
    if UDP in packet:
        return "udp"
    return "other"


def _packet_length(packet, IP, TCP, UDP, Raw, *, mode: LengthMode) -> int:
    if mode == "packet":
        return len(packet)
    if mode == "ip":
        return len(packet[IP])
    if mode == "transport":
        if TCP in packet:
            return len(packet[TCP])
        if UDP in packet:
            return len(packet[UDP])
        return len(packet[IP].payload)
    if mode == "payload":
        if Raw in packet:
            return len(bytes(packet[Raw].load))
        return 0
    raise ValueError(f"Unsupported length mode: {mode}")


def zscore(values: np.ndarray, *, eps: float = 1e-9) -> np.ndarray:
    values = np.asarray(values, dtype=np.float64)
    if values.size == 0:
        return values
    return (values - values.mean()) / (values.std() + eps)


def trim_silence(signal: np.ndarray, *, eps: float = 1e-9) -> np.ndarray:
    signal = np.asarray(signal, dtype=np.float64)
    active = np.flatnonzero(np.abs(signal) > eps)
    if active.size == 0:
        return signal.copy()
    return signal[active[0] : active[-1] + 1]


def pad_or_trim(signal: np.ndarray, length: int) -> np.ndarray:
    signal = np.asarray(signal, dtype=np.float64)
    if signal.size == length:
        return signal.copy()
    if signal.size > length:
        return signal[:length].copy()
    out = np.zeros(length, dtype=np.float64)
    out[: signal.size] = signal
    return out


def iter_pcaps(data_dir: str | Path) -> Iterable[tuple[str, Path]]:
    data_dir = Path(data_dir)
    suffixes = {".pcap", ".pcapng", ".cap"}
    for label_dir in sorted(path for path in data_dir.iterdir() if path.is_dir()):
        label = label_dir.name
        for path in sorted(label_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in suffixes:
                yield label, path
