from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .pcap_signal import pad_or_trim, zscore
from .templates import ActionTemplate, prepare_signal


@dataclass(frozen=True)
class FeatureVector:
    names: list[str]
    values: np.ndarray


def extract_features(
    signal: np.ndarray,
    templates: dict[str, ActionTemplate],
    *,
    bin_size: float,
    trim: bool = True,
) -> FeatureVector:
    """Extract template matching and generic traffic features."""

    prepared = prepare_signal(signal, trim=trim)
    names: list[str] = []
    values: list[float] = []

    generic = _generic_signal_stats(prepared, bin_size=bin_size)
    for key, value in generic.items():
        names.append(key)
        values.append(value)

    for label in sorted(templates):
        template = templates[label].signal
        corr = normalized_correlation(prepared, template)
        conv = normalized_convolution(prepared, template)

        for prefix, matched in ((f"{label}_corr", corr), (f"{label}_conv", conv)):
            stats = _matched_signal_stats(matched, bin_size=bin_size)
            for key, value in stats.items():
                names.append(f"{prefix}_{key}")
                values.append(value)

        aligned = pad_or_trim(prepared, template.size)
        distance = float(np.linalg.norm(aligned - template) / max(1, template.size))
        cosine = _cosine_similarity(aligned, template)
        names.extend([f"{label}_template_l2", f"{label}_template_cosine"])
        values.extend([distance, cosine])

    return FeatureVector(names=names, values=np.asarray(values, dtype=np.float64))


def normalized_correlation(signal: np.ndarray, template: np.ndarray) -> np.ndarray:
    signal = zscore(signal)
    template = zscore(template)
    if signal.size == 0 or template.size == 0:
        return np.zeros(1, dtype=np.float64)
    denom = (np.linalg.norm(signal) * np.linalg.norm(template)) + 1e-9
    return np.correlate(signal, template, mode="full") / denom


def normalized_convolution(signal: np.ndarray, template: np.ndarray) -> np.ndarray:
    signal = zscore(signal)
    template = zscore(template)
    if signal.size == 0 or template.size == 0:
        return np.zeros(1, dtype=np.float64)
    denom = (np.linalg.norm(signal) * np.linalg.norm(template)) + 1e-9
    return np.convolve(signal, template, mode="full") / denom


def _generic_signal_stats(signal: np.ndarray, *, bin_size: float) -> dict[str, float]:
    abs_signal = np.abs(signal)
    nonzero = np.flatnonzero(abs_signal > 1e-9)
    duration = float(signal.size * bin_size)
    active_duration = float(nonzero.size * bin_size)
    return {
        "signal_len": float(signal.size),
        "duration": duration,
        "active_duration": active_duration,
        "energy": float(np.sum(signal * signal)),
        "abs_sum": float(np.sum(abs_signal)),
        "nonzero_ratio": float(nonzero.size / max(1, signal.size)),
        "pos_bins": float(np.sum(signal > 0)),
        "neg_bins": float(np.sum(signal < 0)),
        "mean": _safe_stat(signal, "mean"),
        "std": _safe_stat(signal, "std"),
        "max": _safe_stat(signal, "max"),
        "min": _safe_stat(signal, "min"),
        "p25": _percentile(signal, 25),
        "p50": _percentile(signal, 50),
        "p75": _percentile(signal, 75),
        "skew": _skew(signal),
        "kurtosis": _kurtosis(signal),
    }


def _matched_signal_stats(values: np.ndarray, *, bin_size: float) -> dict[str, float]:
    values = np.asarray(values, dtype=np.float64)
    abs_values = np.abs(values)
    threshold = float(abs_values.mean() + abs_values.std())
    clusters = _clusters(abs_values >= threshold)
    cluster_lengths = [end - start + 1 for start, end in clusters]
    cluster_gaps = [
        clusters[idx][0] - clusters[idx - 1][1] - 1 for idx in range(1, len(clusters))
    ]
    peak_idx = int(np.argmax(abs_values)) if abs_values.size else 0

    return {
        "mean": _safe_stat(values, "mean"),
        "std": _safe_stat(values, "std"),
        "median": _percentile(values, 50),
        "p25": _percentile(values, 25),
        "p75": _percentile(values, 75),
        "max": _safe_stat(values, "max"),
        "min": _safe_stat(values, "min"),
        "abs_max": float(abs_values.max()) if abs_values.size else 0.0,
        "skew": _skew(values),
        "kurtosis": _kurtosis(values),
        "peak_pos": float(peak_idx / max(1, values.size - 1)),
        "threshold": threshold,
        "cluster_count": float(len(clusters)),
        "cluster_total_duration": float(sum(cluster_lengths) * bin_size),
        "cluster_avg_duration": float(np.mean(cluster_lengths) * bin_size)
        if cluster_lengths
        else 0.0,
        "cluster_total_span": float((clusters[-1][1] - clusters[0][0] + 1) * bin_size)
        if clusters
        else 0.0,
        "cluster_avg_gap": float(np.mean(cluster_gaps) * bin_size)
        if cluster_gaps
        else 0.0,
    }


def _clusters(mask: np.ndarray) -> list[tuple[int, int]]:
    clusters: list[tuple[int, int]] = []
    start: int | None = None
    for idx, active in enumerate(mask):
        if active and start is None:
            start = idx
        elif not active and start is not None:
            clusters.append((start, idx - 1))
            start = None
    if start is not None:
        clusters.append((start, len(mask) - 1))
    return clusters


def _cosine_similarity(left: np.ndarray, right: np.ndarray) -> float:
    denom = (np.linalg.norm(left) * np.linalg.norm(right)) + 1e-9
    return float(np.dot(left, right) / denom)


def _safe_stat(values: np.ndarray, name: str) -> float:
    if values.size == 0:
        return 0.0
    return float(getattr(np, name)(values))


def _percentile(values: np.ndarray, q: float) -> float:
    if values.size == 0:
        return 0.0
    return float(np.percentile(values, q))


def _skew(values: np.ndarray) -> float:
    if values.size < 3:
        return 0.0
    centered = values - values.mean()
    std = values.std() + 1e-9
    return float(np.mean((centered / std) ** 3))


def _kurtosis(values: np.ndarray) -> float:
    if values.size < 4:
        return 0.0
    centered = values - values.mean()
    std = values.std() + 1e-9
    return float(np.mean((centered / std) ** 4) - 3.0)
