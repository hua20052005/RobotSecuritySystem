from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .pcap_signal import pad_or_trim, trim_silence, zscore


@dataclass(frozen=True)
class ActionTemplate:
    label: str
    signal: np.ndarray
    sample_count: int
    length: int


def build_templates(
    labeled_signals: list[tuple[str, np.ndarray]],
    *,
    trim: bool = True,
) -> dict[str, ActionTemplate]:
    """Build one average normalized traffic template per action label."""

    by_label: dict[str, list[np.ndarray]] = {}
    for label, signal in labeled_signals:
        prepared = prepare_signal(signal, trim=trim)
        by_label.setdefault(label, []).append(prepared)

    templates: dict[str, ActionTemplate] = {}
    for label, signals in sorted(by_label.items()):
        max_len = max(sig.size for sig in signals)
        aligned = np.vstack([pad_or_trim(sig, max_len) for sig in signals])
        avg = zscore(aligned.mean(axis=0))
        templates[label] = ActionTemplate(
            label=label,
            signal=avg,
            sample_count=len(signals),
            length=int(avg.size),
        )
    return templates


def prepare_signal(signal: np.ndarray, *, trim: bool = True) -> np.ndarray:
    prepared = np.asarray(signal, dtype=np.float64)
    if trim:
        prepared = trim_silence(prepared)
    return zscore(prepared)


def save_template_preview(
    templates: dict[str, ActionTemplate],
    output_dir: str | Path,
) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for label, template in templates.items():
        np.savetxt(output_dir / f"{label}_template.csv", template.signal, delimiter=",")
