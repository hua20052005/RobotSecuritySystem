"""Matplotlib / chart colors aligned with frontend/ui_theme.py (warm paper + slate + rust)."""

from __future__ import annotations

import matplotlib.pyplot as plt

PRIMARY = "#475569"  # slate-600 — bars, main series
PRIMARY_DARK = "#334155"  # slate-700
ACCENT = "#9a3412"  # rust — emphasis, second series
MUTED = "#78716c"  # stone-500
AXIS = "#a8a29e"
GRID = "#e7e5e4"
RISK_LINE = "#b45309"  # amber-700
ALERT = "#b91c1c"  # red-700


def apply_mpl_rc() -> None:
    """Match figure styling to Streamlit surface / borders."""
    plt.rcParams.update(
        {
            "axes.facecolor": "#fafaf8",
            "figure.facecolor": "#fafaf8",
            "axes.edgecolor": "#d6d3d1",
            "axes.labelcolor": "#57534e",
            "axes.titlecolor": "#1c1917",
            "xtick.color": "#78716c",
            "ytick.color": "#78716c",
            "text.color": "#1c1917",
            "grid.color": GRID,
            "grid.alpha": 0.55,
            "axes.grid": False,
        }
    )
