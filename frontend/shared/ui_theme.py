from __future__ import annotations

from html import escape
from typing import Iterable, Sequence, Tuple

import streamlit as st

MetricItem = Tuple[str, str, str]


def apply_modern_theme() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Noto+Sans+SC:wght@400;500;600;700&display=swap');

        :root {
            --bg-main: #edf1f6;
            --bg-soft: #f6f8fb;
            --grid: rgba(16, 44, 80, 0.07);
            --surface: rgba(255, 255, 255, 0.82);
            --surface-strong: #ffffff;
            --text: #13233d;
            --muted: #5d6d86;
            --line: #c7d3e1;
            --line-strong: #97abc2;
            --primary: #0c5c74;
            --primary-2: #1f7f88;
            --accent: #b56a3f;
            --ok: #0f7b57;
            --warn: #b94b4b;
            --shadow: 0 16px 34px rgba(14, 29, 53, 0.1);
            --shadow-raise: 0 24px 48px rgba(9, 20, 40, 0.16);
        }

        .stApp {
            font-family: 'Noto Sans SC', 'Space Grotesk', sans-serif;
            color: var(--text);
            background:
                radial-gradient(1040px 520px at 5% 7%, rgba(12, 92, 116, 0.16), transparent 58%),
                radial-gradient(760px 420px at 98% 90%, rgba(181, 106, 63, 0.13), transparent 62%),
                linear-gradient(180deg, var(--bg-main) 0%, #f2f5f9 48%, var(--bg-soft) 100%);
            background-image:
                radial-gradient(1040px 520px at 5% 7%, rgba(12, 92, 116, 0.16), transparent 58%),
                radial-gradient(760px 420px at 98% 90%, rgba(181, 106, 63, 0.13), transparent 62%),
                repeating-linear-gradient(0deg, transparent 0, transparent 31px, var(--grid) 32px),
                repeating-linear-gradient(90deg, transparent 0, transparent 31px, var(--grid) 32px),
                linear-gradient(180deg, var(--bg-main) 0%, #f2f5f9 48%, var(--bg-soft) 100%);
            animation: pageIn 0.35s ease-out;
        }

        .stSidebar {
            background: linear-gradient(180deg, rgba(247, 250, 253, 0.98), rgba(240, 245, 250, 0.98));
            border-right: 1px solid rgba(63, 89, 126, 0.2);
        }

        .main .block-container {
            padding-top: 1.05rem;
            padding-bottom: 2.1rem;
            max-width: 1300px;
        }

        [data-testid="stSidebarNav"] {
            display: none !important;
        }

        [data-testid="collapsedControl"] {
            top: 0.7rem;
        }

        .main .block-container > div:first-child {
            position: sticky;
            top: 0.3rem;
            z-index: 900;
            background: rgba(251, 253, 255, 0.8);
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 0.36rem;
            margin-bottom: 1rem;
            backdrop-filter: blur(8px);
            max-width: 760px;
            margin-left: auto;
            margin-right: auto;
            box-shadow: 0 10px 20px rgba(31, 49, 80, 0.12);
        }

        .main .block-container > div:first-child .stPageLink a {
            width: 100%;
            min-height: 34px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none !important;
            color: #375174 !important;
            border-radius: 999px;
            border: 1px solid transparent;
            background: transparent;
            transition: all 0.2s ease;
            font-size: 0.86rem;
            font-weight: 700;
        }

        .main .block-container > div:first-child .stPageLink a:hover {
            border-color: var(--line);
            color: #163764 !important;
            background: #ffffff;
            transform: translateY(-1px);
        }

        .nav-active {
            width: 100%;
            min-height: 34px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            border: 1px solid var(--line-strong);
            color: #14335f;
            background: linear-gradient(130deg, rgba(245, 249, 252, 0.98), rgba(238, 246, 249, 0.95));
            font-weight: 700;
            font-size: 0.86rem;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
        }

        .control-panel-card {
            position: relative;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: linear-gradient(165deg, rgba(255, 255, 255, 0.94), rgba(248, 250, 253, 0.9));
            padding: 1rem 0.95rem 1.05rem 0.95rem;
            box-shadow: var(--shadow);
            backdrop-filter: blur(6px);
            overflow: hidden;
        }

        .control-panel-card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0.95rem;
            bottom: 0.95rem;
            width: 3px;
            border-radius: 0 3px 3px 0;
            background: linear-gradient(180deg, var(--primary), var(--primary-2), var(--accent));
        }

        .control-panel-title {
            margin: 0 0 0.55rem 0.35rem;
            font-size: 1.03rem;
            font-weight: 700;
            color: #1f365d;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .control-panel-hint {
            margin: 0 0 0.85rem 0.35rem;
            color: #657691;
            font-size: 0.84rem;
            line-height: 1.6;
        }

        .panel-group-label {
            margin: 0.7rem 0 0.35rem 0;
            color: #4d617f;
            font-size: 0.76rem;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .hero {
            position: relative;
            background: linear-gradient(150deg, rgba(255, 255, 255, 0.97), rgba(245, 249, 253, 0.92));
            border: 1px solid var(--line);
            border-radius: 22px;
            box-shadow: var(--shadow);
            padding: 1.45rem 1.65rem;
            margin-bottom: 1.1rem;
            overflow: hidden;
            animation: rise 0.34s ease-out;
        }

        .hero::after {
            content: "";
            position: absolute;
            right: -68px;
            top: -68px;
            width: 190px;
            height: 190px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(12, 92, 116, 0.18), rgba(12, 92, 116, 0));
        }

        .hero-title {
            margin: 0;
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: clamp(1.84rem, 3.2vw, 2.3rem);
            font-weight: 700;
            color: #1a3359;
            letter-spacing: 0.02em;
            position: relative;
            z-index: 1;
        }

        .hero-subtitle {
            margin-top: 0.52rem;
            color: var(--muted);
            font-size: 1rem;
            line-height: 1.75;
            position: relative;
            z-index: 1;
        }

        .metric-card {
            position: relative;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: linear-gradient(165deg, rgba(255, 255, 255, 0.98), rgba(248, 250, 253, 0.92));
            padding: 0.95rem 1rem;
            min-height: 116px;
            box-shadow: 0 10px 20px rgba(22, 37, 61, 0.1);
            animation: fadeIn 0.3s ease-out;
            overflow: hidden;
        }

        .metric-card::before {
            content: "";
            position: absolute;
            left: 0;
            right: 0;
            top: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            opacity: 0.88;
        }

        .metric-label {
            margin: 0;
            color: #5d6f89;
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .metric-value {
            margin: 0.25rem 0 0 0;
            font-size: 1.55rem;
            font-weight: 700;
            color: #19375f;
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
        }

        .metric-hint {
            margin: 0.42rem 0 0 0;
            font-size: 0.83rem;
            color: #677a97;
        }

        .status-pill {
            border: 1px solid var(--line);
            border-left: 4px solid var(--primary);
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 0.58rem 0.72rem;
            margin-bottom: 0.8rem;
            color: #304a72;
            font-size: 0.9rem;
            line-height: 1.5;
        }

        .status-pill.ok {
            border-left-color: var(--ok);
        }

        .status-pill.warn {
            border-left-color: var(--warn);
        }

        .stButton > button {
            border-radius: 11px;
            border: 1px solid rgba(22, 56, 94, 0.38);
            background: linear-gradient(132deg, rgba(22, 58, 95, 0.97), rgba(28, 88, 112, 0.95));
            color: #f5f8fc;
            font-weight: 700;
            letter-spacing: 0.03em;
            padding: 0.56rem 1rem;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            box-shadow: 0 8px 16px rgba(13, 31, 56, 0.18);
        }

        .stButton > button:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 20px rgba(10, 24, 44, 0.22);
            background: linear-gradient(132deg, rgba(18, 51, 86, 0.98), rgba(30, 99, 119, 0.96));
        }

        .stButton > button:focus {
            box-shadow: 0 0 0 0.2rem rgba(12, 92, 116, 0.22);
        }

        .stDownloadButton > button {
            border-radius: 10px;
            border: 1px solid var(--line-strong);
            background: rgba(255, 255, 255, 0.95);
            color: #21426a;
            font-weight: 700;
        }

        .stDownloadButton > button:hover {
            border-color: #7f97b3;
            background: #ffffff;
        }

        div[data-testid="stFileUploaderDropzone"] {
            border: 1px dashed #89a0ba;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.62);
            transition: border-color 0.2s ease, background 0.2s ease;
        }

        div[data-testid="stFileUploaderDropzone"]:hover {
            border-color: #597fa4;
            background: rgba(255, 255, 255, 0.78);
        }

        div[data-baseweb="input"] > div,
        div[data-baseweb="select"] > div {
            border: 1px solid var(--line) !important;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.92);
        }

        div[data-baseweb="slider"] [role="slider"] {
            background: var(--accent) !important;
            border-color: var(--accent) !important;
        }

        div[data-testid="stMetric"] {
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 0.42rem 0.65rem;
            background: rgba(255, 255, 255, 0.86);
        }

        .stDataFrame, .stTable {
            border: 1px solid var(--line);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 16px rgba(16, 31, 54, 0.08);
            background: rgba(255, 255, 255, 0.92);
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.35rem;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: rgba(252, 253, 255, 0.76);
            padding: 0.2rem;
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 9px;
            border: 1px solid transparent;
            background: transparent;
            padding: 0.42rem 0.78rem;
            color: #4c617f;
            font-weight: 700;
        }

        .stTabs [aria-selected="true"] {
            background: #ffffff;
            color: #18385f;
            border-color: var(--line);
            box-shadow: 0 8px 16px rgba(20, 37, 64, 0.12);
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 1rem;
            margin-top: 0.2rem;
            margin-bottom: 0.6rem;
        }

        .feature-card {
            border: 1px solid var(--line);
            border-radius: 16px;
            background: linear-gradient(165deg, rgba(255, 255, 255, 0.98), rgba(248, 250, 253, 0.92));
            padding: 1.12rem 1.2rem;
            box-shadow: var(--shadow);
            animation: rise 0.35s ease-out;
        }

        .feature-title {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 700;
            color: #1f3b67;
            letter-spacing: 0.1px;
        }

        .feature-desc {
            margin: 0.45rem 0 0 0;
            color: #5f7190;
            line-height: 1.68;
            font-size: 0.95rem;
        }

        .feature-meta {
            margin-top: 0.7rem;
            font-size: 0.82rem;
            color: #355a83;
            font-weight: 700;
            letter-spacing: 0.06em;
        }

        .system-note {
            margin-top: 0.8rem;
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 0.8rem 0.92rem;
            color: #596d8d;
            background: rgba(255, 255, 255, 0.82);
            font-size: 0.92rem;
            line-height: 1.62;
        }

        @keyframes rise {
            from {
                opacity: 0;
                transform: translateY(6px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        @keyframes pageIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        @media (max-width: 980px) {
            .main .block-container {
                padding-top: 0.8rem;
            }

            .hero {
                border-radius: 16px;
                padding: 1.15rem 1.15rem;
            }

            .main .block-container > div:first-child {
                border-radius: 16px;
            }

            .hero-title {
                font-size: 1.68rem;
            }

            .feature-grid {
                grid-template-columns: repeat(1, minmax(0, 1fr));
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .stApp,
            .hero,
            .metric-card,
            .feature-card,
            .stButton > button {
                animation: none !important;
                transition: none !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero(title: str, subtitle: str) -> None:
    st.markdown(
        (
            '<section class="hero">'
            f'<h1 class="hero-title">{escape(title)}</h1>'
            f'<p class="hero-subtitle">{escape(subtitle)}</p>'
            "</section>"
        ),
        unsafe_allow_html=True,
    )


def render_metric_cards(items: Sequence[MetricItem]) -> None:
    if not items:
        return

    cols = st.columns(len(items))
    for col, (label, value, hint) in zip(cols, items):
        col.markdown(
            (
                '<div class="metric-card">'
                f'<p class="metric-label">{escape(label)}</p>'
                f'<p class="metric-value">{escape(value)}</p>'
                f'<p class="metric-hint">{escape(hint)}</p>'
                "</div>"
            ),
            unsafe_allow_html=True,
        )


def render_sidebar_status(message: str, is_ok: bool) -> None:
    status_class = "ok" if is_ok else "warn"
    st.sidebar.markdown(
        f'<div class="status-pill {status_class}">{escape(message)}</div>',
        unsafe_allow_html=True,
    )


def safe_columns(df_columns: Iterable[str], desired: Sequence[str]) -> list[str]:
    existing = set(df_columns)
    return [c for c in desired if c in existing]


def render_feature_cards(items: Sequence[Tuple[str, str, str]]) -> None:
    if not items:
        return

    fragments = []
    for title, desc, meta in items:
        fragments.append(
            (
                '<article class="feature-card">'
                f'<h3 class="feature-title">{escape(title)}</h3>'
                f'<p class="feature-desc">{escape(desc)}</p>'
                f'<div class="feature-meta">{escape(meta)}</div>'
                "</article>"
            )
        )

    html = '<section class="feature-grid">' + "".join(fragments) + "</section>"
    st.markdown(html, unsafe_allow_html=True)


def render_top_nav(active: str) -> None:
    links = [
        ("首页", "app.py", "home"),
        ("侧信道分析", "pages/1_side_channel_analysis.py", "side"),
        ("通信包载荷检测", "pages/2_payload_detection.py", "payload"),
    ]

    cols = st.columns([1, 1, 1], gap="small")
    for col, (label, path, key) in zip(cols, links):
        with col:
            if key == active:
                st.markdown(f'<div class="nav-active">{escape(label)}</div>', unsafe_allow_html=True)
            else:
                st.page_link(path, label=label)
