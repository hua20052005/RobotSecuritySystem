from __future__ import annotations

from html import escape
from typing import Iterable, Sequence, Tuple

import streamlit as st

MetricItem = Tuple[str, str, str]

# Shared design tokens (warm paper + ink; avoids generic “gradient grid” AI landing look)
_THEME_CORE_NO_NAV = """
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700&family=Noto+Sans+SC:wght@400;500;600;700&display=swap');

        :root {
            --bg: #f4f3f0;
            --bg-top: #fafaf8;
            --surface: #ffffff;
            --surface-muted: rgba(255, 255, 255, 0.72);
            --text: #1c1917;
            --muted: #57534e;
            --muted-2: #78716c;
            --border: #e7e5e4;
            --border-strong: #d6d3d1;
            --ink: #0f172a;
            --ink-2: #334155;
            --accent: #9a3412;
            --accent-soft: rgba(154, 52, 18, 0.12);
            --ok: #14532d;
            --warn: #991b1b;
            --shadow-sm: 0 1px 0 rgba(28, 25, 23, 0.04);
            --shadow-md: 0 8px 30px rgba(15, 23, 42, 0.06);
            --shadow-lg: 0 20px 50px rgba(15, 23, 42, 0.08);
            --radius: 12px;
            --radius-sm: 8px;
        }

        .stApp {
            font-family: 'IBM Plex Sans', 'Noto Sans SC', system-ui, sans-serif;
            color: var(--text);
            background-color: var(--bg);
            background-image:
                radial-gradient(ellipse 120% 80% at 50% -20%, rgba(15, 23, 42, 0.05), transparent 55%),
                linear-gradient(180deg, var(--bg-top) 0%, var(--bg) 45%, #eeede8 100%);
            animation: pageIn 0.28s ease-out;
        }

        .stSidebar {
            background: linear-gradient(180deg, #f7f6f4 0%, #efede9 100%);
            border-right: 1px solid var(--border);
        }

        .main .block-container {
            padding-top: 1.25rem;
            padding-bottom: 2.25rem;
            padding-left: 1.25rem;
            padding-right: 1.25rem;
            max-width: 1320px;
        }

        .main h2 {
            font-size: 1.12rem;
            font-weight: 600;
            color: var(--ink);
            letter-spacing: -0.02em;
            border-bottom: none;
            padding-bottom: 0.25rem;
        }

        .main h3 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--ink-2);
        }

        [data-testid="stSidebarNav"] {
            display: none !important;
        }

        [data-testid="collapsedControl"] {
            display: none !important;
        }

        /* 多页应用默认侧边栏：「首页」下易出现空白输入框感白块 — 整栏隐藏，仅用顶栏导航 */
        section[data-testid="stSidebar"],
        [data-testid="stSidebar"] {
            display: none !important;
        }

        section[data-testid="stMain"],
        [data-testid="stMain"] {
            margin-left: 0 !important;
            width: 100% !important;
            max-width: 100% !important;
        }

        [data-testid="stAppViewContainer"] {
            margin-left: 0 !important;
        }

        /* 顶栏 st.page_link：去掉白底、边框，避免像搜索框 */
        .main .block-container > div:first-child [data-testid="stPageLink-Container"],
        .main .block-container > div:first-child [data-testid="stPageLink-NavLinkContainer"] {
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
            margin: 0 !important;
        }

        .main .block-container > div:first-child a[data-testid="stPageLink-NavLink"],
        .main .block-container > div:first-child [data-testid="stPageLink-NavLink"] a {
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            color: var(--ink-2) !important;
            font-weight: 600 !important;
            font-size: 0.875rem !important;
            padding: 0.5rem 0.75rem !important;
            border-radius: var(--radius-sm) !important;
            text-decoration: none !important;
        }

        .main .block-container > div:first-child a[data-testid="stPageLink-NavLink"]:hover,
        .main .block-container > div:first-child [data-testid="stPageLink-NavLink"] a:hover {
            background: rgba(255, 255, 255, 0.85) !important;
            color: var(--ink) !important;
        }

        .main .block-container > div:first-child [data-testid*="PageLink"] {
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }

        /* 提示条：弱化默认「蓝条 AI 感」 */
        div[data-testid="stAlert"] {
            border-radius: var(--radius-sm) !important;
            border: 1px solid var(--border) !important;
            background: #f8f7f4 !important;
            color: var(--ink-2) !important;
        }

        div[data-testid="stAlert"] p {
            color: var(--ink-2) !important;
        }

        /* 顶栏工具条：与页面背景统一，减少「默认 Streamlit」割裂感 */
        header[data-testid="stHeader"] {
            background: linear-gradient(180deg, rgba(247, 246, 244, 0.97), rgba(242, 240, 236, 0.95)) !important;
            border-bottom: 1px solid var(--border) !important;
            backdrop-filter: blur(10px);
        }

        /* 正文链接 */
        .main .stMarkdown a {
            color: var(--ink-2);
            text-decoration: underline;
            text-decoration-color: rgba(51, 65, 85, 0.35);
            text-underline-offset: 2px;
            transition: color 0.15s ease, text-decoration-color 0.15s ease;
        }

        .main .stMarkdown a:hover {
            color: var(--accent);
            text-decoration-color: rgba(154, 52, 18, 0.45);
        }

        /* 辅助说明 */
        [data-testid="stCaption"] {
            color: var(--muted) !important;
        }

        /* 分隔线 */
        hr {
            border: none !important;
            border-top: 1px solid var(--border) !important;
            margin: 1.15rem 0 !important;
            opacity: 1 !important;
        }

        /* 代码块 */
        [data-testid="stCodeBlock"],
        .stCodeBlock {
            border-radius: var(--radius-sm) !important;
            border: 1px solid var(--border) !important;
            background: #fafaf8 !important;
        }

        /* JSON 视图 */
        [data-testid="stJson"] {
            border-radius: var(--radius-sm) !important;
            border: 1px solid var(--border) !important;
            background: #fafaf8 !important;
        }

        /* 折叠面板 */
        [data-testid="stExpander"] {
            border: 1px solid var(--border) !important;
            border-radius: var(--radius-sm) !important;
            background: rgba(255, 255, 255, 0.55) !important;
        }

        /* 复选框标签 */
        [data-testid="stCheckbox"] label,
        [data-testid="stCheckbox"] label p {
            color: var(--text) !important;
        }

        /* 数字输入标签 */
        [data-testid="stNumberInput"] label {
            color: var(--ink-2) !important;
        }

"""

_NAV_STICKY = """
        /* Top nav: segmented bar */
        .main .block-container > div:first-child {
            position: sticky;
            top: 0.35rem;
            z-index: 900;
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 0.28rem;
            margin-bottom: 1.05rem;
            backdrop-filter: blur(10px);
            max-width: 720px;
            margin-left: auto;
            margin-right: auto;
            box-shadow: var(--shadow-sm);
        }

        .main .block-container > div:first-child .stPageLink a {
            width: 100%;
            min-height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none !important;
            color: var(--ink-2) !important;
            border-radius: var(--radius-sm);
            border: 1px solid transparent;
            background: transparent;
            transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .main .block-container > div:first-child .stPageLink a:hover {
            border-color: var(--border);
            color: var(--ink) !important;
            background: var(--surface);
        }

        .nav-active {
            width: 100%;
            min-height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-strong);
            color: var(--ink);
            background: var(--surface);
            font-weight: 600;
            font-size: 0.875rem;
            box-shadow: var(--shadow-sm);
        }

"""

_THEME_REST = """
        .control-panel-card {
            position: relative;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: var(--surface);
            padding: 1rem 1rem 1.05rem 1rem;
            box-shadow: var(--shadow-md);
            overflow: hidden;
        }

        .control-panel-card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: var(--ink);
        }

        .control-panel-title {
            margin: 0 0 0.5rem 0.15rem;
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--ink);
            letter-spacing: -0.02em;
        }

        .control-panel-hint {
            margin: 0 0 0.85rem 0.15rem;
            color: var(--muted);
            font-size: 0.875rem;
            line-height: 1.65;
        }

        .panel-group-label {
            margin: 0.65rem 0 0.35rem 0;
            color: var(--muted-2);
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }

        .hero {
            position: relative;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: var(--shadow-md);
            padding: 1.35rem 1.5rem;
            margin-bottom: 1rem;
            overflow: hidden;
            animation: rise 0.32s ease-out;
        }

        .hero-title {
            margin: 0;
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            font-size: clamp(1.75rem, 2.8vw, 2.15rem);
            font-weight: 600;
            color: var(--ink);
            letter-spacing: -0.03em;
            position: relative;
            z-index: 1;
        }

        .hero-subtitle {
            margin-top: 0.5rem;
            color: var(--muted);
            font-size: 0.98rem;
            line-height: 1.72;
            position: relative;
            z-index: 1;
        }

        .metric-card {
            position: relative;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            background: var(--surface);
            padding: 0.9rem 1rem;
            min-height: 112px;
            box-shadow: var(--shadow-sm);
            animation: fadeIn 0.28s ease-out;
            overflow: hidden;
        }

        .metric-card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: var(--accent);
            opacity: 0.85;
        }

        .metric-label {
            margin: 0;
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 600;
            letter-spacing: 0.01em;
        }

        .metric-value {
            margin: 0.28rem 0 0 0;
            font-size: 1.45rem;
            font-weight: 600;
            color: var(--ink);
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            letter-spacing: -0.02em;
        }

        .metric-hint {
            margin: 0.38rem 0 0 0;
            font-size: 0.82rem;
            color: var(--muted-2);
        }

        .status-pill {
            border: 1px solid var(--border);
            border-left: 3px solid var(--ink);
            background: var(--surface);
            border-radius: var(--radius-sm);
            padding: 0.55rem 0.72rem;
            margin-bottom: 0.75rem;
            color: var(--ink-2);
            font-size: 0.88rem;
            line-height: 1.5;
        }

        .status-pill.ok {
            border-left-color: var(--ok);
        }

        .status-pill.warn {
            border-left-color: var(--warn);
        }

        .stButton > button {
            border-radius: var(--radius-sm);
            border: 1px solid #1e293b !important;
            background: linear-gradient(180deg, #334155 0%, #1e293b 100%) !important;
            color: #f8fafc !important;
            font-weight: 600;
            letter-spacing: 0.01em;
            padding: 0.5rem 1rem;
            transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease, border-color 0.18s ease;
            box-shadow: 0 1px 0 rgba(255, 255, 255, 0.12) inset, var(--shadow-sm);
            cursor: pointer !important;
        }

        .stButton > button:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
            background: linear-gradient(180deg, #475569 0%, #334155 100%) !important;
            border-color: #475569 !important;
        }

        .stButton > button:focus-visible {
            box-shadow: 0 0 0 2px rgba(71, 85, 105, 0.35);
        }

        .stDownloadButton > button {
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-strong);
            background: var(--surface);
            color: var(--ink-2);
            font-weight: 600;
        }

        .stDownloadButton > button:hover {
            border-color: var(--ink-2);
            background: var(--bg-top);
        }

        div[data-testid="stFileUploaderDropzone"] {
            border: 1px dashed var(--border-strong);
            border-radius: var(--radius-sm);
            background: rgba(255, 255, 255, 0.5);
            transition: border-color 0.15s ease, background 0.15s ease;
        }

        div[data-testid="stFileUploaderDropzone"]:hover {
            border-color: var(--muted-2);
            background: var(--surface);
        }

        div[data-baseweb="input"] > div,
        div[data-baseweb="select"] > div {
            border: 1px solid var(--border) !important;
            border-radius: var(--radius-sm);
            background: var(--surface) !important;
        }

        div[data-baseweb="slider"] [role="slider"] {
            background: var(--accent) !important;
            border-color: var(--accent) !important;
        }

        div[data-baseweb="slider"] [data-baseweb="thumb"] {
            background: var(--surface) !important;
            border: 2px solid var(--accent) !important;
        }

        /* 加载中：弱化转圈对比度 */
        [data-testid="stSpinner"] {
            color: var(--ink-2) !important;
        }

        div[data-testid="stMetric"] {
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 0.4rem 0.6rem;
            background: var(--surface);
        }

        .stDataFrame, .stTable {
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            overflow: hidden;
            box-shadow: var(--shadow-sm);
            background: var(--surface);
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.25rem;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            background: rgba(255, 255, 255, 0.5);
            padding: 0.2rem;
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 6px;
            border: 1px solid transparent;
            background: transparent;
            padding: 0.4rem 0.75rem;
            color: var(--muted);
            font-weight: 600;
        }

        .stTabs [aria-selected="true"] {
            background: var(--surface);
            color: var(--ink);
            border-color: var(--border);
            box-shadow: var(--shadow-sm);
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 1rem;
            margin-top: 0.2rem;
            margin-bottom: 0.55rem;
        }

        .feature-card {
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: var(--surface);
            padding: 1.05rem 1.1rem;
            box-shadow: var(--shadow-md);
            animation: rise 0.32s ease-out;
        }

        .feature-title {
            margin: 0;
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--ink);
            letter-spacing: -0.02em;
        }

        .feature-desc {
            margin: 0.4rem 0 0 0;
            color: var(--muted);
            line-height: 1.65;
            font-size: 0.94rem;
        }

        .feature-meta {
            margin-top: 0.65rem;
            font-size: 0.8rem;
            color: var(--ink-2);
            font-weight: 600;
        }

        .system-note {
            margin-top: 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 0.75rem 0.88rem;
            color: var(--muted);
            background: var(--surface-muted);
            font-size: 0.9rem;
            line-height: 1.6;
        }

        /* 侧信道 / 分析页：空状态面板 */
        .side-empty-state {
            position: relative;
            border: 1px dashed var(--border-strong);
            border-radius: var(--radius);
            background: linear-gradient(165deg, #fafaf8 0%, #f4f3ef 100%);
            padding: 1.85rem 1.6rem 1.75rem 1.6rem;
            margin-top: 0.35rem;
            margin-bottom: 0.5rem;
            text-align: center;
            max-width: 640px;
            margin-left: auto;
            margin-right: auto;
            box-shadow: var(--shadow-sm);
        }

        .side-empty-state .empty-illus {
            display: block;
            margin: 0 auto 1rem auto;
            opacity: 0.72;
        }

        .side-empty-state h2 {
            margin: 0 0 0.5rem 0;
            font-size: 1.08rem;
            font-weight: 600;
            color: var(--ink);
        }

        .side-empty-state p {
            margin: 0 0 1rem 0;
            font-size: 0.9rem;
            color: var(--muted);
            line-height: 1.65;
        }

        @keyframes rise {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes pageIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @media (max-width: 980px) {
            .main .block-container {
                padding-top: 0.75rem;
            }

            .hero {
                padding: 1.1rem 1.15rem;
            }

            .hero-title {
                font-size: 1.6rem;
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
"""

_HOME_EXTRA = """
        .main .block-container {
            max-width: 1180px;
            padding-top: 2rem;
            padding-bottom: 2.5rem;
            animation: homeFade 0.38s ease-out;
        }

        [data-testid="stSidebarNav"], [data-testid="collapsedControl"], header {
            display: none !important;
        }

        /* Hero 区：低透明度拓扑/线框装饰 */
        .hero-graphic-shell {
            position: relative;
            margin: 0 auto 1.5rem auto;
            max-width: 960px;
            padding: 1.35rem 1.25rem 1.5rem 1.25rem;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            background: linear-gradient(145deg, rgba(255, 255, 255, 0.96) 0%, rgba(247, 246, 242, 0.92) 100%);
            box-shadow: var(--shadow-md);
            overflow: hidden;
        }

        .hero-graphic-bg {
            position: absolute;
            inset: 0;
            pointer-events: none;
            opacity: 0.4;
            background-image:
                radial-gradient(circle at 18% 28%, rgba(15, 23, 42, 0.07) 0%, transparent 42%),
                radial-gradient(circle at 88% 12%, rgba(154, 52, 18, 0.06) 0%, transparent 38%),
                linear-gradient(105deg, transparent 48%, rgba(148, 163, 184, 0.12) 49%, transparent 51%),
                linear-gradient(165deg, transparent 58%, rgba(148, 163, 184, 0.1) 59%, transparent 61%);
        }

        .hero-graphic-bg svg {
            position: absolute;
            right: -2%;
            top: 50%;
            transform: translateY(-50%);
            width: min(340px, 42vw);
            height: auto;
            opacity: 0.55;
        }

        .hero-wrap {
            text-align: left;
            margin: 0;
            max-width: 100%;
            position: relative;
            z-index: 1;
            padding-left: 0.1rem;
        }

        /* 首页全局运行概览（展示期 mock） */
        .home-global-stats {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
            margin: 0 auto 1.35rem auto;
            max-width: 960px;
        }

        .home-global-stat {
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            background: var(--surface);
            padding: 0.85rem 1rem;
            box-shadow: var(--shadow-sm);
        }

        .home-global-stat span {
            display: block;
            font-size: 0.72rem;
            font-weight: 600;
            color: var(--muted);
            letter-spacing: 0.04em;
        }

        .home-global-stat strong {
            display: block;
            margin-top: 0.28rem;
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--ink);
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            letter-spacing: -0.02em;
        }

        .home-global-stat em {
            display: block;
            margin-top: 0.2rem;
            font-style: normal;
            font-size: 0.78rem;
            color: var(--muted-2);
        }

        /* 入口卡片顶栏：图标 + 压缩主按钮高度 */
        .home-card-head {
            display: flex;
            align-items: flex-start;
            gap: 0.65rem;
            margin-bottom: 0.35rem;
        }

        .home-card-icon {
            flex-shrink: 0;
            width: 44px;
            height: 44px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: linear-gradient(180deg, #ffffff, #f4f3f0);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .home-card-icon svg {
            width: 26px;
            height: 26px;
            opacity: 0.88;
        }

        .home-kicker {
            margin: 0 0 0.85rem 0;
            font-size: 0.8125rem;
            font-weight: 600;
            color: var(--muted);
            letter-spacing: 0.06em;
        }

        .hero-title {
            margin: 0;
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            font-size: clamp(2rem, 5vw, 3.35rem);
            font-weight: 600;
            letter-spacing: -0.04em;
            color: var(--ink);
            line-height: 1.12;
            text-align: left;
        }

        .hero-subtitle {
            margin: 0.9rem 0 0 0;
            max-width: 52rem;
            color: var(--muted);
            font-size: 1.02rem;
            line-height: 1.75;
            text-align: left;
        }

        .value-row {
            display: flex;
            justify-content: flex-start;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1.1rem;
            margin-bottom: 1.15rem;
        }

        .value-pill {
            border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--ink-2);
            padding: 0.32rem 0.72rem;
            font-size: 0.8125rem;
            font-weight: 500;
        }

        .hero-kpis {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.65rem;
            margin-top: 0.5rem;
        }

        .hero-kpi {
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            background: var(--surface);
            padding: 0.75rem 0.88rem;
            text-align: left;
            box-shadow: var(--shadow-sm);
        }

        .hero-kpi span {
            display: block;
            color: var(--muted);
            font-size: 0.72rem;
            font-weight: 600;
            letter-spacing: 0.04em;
        }

        .hero-kpi strong {
            display: block;
            margin-top: 0.2rem;
            font-size: 1.28rem;
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            color: var(--ink);
            font-weight: 600;
            letter-spacing: -0.02em;
        }

        .hero-kpi em {
            display: block;
            margin-top: 0.12rem;
            font-style: normal;
            font-size: 0.82rem;
            color: var(--muted-2);
        }

        .entry-caption {
            margin: 1.15rem 0 0.9rem 0;
            color: var(--muted);
            font-size: 0.8125rem;
            font-weight: 600;
            letter-spacing: 0.04em;
            text-align: left;
        }

        /* Home entry cards: pointer + no text caret; block Streamlit hover “pure black” text */
        div[data-testid="stButton"] > button {
            width: 100%;
            min-height: 168px;
            border-radius: 14px !important;
            border: 1px solid var(--border) !important;
            background: linear-gradient(165deg, #ffffff 0%, #faf9f7 100%) !important;
            padding: 1rem 1.15rem 1rem 1.15rem !important;
            text-align: left;
            box-shadow:
                0 1px 0 rgba(255, 255, 255, 0.9) inset,
                0 12px 32px rgba(15, 23, 42, 0.06);
            transition:
                transform 0.22s cubic-bezier(0.33, 1, 0.68, 1),
                box-shadow 0.22s ease,
                border-color 0.22s ease,
                background 0.22s ease;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-items: stretch;
            position: relative;
            overflow: hidden;
            cursor: pointer !important;
            color: var(--muted) !important;
            -webkit-tap-highlight-color: transparent;
        }

        div[data-testid="stButton"] > button::before {
            content: "";
            position: absolute;
            inset: 0 auto 0 0;
            width: 3px;
            height: 100%;
            background: linear-gradient(180deg, #94a3b8 0%, #64748b 100%);
            opacity: 0.85;
            transition: width 0.22s ease, opacity 0.22s ease, filter 0.22s ease;
        }

        div[data-testid="stButton"] > button::after {
            content: "进入分析";
            display: block;
            margin-top: auto;
            padding-top: 0.85rem;
            font-size: 0.78rem;
            letter-spacing: 0.06em;
            color: var(--muted-2) !important;
            font-weight: 600;
            transition: color 0.2s ease;
        }

        div[data-testid="stButton"] > button:hover {
            transform: translateY(-4px);
            border-color: rgba(154, 52, 18, 0.35) !important;
            background: linear-gradient(165deg, #ffffff 0%, #f5f3ef 100%) !important;
            box-shadow:
                0 1px 0 rgba(255, 255, 255, 0.95) inset,
                0 20px 44px rgba(15, 23, 42, 0.1);
            color: var(--muted) !important;
        }

        div[data-testid="stButton"] > button:hover::before {
            width: 4px;
            opacity: 1;
            background: linear-gradient(180deg, #c2410c 0%, #9a3412 55%, #7c2d12 100%);
            filter: none;
        }

        div[data-testid="stButton"] > button:hover::after {
            color: var(--ink-2) !important;
        }

        div[data-testid="stButton"] p {
            margin: 0;
            color: var(--muted) !important;
            font-size: 0.94rem;
            line-height: 1.72;
            white-space: pre-wrap;
            letter-spacing: 0;
            cursor: pointer !important;
            user-select: none !important;
            -webkit-user-select: none !important;
        }

        div[data-testid="stButton"] p::first-line {
            font-family: 'IBM Plex Sans', 'Noto Sans SC', sans-serif;
            font-size: 1.32rem;
            font-weight: 600;
            color: var(--ink-2) !important;
            letter-spacing: -0.02em;
            line-height: 1.65;
        }

        div[data-testid="stButton"] > button:hover p,
        div[data-testid="stButton"] > button:hover p::first-line {
            color: var(--muted) !important;
        }

        div[data-testid="stButton"] > button:hover p::first-line {
            color: var(--ink) !important;
        }

        div[data-testid="stButton"] > button:focus-visible {
            outline: none !important;
            border-color: #c4b8a8 !important;
            box-shadow:
                0 1px 0 rgba(255, 255, 255, 0.9) inset,
                0 0 0 3px rgba(148, 124, 96, 0.22) !important;
        }

        div[data-testid="stButton"] > button:active {
            transform: translateY(0);
            box-shadow:
                0 1px 0 rgba(255, 255, 255, 0.85) inset,
                0 8px 20px rgba(15, 23, 42, 0.06);
        }

        .home-footer-note {
            margin-top: 1.35rem;
            color: var(--muted-2);
            text-align: left;
            font-size: 0.86rem;
            line-height: 1.65;
            max-width: 52rem;
        }

        @keyframes homeFade {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 900px) {
            .main .block-container {
                padding-top: 1.25rem;
            }

            .hero-kpis {
                grid-template-columns: repeat(1, minmax(0, 1fr));
            }

            .home-global-stats {
                grid-template-columns: 1fr;
            }

            div[data-testid="stButton"] > button {
                min-height: 158px;
            }
        }
"""


def apply_modern_theme() -> None:
    st.markdown(
        f"""
        <style>
        {_THEME_CORE_NO_NAV}{_NAV_STICKY}{_THEME_REST}
        </style>
        """,
        unsafe_allow_html=True,
    )


def apply_home_theme() -> None:
    st.markdown(
        f"""
        <style>
        {_THEME_CORE_NO_NAV}{_THEME_REST}{_HOME_EXTRA}
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
                try:
                    st.page_link(path, label=label, use_container_width=True)
                except TypeError:
                    st.page_link(path, label=label)
