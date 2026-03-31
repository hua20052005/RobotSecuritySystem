from __future__ import annotations
import streamlit as st

ANNOUNCEMENT_TEXT = "Robot Threat Intelligence Workspace · 机器人网络安全分析中枢"


def _apply_home_theme() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Noto+Sans+SC:wght@400;500;600;700&display=swap');

        :root {
            --bg-canvas: #eef2f6;
            --bg-grid: rgba(14, 43, 80, 0.07);
            --surface: rgba(255, 255, 255, 0.84);
            --surface-strong: #ffffff;
            --text: #11223d;
            --muted: #5f6f88;
            --line: #c2cfdf;
            --line-strong: #94aac5;
            --primary: #114a6e;
            --primary-2: #228690;
            --accent: #b66d40;
            --shadow-soft: 0 16px 34px rgba(18, 34, 58, 0.1);
            --shadow-raise: 0 24px 48px rgba(12, 26, 48, 0.16);
        }

        [data-testid="stSidebarNav"], [data-testid="collapsedControl"], header {
            display: none !important;
        }

        .stApp {
            color: var(--text);
            font-family: 'Noto Sans SC', 'Space Grotesk', sans-serif;
            background:
                radial-gradient(960px 460px at 6% 4%, rgba(17, 74, 110, 0.18), transparent 58%),
                radial-gradient(760px 460px at 98% 90%, rgba(182, 109, 64, 0.12), transparent 62%),
                linear-gradient(180deg, #f4f7fb 0%, var(--bg-canvas) 52%, #f8fbfd 100%);
            background-image:
                radial-gradient(960px 460px at 6% 4%, rgba(17, 74, 110, 0.18), transparent 58%),
                radial-gradient(760px 460px at 98% 90%, rgba(182, 109, 64, 0.12), transparent 62%),
                repeating-linear-gradient(0deg, transparent 0, transparent 31px, var(--bg-grid) 32px),
                repeating-linear-gradient(90deg, transparent 0, transparent 31px, var(--bg-grid) 32px),
                linear-gradient(180deg, #f4f7fb 0%, var(--bg-canvas) 52%, #f8fbfd 100%);
        }

        .main .block-container {
            max-width: 1220px;
            padding-top: 2.3rem;
            padding-bottom: 2.4rem;
            animation: homeFade 0.42s ease-out;
        }

        .hero-wrap {
            text-align: center;
            margin: 0 auto 1.8rem auto;
            max-width: 980px;
            position: relative;
        }

        .announcement {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1.1rem;
            padding: 0.54rem 0.98rem;
            border-radius: 999px;
            border: 1px solid var(--line-strong);
            background: rgba(255, 255, 255, 0.8);
            color: var(--muted);
            font-size: 0.86rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            line-height: 1.45;
            backdrop-filter: blur(6px);
        }

        .hero-title {
            margin: 0;
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: clamp(2.4rem, 6.4vw, 4.5rem);
            font-weight: 700;
            letter-spacing: 0.02em;
            color: #12284a;
            text-align: center;
            text-shadow: 0 2px 0 rgba(255, 255, 255, 0.55);
        }

        .hero-subtitle {
            margin: 0.85rem auto 0 auto;
            max-width: 870px;
            color: #495d7c;
            font-size: 1.02rem;
            line-height: 1.84;
            text-align: center;
        }

        .value-row {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 0.58rem;
            margin-top: 1.15rem;
            margin-bottom: 1.2rem;
        }

        .value-pill {
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, 0.72);
            color: #2f466c;
            padding: 0.36rem 0.82rem;
            font-size: 0.81rem;
            font-weight: 600;
            letter-spacing: 0.03em;
        }

        .hero-kpis {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
            margin-top: 1rem;
        }

        .hero-kpi {
            border: 1px solid var(--line);
            border-radius: 14px;
            background: var(--surface);
            padding: 0.72rem 0.86rem;
            text-align: left;
            box-shadow: var(--shadow-soft);
        }

        .hero-kpi span {
            display: block;
            color: #627492;
            font-size: 0.76rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            font-weight: 600;
        }

        .hero-kpi strong {
            display: block;
            margin-top: 0.15rem;
            font-size: 1.35rem;
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            color: #152a4a;
            font-weight: 700;
        }

        .hero-kpi em {
            display: block;
            margin-top: 0.08rem;
            font-style: normal;
            font-size: 0.84rem;
            color: #5a6f92;
        }

        .entry-caption {
            margin: 1.1rem 0 0.95rem 0;
            color: #4e6387;
            font-size: 0.9rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            text-align: center;
            font-weight: 600;
        }

        div[data-testid="stButton"] > button {
            width: 100%;
            min-height: 238px;
            border-radius: 22px;
            border: 1px solid var(--line) !important;
            background: linear-gradient(170deg, rgba(255, 255, 255, 0.96), rgba(244, 248, 253, 0.92)) !important;
            backdrop-filter: blur(6px);
            padding: 1.18rem 1.2rem !important;
            text-align: left;
            box-shadow: var(--shadow-soft);
            transition: transform 0.26s ease, box-shadow 0.26s ease, border-color 0.26s ease;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-items: stretch;
            position: relative;
            overflow: hidden;
        }

        div[data-testid="stButton"] > button::before {
            content: "";
            position: absolute;
            inset: 0 auto auto 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--primary-2), var(--accent));
            opacity: 0.9;
        }

        div[data-testid="stButton"] > button::after {
            content: "OPEN WORKSPACE";
            display: inline-block;
            margin-top: 0.8rem;
            font-size: 0.75rem;
            letter-spacing: 0.12em;
            color: #5c718f;
            font-weight: 700;
            text-transform: uppercase;
        }

        div[data-testid="stButton"] > button:hover {
            transform: translateY(-5px);
            border-color: #8ea4c1 !important;
            box-shadow: var(--shadow-raise);
        }

        div[data-testid="stButton"] p {
            margin: 0;
            color: #425778;
            font-size: 0.96rem;
            line-height: 1.76;
            white-space: pre-wrap;
            letter-spacing: 0;
        }

        div[data-testid="stButton"] p::first-line {
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: 1.48rem;
            font-weight: 700;
            color: #16365f;
            letter-spacing: 0.01em;
            line-height: 1.85;
        }

        div[data-testid="stButton"] > button:focus,
        div[data-testid="stButton"] > button:active {
            outline: none !important;
            border-color: #88a2c4 !important;
            box-shadow: 0 0 0 0.2rem rgba(17, 74, 110, 0.14) !important;
        }

        .home-footer-note {
            margin-top: 1.2rem;
            color: #607392;
            text-align: center;
            font-size: 0.88rem;
            line-height: 1.66;
        }

        @keyframes homeFade {
            from {
                opacity: 0;
                transform: translateY(6px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @media (max-width: 900px) {
            .main .block-container {
                padding-top: 1.4rem;
            }

            .hero-kpis {
                grid-template-columns: repeat(1, minmax(0, 1fr));
            }

            div[data-testid="stButton"] > button {
                min-height: 212px;
            }

            .hero-subtitle {
                font-size: 1rem;
                line-height: 1.76;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .main .block-container,
            div[data-testid="stButton"] > button {
                animation: none !important;
                transition: none !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def _switch_page(path: str) -> None:
    if hasattr(st, "switch_page"):
        st.switch_page(path)
    else:
        st.error("页面路由异常")

def main() -> None:
    st.set_page_config(
        page_title="Robot Security System",
        page_icon="R",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    _apply_home_theme()

    st.markdown(
        (
            '<section class="hero-wrap">'
            f'<div class="announcement">{ANNOUNCEMENT_TEXT}</div>'
            '<h1 class="hero-title">Robot Security System</h1>'
            '<p class="hero-subtitle">面向机器人网络空间的专业检测工作台，统一接入侧信道与载荷风险分析，输出可追溯证据链与高可读审计报告。</p>'
            '<div class="value-row">'
            '<span class="value-pill">异常时序追踪</span>'
            '<span class="value-pill">风险分布画像</span>'
            '<span class="value-pill">证据链导出</span>'
            '<span class="value-pill">研判报告生成</span>'
            '</div>'
            '<div class="hero-kpis">'
            '<article class="hero-kpi"><span>Analysis Workflows</span><strong>2</strong><em>检测入口即开即用</em></article>'
            '<article class="hero-kpi"><span>Evidence Output</span><strong>JSON / CSV</strong><em>结构化证据可回溯</em></article>'
            '<article class="hero-kpi"><span>Report Experience</span><strong>Modal + Export</strong><em>报告查看与下载一体化</em></article>'
            '</div>'
            '</section>'
        ),
        unsafe_allow_html=True,
    )

    st.markdown('<p class="entry-caption">选择工作台并开始检测</p>', unsafe_allow_html=True)

    col1, col2 = st.columns(2, gap="large")

    with col1:
        side_text = (
            "侧信道分析\n"
            "流量特征建模 + 离群审计。\n"
            "生成异常时序图、目标追踪与证据清单。"
        )
        if st.button(side_text, key="btn_side", width="stretch"):
            _switch_page("pages/1_side_channel_analysis.py")

    with col2:
        payload_text = (
            "通信包载荷检测\n"
            "逐包风险评分 + 协议画像。\n"
            "输出威胁分布、明细表格与检测结果下载。"
        )
        if st.button(payload_text, key="btn_payload", width="stretch"):
            _switch_page("pages/2_payload_detection.py")

    st.markdown(
        '<p class="home-footer-note">平台聚焦机器人网络安全场景，确保检测链路可解释、可追溯、可交付。</p>',
        unsafe_allow_html=True,
    )

if __name__ == "__main__":
    main()