from __future__ import annotations

from html import escape

import streamlit as st

from frontend.shared.ui_theme import apply_home_theme

HOME_KICKER = "机器人威胁情报 · 检测与审计工作台"

HERO_DECOR_SVG = """
<svg viewBox="0 0 220 180" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <g stroke="#64748b" stroke-width="0.75" fill="none" opacity="0.55">
    <path d="M10 120 Q55 40 100 90 T190 70"/>
    <path d="M25 150 L80 55 L130 95 L205 35" stroke-dasharray="4 3"/>
    <circle cx="80" cy="55" r="4" fill="#475569" opacity="0.35"/>
    <circle cx="130" cy="95" r="4" fill="#9a3412" opacity="0.35"/>
    <circle cx="190" cy="70" r="4" fill="#475569" opacity="0.35"/>
    <rect x="155" y="115" width="38" height="52" rx="4" stroke-dasharray="3 2" opacity="0.45"/>
    <line x1="155" y1="128" x2="193" y2="128" opacity="0.4"/>
  </g>
</svg>
"""

ICON_SIDE_SVG = """<svg viewBox="0 0 24 24" fill="none" stroke="#334155" stroke-width="1.5" stroke-linecap="round"><path d="M4 12h3l2 5 4-10 2 5h5"/><circle cx="6" cy="12" r="1.5" fill="#334155" stroke="none"/></svg>"""

ICON_PAYLOAD_SVG = """<svg viewBox="0 0 24 24" fill="none" stroke="#334155" stroke-width="1.5" stroke-linejoin="round"><path d="M12 3l8 4v10l-8 4-8-4V7z"/><path d="M12 11V21M12 11l8-4M12 11L4 7"/><path d="M9 14h6"/></svg>"""


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

    apply_home_theme()

    st.markdown(
        (
            '<div class="hero-graphic-shell">'
            '<div class="hero-graphic-bg" aria-hidden="true">'
            f"{HERO_DECOR_SVG}"
            "</div>"
            '<section class="hero-wrap">'
            f'<p class="home-kicker">{escape(HOME_KICKER)}</p>'
            "<h1 class=\"hero-title\">Robot Security System</h1>"
            "<p class=\"hero-subtitle\">面向机器人网络空间的专业检测工作台，统一接入侧信道与载荷风险分析，"
            "输出可追溯证据链与高可读审计报告。</p>"
            '<div class="value-row">'
            '<span class="value-pill">异常时序追踪</span>'
            '<span class="value-pill">风险分布画像</span>'
            '<span class="value-pill">证据链导出</span>'
            '<span class="value-pill">研判报告生成</span>'
            "</div>"
            '<div class="hero-kpis">'
            '<article class="hero-kpi"><span>分析流程</span><strong>2</strong>'
            "<em>检测入口即开即用</em></article>"
            '<article class="hero-kpi"><span>证据输出</span><strong>JSON / CSV</strong>'
            "<em>结构化证据可回溯</em></article>"
            '<article class="hero-kpi"><span>报告体验</span><strong>弹窗与导出</strong>'
            "<em>查看与下载一体</em></article>"
            "</div>"
            "</section>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )

    st.markdown('<p class="entry-caption">选择工作台并开始检测</p>', unsafe_allow_html=True)

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.markdown(
            f'<div class="home-card-head"><span class="home-card-icon">{ICON_SIDE_SVG}</span></div>',
            unsafe_allow_html=True,
        )
        side_text = (
            "侧信道分析\n"
            "流量特征建模 + 离群审计。\n"
            "生成异常时序图、目标追踪与证据清单。"
        )
        if st.button(side_text, key="btn_side", width="stretch"):
            _switch_page("pages/1_side_channel_analysis.py")

    with col2:
        st.markdown(
            f'<div class="home-card-head"><span class="home-card-icon">{ICON_PAYLOAD_SVG}</span></div>',
            unsafe_allow_html=True,
        )
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
