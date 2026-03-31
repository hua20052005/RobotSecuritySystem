from __future__ import annotations

import json
from typing import Dict, Optional

import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

from core.payload_backend_bootstrap import DEFAULT_BACKEND_URL, ensure_payload_backend
from frontend.shared.ai_report import (
    build_report_html,
    build_report_pdf_bytes,
    generate_security_report,
    get_deepseek_runtime_config,
    markdown_to_plain_text,
)
from frontend.shared.ui_theme import apply_modern_theme, render_hero, render_metric_cards, render_top_nav


PAYLOAD_RESULT_STATE_KEY = "payload_detection_state"


def _build_url(base: str, suffix: str) -> str:
    return f"{base.rstrip('/')}{suffix}"


def _render_control_panel():
    st.markdown('<section class="control-panel-card">', unsafe_allow_html=True)
    st.markdown('<h3 class="control-panel-title">控制面板</h3>', unsafe_allow_html=True)
    st.markdown('<p class="control-panel-hint">上传流量包并设置处理策略，系统将调用后端执行逐包风险推理。</p>', unsafe_allow_html=True)

    st.markdown('<div class="panel-group-label">处理范围</div>', unsafe_allow_html=True)
    limit = st.number_input("最多处理包数 (0 表示不限)", min_value=0, value=0, step=100)

    st.markdown('<div class="panel-group-label">运行选项</div>', unsafe_allow_html=True)
    verbose = st.checkbox("显示详细日志", value=False)

    st.markdown('<div class="panel-group-label">文件输入</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("上传 .pcap / .pcapng", type=["pcap", "pcapng"])
    run_button = st.button("启动载荷风险检测", type="primary", width="stretch")
    st.markdown('</section>', unsafe_allow_html=True)
    return limit, verbose, uploaded_file, run_button


def _run_backend_detection(
    backend_url: str,
    uploaded_file,
    limit: int,
    verbose: bool,
) -> Optional[Dict[str, object]]:
    if uploaded_file is None:
        st.warning("请先上传 pcap 或 pcapng 文件。")
        return None

    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
    data = {"verbose": "true" if verbose else "false"}
    if limit > 0:
        data["limit"] = str(limit)

    endpoint = _build_url(backend_url, "/detect-file")
    with st.spinner("正在调用后端执行载荷检测，请稍候..."):
        try:
            resp = requests.post(endpoint, files=files, data=data, timeout=1800)
        except requests.RequestException as e:
            st.error(f"后端连接失败: {e}")
            return None

    if resp.status_code != 200:
        st.error(f"检测失败，状态码: {resp.status_code}")
        try:
            st.json(resp.json())
        except Exception:
            st.text(resp.text)
        return None

    return resp.json()


def _render_summary_metrics(summary: Dict[str, object]) -> None:
    processed = int(summary.get("processed_packets", 0) or 0)
    total = int(summary.get("total_packets_in_file", 0) or 0)
    avg_score = float(summary.get("avg_final_score", 0.0) or 0.0)
    high_ratio = float(summary.get("high_or_critical_ratio", 0.0) or 0.0)
    avg_ms = float(summary.get("avg_packet_time_ms", 0.0) or 0.0)

    render_metric_cards(
        [
            ("处理包数", f"{processed:,}", f"总包数 {total:,}"),
            ("平均风险分", f"{avg_score:.4f}", "分值越高风险通常越高"),
            ("高危占比", f"{high_ratio:.2%}", "HIGH + CRITICAL 比例"),
            ("平均单包耗时", f"{avg_ms:.2f} ms", "后端推理时延参考"),
        ]
    )


def _render_distribution_charts(summary: Dict[str, object]) -> None:
    threat_dist = summary.get("threat_level_distribution") or {}
    protocol_dist = summary.get("protocol_distribution") or {}

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.markdown("#### 威胁等级分布")
        if threat_dist:
            threat_df = pd.DataFrame({"level": list(threat_dist.keys()), "count": list(threat_dist.values())})
            threat_df.sort_values("count", ascending=False, inplace=True)
            fig, ax = plt.subplots(figsize=(6.8, 4.2))
            ax.bar(threat_df["level"], threat_df["count"], color="#0f766e")
            ax.set_xlabel("threat level")
            ax.set_ylabel("count")
            ax.grid(axis="y", alpha=0.18)
            st.pyplot(fig, width="stretch")
        else:
            st.info("暂无威胁等级分布数据。")

    with col2:
        st.markdown("#### 协议分布 (Top 8)")
        if protocol_dist:
            protocol_df = pd.DataFrame({"protocol": list(protocol_dist.keys()), "count": list(protocol_dist.values())})
            protocol_df.sort_values("count", ascending=False, inplace=True)
            top_df = protocol_df.head(8)
            fig2, ax2 = plt.subplots(figsize=(6.8, 4.2))
            ax2.barh(top_df["protocol"], top_df["count"], color="#0e7490")
            ax2.invert_yaxis()
            ax2.set_xlabel("count")
            ax2.grid(axis="x", alpha=0.18)
            st.pyplot(fig2, width="stretch")
        else:
            st.info("暂无协议分布数据。")


def _render_preview(preview: list[dict]) -> None:
    st.markdown("#### 逐包结果预览")
    if not preview:
        st.info("无可展示的逐包预览数据。")
        return

    df_preview = pd.DataFrame(preview)

    tab_a, tab_b = st.tabs(["风险视图", "明细表格"])
    with tab_a:
        has_score = "final_score" in df_preview.columns
        has_level = "threat_level" in df_preview.columns
        cols = st.columns(2, gap="large")

        with cols[0]:
            if has_score:
                fig, ax = plt.subplots(figsize=(6.5, 3.9))
                ax.plot(df_preview.index, df_preview["final_score"], color="#0f766e", linewidth=1.2)
                ax.fill_between(df_preview.index, df_preview["final_score"], alpha=0.16, color="#0f766e")
                ax.set_title("final_score 走势")
                ax.set_xlabel("packet order")
                ax.set_ylabel("score")
                ax.grid(alpha=0.16)
                st.pyplot(fig, width="stretch")
            else:
                st.info("预览中无 final_score 字段。")

        with cols[1]:
            if has_level:
                level_series = df_preview["threat_level"].astype(str).value_counts().sort_values(ascending=False)
                fig2, ax2 = plt.subplots(figsize=(6.5, 3.9))
                ax2.bar(level_series.index, level_series.values, color="#334155")
                ax2.set_title("threat_level 统计")
                ax2.set_xlabel("level")
                ax2.set_ylabel("count")
                ax2.grid(axis="y", alpha=0.16)
                st.pyplot(fig2, width="stretch")
            else:
                st.info("预览中无 threat_level 字段。")

    with tab_b:
        st.dataframe(df_preview, width="stretch", height=400)


def _render_downloads(run_id: str, csv_url: str, summary_url: str, backend_url: str) -> None:
    csv_full_url = _build_url(backend_url, csv_url)
    summary_full_url = _build_url(backend_url, summary_url)

    try:
        csv_resp = requests.get(csv_full_url, timeout=120)
        summary_resp = requests.get(summary_full_url, timeout=120)
    except requests.RequestException:
        st.warning("下载结果文件失败，可检查后端日志后重试。")
        return

    c1, c2 = st.columns(2)
    if csv_resp.status_code == 200:
        c1.download_button(
            "下载完整逐包 CSV",
            data=csv_resp.content,
            file_name=f"{run_id}_results.csv",
            mime="text/csv",
        )
    if summary_resp.status_code == 200:
        c2.download_button(
            "下载汇总 JSON",
            data=summary_resp.content,
            file_name=f"{run_id}_summary.json",
            mime="application/json",
        )


def _build_payload_evidence(summary: Dict[str, object], preview_df: pd.DataFrame) -> Dict[str, object]:
    top_packets = preview_df.copy()
    if "final_score" in top_packets.columns:
        top_packets = top_packets.sort_values("final_score", ascending=False)
    top_packets = top_packets.head(40)

    detail_cols = [
        col
        for col in ["packet_index", "protocol", "final_score", "threat_level", "confidence", "rule_hits", "elapsed_ms"]
        if col in top_packets.columns
    ]

    timeline_records = []
    if {"packet_index", "final_score"}.issubset(preview_df.columns):
        timeline_records = (
            preview_df[["packet_index", "final_score"]]
            .sort_values("packet_index")
            .head(500)
            .round(6)
            .to_dict("records")
        )

    return {
        "scene": "payload_detection",
        "summary": summary,
        "preview_size": int(len(preview_df)),
        "top_risk_packets": top_packets[detail_cols].fillna("").to_dict("records") if detail_cols else top_packets.fillna("").to_dict("records"),
        "score_timeline": timeline_records,
    }


def _render_payload_report_downloads(report_text: str, evidence_text: Dict[str, object]) -> None:
    txt_report = markdown_to_plain_text(report_text)
    html_report = build_report_html("通信包载荷检测 AI检测报告", report_text)

    try:
        pdf_bytes = build_report_pdf_bytes("通信包载荷检测 AI检测报告", report_text)
    except Exception as exc:
        pdf_bytes = None
        st.warning(f"PDF 导出暂不可用: {exc}")

    export_cols = st.columns(3, gap="small")
    with export_cols[0]:
        st.download_button(
            "导出报告 (MD)",
            data=report_text.encode("utf-8"),
            file_name="payload_ai_report.md",
            mime="text/markdown",
            key="payload_ai_download_md",
            width="stretch",
        )
    with export_cols[1]:
        st.download_button(
            "导出报告 (TXT)",
            data=txt_report.encode("utf-8"),
            file_name="payload_ai_report.txt",
            mime="text/plain",
            key="payload_ai_download_txt",
            width="stretch",
        )
    with export_cols[2]:
        st.download_button(
            "导出报告 (HTML)",
            data=html_report.encode("utf-8"),
            file_name="payload_ai_report.html",
            mime="text/html",
            key="payload_ai_download_html",
            width="stretch",
        )

    if pdf_bytes is not None:
        st.download_button(
            "导出报告 (PDF)",
            data=pdf_bytes,
            file_name="payload_ai_report.pdf",
            mime="application/pdf",
            key="payload_ai_download_pdf",
            width="stretch",
        )

    st.download_button(
        "下载证据链 (JSON)",
        data=json.dumps(evidence_text, ensure_ascii=False, indent=2, default=str).encode("utf-8"),
        file_name="payload_evidence.json",
        mime="application/json",
        key="payload_ai_download_evidence",
        width="stretch",
    )


def _render_payload_ai_report_dialog(report_text: str, evidence: Dict[str, object]) -> None:
    def _render_dialog_body() -> None:
        st.markdown("#### AI研判结果")
        st.markdown(report_text)

        st.markdown("#### 异常证据链")
        summary = evidence.get("summary", {}) if isinstance(evidence, dict) else {}
        metric_cols = st.columns(3, gap="small")
        metric_cols[0].metric("处理包数", str(summary.get("processed_packets", "-")))
        metric_cols[1].metric("平均风险分", f"{float(summary.get('avg_final_score', 0.0)):.4f}" if isinstance(summary.get("avg_final_score"), (int, float)) else "-")
        high_ratio = summary.get("high_or_critical_ratio", 0)
        metric_cols[2].metric("高危占比", f"{float(high_ratio):.2%}" if isinstance(high_ratio, (int, float)) else "-")

        timeline_records = evidence.get("score_timeline", []) if isinstance(evidence, dict) else []
        detail_records = evidence.get("top_risk_packets", []) if isinstance(evidence, dict) else []

        tab1, tab2, tab3 = st.tabs(["异常时序图", "指令详情", "原始证据"])
        with tab1:
            if timeline_records:
                timeline_df = pd.DataFrame(timeline_records)
                if {"packet_index", "final_score"}.issubset(timeline_df.columns):
                    timeline_df = timeline_df.sort_values("packet_index")
                    st.line_chart(timeline_df.set_index("packet_index")["final_score"], height=260)
                else:
                    st.dataframe(timeline_df, width="stretch", height=260)
            else:
                st.info("当前无可展示的异常时序数据。")
        with tab2:
            if detail_records:
                st.dataframe(pd.DataFrame(detail_records), width="stretch", height=320)
            else:
                st.info("当前无可展示的异常指令详情。")
        with tab3:
            st.json(evidence)

        st.markdown("#### 报告导出")
        _render_payload_report_downloads(report_text, evidence if isinstance(evidence, dict) else {})
        if st.button("关闭", key="payload_ai_dialog_close", width="stretch"):
            st.rerun()

    if hasattr(st, "dialog"):
        @st.dialog("AI检测报告", width="large")
        def _show_dialog() -> None:
            _render_dialog_body()

        _show_dialog()
    else:
        with st.container(border=True):
            st.markdown("### AI检测报告")
            _render_dialog_body()


def _render_ai_report_actions(summary: Dict[str, object], preview: list[dict]) -> None:
    st.subheader("AI检测报告")
    st.caption("报告输入: AI研判结果 + 异常证据链 + 原始流量；输出: 异常时序图、指令详情、漏洞分析、危害预测。")
    st.caption("DeepSeek 配置已从项目根目录 .env 自动读取。")

    cfg = get_deepseek_runtime_config()
    if not cfg.get("api_key"):
        st.warning("未检测到 DeepSeek API Key。请在 .env 中配置 DEEPSEEK_API_KEY 后再生成报告。")

    has_cached_report = bool(st.session_state.get("payload_ai_report"))
    action_cols = st.columns([1.2, 1.0], gap="small")
    with action_cols[0]:
        trigger_generate = st.button(
            "重新生成AI检测报告" if has_cached_report else "AI检测报告",
            type="primary",
            key="payload_ai_generate_modal",
            width="stretch",
        )
    with action_cols[1]:
        open_cached = st.button(
            "查看最近AI检测报告",
            key="payload_ai_open_cached",
            width="stretch",
            disabled=not has_cached_report,
        )

    show_modal = False
    if trigger_generate:
        preview_df = pd.DataFrame(preview)
        for col in ["packet_index", "final_score", "confidence", "rule_hits", "elapsed_ms", "anomaly_score"]:
            if col in preview_df.columns:
                preview_df[col] = pd.to_numeric(preview_df[col], errors="coerce")
        evidence = _build_payload_evidence(summary, preview_df)
        with st.spinner("AI 正在基于证据链生成报告，请稍候..."):
            try:
                report = generate_security_report(
                    scene_name="通信包载荷检测",
                    evidence=evidence,
                    api_key=str(cfg.get("api_key", "")),
                    base_url=str(cfg.get("base_url", "https://api.deepseek.com")),
                    model=str(cfg.get("model", "deepseek-chat")),
                    temperature=float(cfg.get("temperature", 0.2)),
                    max_tokens=int(cfg.get("max_tokens", 1800)),
                    timeout=int(cfg.get("timeout", 120)),
                )
            except Exception as exc:
                st.error(str(exc))
            else:
                st.session_state["payload_ai_report"] = report
                st.session_state["payload_ai_evidence"] = evidence
                st.success("AI检测报告已生成。")
                show_modal = True

    if open_cached:
        show_modal = True

    report_text = st.session_state.get("payload_ai_report", "")
    evidence_text = st.session_state.get("payload_ai_evidence", {})
    if show_modal and report_text:
        _render_payload_ai_report_dialog(str(report_text), evidence_text if isinstance(evidence_text, dict) else {})


def main() -> None:
    st.set_page_config(page_title="通信包载荷检测", layout="wide", initial_sidebar_state="collapsed")

    apply_modern_theme()
    render_top_nav(active="payload")
    left_col, right_col = st.columns([1, 2.45], gap="large")

    with left_col:
        limit, verbose, uploaded_file, run_button = _render_control_panel()

    with right_col:
        render_hero(
            "通信包载荷检测",
            "对 pcap 或 pcapng 执行逐包风险评分，输出威胁分布、协议画像与可下载检测结果。",
        )

        ensure_payload_backend(DEFAULT_BACKEND_URL)
        backend_url = DEFAULT_BACKEND_URL

        if run_button:
            result = _run_backend_detection(backend_url, uploaded_file, limit, verbose)
            if result:
                st.session_state[PAYLOAD_RESULT_STATE_KEY] = {
                    "result": result,
                    "summary": result.get("summary", {}),
                    "preview": result.get("preview", []),
                }
                st.session_state.pop("payload_ai_report", None)
                st.session_state.pop("payload_ai_evidence", None)

        detection_state = st.session_state.get(PAYLOAD_RESULT_STATE_KEY)
        if not detection_state:
            st.info("在左侧上传文件并点击“启动载荷风险检测”，可查看风险指标、分布图与逐包明细。")
            return

        result = detection_state["result"]
        summary = detection_state["summary"]
        preview = detection_state["preview"]

        st.success("检测完成")
        _render_summary_metrics(summary)

        top_tabs = st.tabs(["统计概览", "逐包分析", "原始输出"])
        with top_tabs[0]:
            _render_distribution_charts(summary)
        with top_tabs[1]:
            _render_preview(preview)
        with top_tabs[2]:
            st.subheader("文件级汇总")
            st.json(summary)
            logs = result.get("stdout_tail", [])
            if logs:
                st.subheader("后端日志尾部")
                st.code("\n".join(logs))

        _render_ai_report_actions(summary, preview)

        run_id = result.get("run_id")
        csv_url = result.get("download_csv_url")
        summary_url = result.get("download_summary_url")
        if run_id and csv_url and summary_url:
            st.markdown("#### 结果下载")
            _render_downloads(str(run_id), str(csv_url), str(summary_url), backend_url)
