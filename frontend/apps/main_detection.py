from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

from core.feature_eng import pcap_to_dataframe
from frontend.shared.ai_report import (
    build_report_html,
    build_report_pdf_bytes,
    generate_security_report,
    get_deepseek_runtime_config,
    markdown_to_plain_text,
)
from frontend.shared.ui_theme import apply_modern_theme, render_hero, render_metric_cards, render_top_nav, safe_columns

TARGET_IP = "10.4.0.3"
TEMP_PCAP_PATH = os.path.join("data", "temp_upload.pcap")
SIDE_RESULT_STATE_KEY = "side_detection_state"


def _render_control_panel() -> Tuple[object, List[str], float, bool]:
    st.markdown('<section class="control-panel-card">', unsafe_allow_html=True)
    st.markdown('<h3 class="control-panel-title">控制面板</h3>', unsafe_allow_html=True)
    st.markdown('<p class="control-panel-hint">上传流量文件并配置审计参数，建议先使用默认选项快速完成首轮分析。</p>', unsafe_allow_html=True)

    st.markdown('<div class="panel-group-label">文件输入</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("上传流量包 (.pcap)", type=["pcap"])
    st.markdown('<div class="panel-group-label">分析维度</div>', unsafe_allow_html=True)
    feature_map = {
        "目的IP编号": "dst_ip_num",
        "目的端口": "port",
        "报文长度": "size",
        "载荷熵值": "entropy",
        "源IP编号": "src_ip_num",
    }

    selected_features: List[str] = []
    for idx, (label, key) in enumerate(feature_map.items()):
        default_value = idx < 2
        if st.checkbox(label, value=default_value):
            selected_features.append(key)

    st.markdown('<div class="panel-group-label">风险阈值</div>', unsafe_allow_html=True)
    contamination = st.slider("异常比例阈值", 0.01, 0.20, 0.06)
    run_button = st.button("启动侧信道审计", type="primary", width="stretch")
    st.markdown('</section>', unsafe_allow_html=True)
    return uploaded_file, selected_features, contamination, run_button


def _run_detection(pcap_path: str, features: List[str], contamination: float) -> Tuple[pd.DataFrame, pd.DataFrame]:
    df = pcap_to_dataframe(pcap_path)
    model = IsolationForest(n_estimators=120, contamination=contamination, random_state=42)
    feature_frame = df[features]
    df["anomaly_label"] = model.fit_predict(feature_frame)
    df["anomaly_score"] = model.decision_function(feature_frame)

    anomalies = df[df["anomaly_label"] == -1].copy()
    anomalies.sort_values(by="anomaly_score", inplace=True)
    return df, anomalies


def _render_overview(df: pd.DataFrame, anomalies: pd.DataFrame) -> None:
    total = len(df)
    abnormal = len(anomalies)
    ratio = (abnormal / total) if total else 0.0
    avg_score = float(df["anomaly_score"].mean()) if total else 0.0

    render_metric_cards(
        [
            ("总包数", f"{total:,}", "参与本次审计的数据包总量"),
            ("异常包数", f"{abnormal:,}", "IsolationForest 判定为异常的样本数"),
            ("异常占比", f"{ratio:.2%}", "用于快速判断风险密度"),
            ("平均离群得分", f"{avg_score:.4f}", "分值越低通常越可疑"),
        ]
    )


def _render_visuals(df: pd.DataFrame, anomalies: pd.DataFrame, features: List[str]) -> None:
    st.subheader("多维可视分析")
    col1, col2 = st.columns([1.45, 1.0], gap="large")

    with col1:
        x_axis = features[0]
        y_axis = features[1] if len(features) > 1 else "idx"
        if y_axis not in df.columns:
            df = df.copy()
            df["idx"] = range(len(df))

        fig, ax = plt.subplots(figsize=(9, 5.6))
        scatter = ax.scatter(
            df[x_axis],
            df[y_axis],
            c=df["anomaly_score"],
            cmap="RdYlBu_r",
            s=18,
            alpha=0.72,
            edgecolors="none",
        )
        cbar = plt.colorbar(scatter, ax=ax, pad=0.01)
        cbar.set_label("Anomaly Score", rotation=270, labelpad=15)
        ax.set_title("异常分布散点图")
        ax.set_xlabel(x_axis)
        ax.set_ylabel(y_axis)
        ax.grid(alpha=0.16)
        st.pyplot(fig, width="stretch")

    with col2:
        fig2, ax2 = plt.subplots(figsize=(7, 5.6))
        ax2.hist(df["anomaly_score"], bins=28, color="#0f766e", alpha=0.88)
        ax2.axvline(df["anomaly_score"].quantile(0.05), color="#b91c1c", linestyle="--", linewidth=1.5)
        ax2.set_title("离群得分分布")
        ax2.set_xlabel("anomaly_score")
        ax2.set_ylabel("count")
        ax2.grid(alpha=0.15)
        st.pyplot(fig2, width="stretch")

    st.subheader(f"重点目标追踪: {TARGET_IP}")
    target_hits = anomalies[anomalies.get("dst", "") == TARGET_IP] if "dst" in anomalies.columns else pd.DataFrame()
    if not target_hits.empty:
        st.success(f"成功捕获 {len(target_hits)} 个目标 IP 异常包。")
        hit_cols = safe_columns(target_hits.columns, ["idx", "src", "dst", "port", "size", "entropy", "anomaly_score"])
        st.dataframe(target_hits[hit_cols], width="stretch")
    else:
        st.info("当前异常结果中未发现目标 IP。")


def _render_anomaly_table(anomalies: pd.DataFrame) -> None:
    st.subheader("异常通信包清单")
    show_cols = safe_columns(anomalies.columns, ["idx", "src", "dst", "port", "size", "entropy", "anomaly_score"])
    st.dataframe(anomalies[show_cols] if show_cols else anomalies, width="stretch", height=380)

    csv_bytes = anomalies.to_csv(index=False).encode("utf-8")
    st.download_button("导出审计报告 (CSV)", csv_bytes, "audit_report.csv", "text/csv")


def _build_side_channel_evidence(
    df: pd.DataFrame,
    anomalies: pd.DataFrame,
    features: List[str],
    contamination: float,
) -> Dict[str, Any]:
    total = len(df)
    abnormal = len(anomalies)
    ratio = (abnormal / total) if total else 0.0

    detail_cols = safe_columns(
        anomalies.columns,
        ["idx", "timestamp", "src", "dst", "port", "size", "entropy", "anomaly_score", "raw_hex_head"],
    )
    top_anomalies = anomalies.nsmallest(min(30, len(anomalies)), "anomaly_score") if "anomaly_score" in anomalies.columns else anomalies.head(30)
    top_records = top_anomalies[detail_cols].fillna("").to_dict("records") if detail_cols else top_anomalies.fillna("").head(30).to_dict("records")

    timeline_records = []
    if {"idx", "anomaly_score"}.issubset(df.columns):
        timeline_records = (
            df[["idx", "anomaly_score"]]
            .sort_values("idx")
            .tail(500)
            .round(6)
            .to_dict("records")
        )

    return {
        "scene": "side_channel_analysis",
        "selected_features": features,
        "contamination": contamination,
        "summary": {
            "total_packets": total,
            "anomaly_packets": abnormal,
            "anomaly_ratio": round(ratio, 6),
            "mean_anomaly_score": round(float(df["anomaly_score"].mean()), 6) if total and "anomaly_score" in df.columns else 0.0,
            "target_ip": TARGET_IP,
        },
        "top_anomalies": top_records,
        "timeline_tail": timeline_records,
    }


def _render_side_report_downloads(report_text: str, evidence_text: Dict[str, Any]) -> None:
    txt_report = markdown_to_plain_text(report_text)
    html_report = build_report_html("侧信道分析 AI检测报告", report_text)

    try:
        pdf_bytes = build_report_pdf_bytes("侧信道分析 AI检测报告", report_text)
    except Exception as exc:
        pdf_bytes = None
        st.warning(f"PDF 导出暂不可用: {exc}")

    export_cols = st.columns(3, gap="small")
    with export_cols[0]:
        st.download_button(
            "导出报告 (MD)",
            data=report_text.encode("utf-8"),
            file_name="side_channel_ai_report.md",
            mime="text/markdown",
            key="side_ai_download_md",
            width="stretch",
        )
    with export_cols[1]:
        st.download_button(
            "导出报告 (TXT)",
            data=txt_report.encode("utf-8"),
            file_name="side_channel_ai_report.txt",
            mime="text/plain",
            key="side_ai_download_txt",
            width="stretch",
        )
    with export_cols[2]:
        st.download_button(
            "导出报告 (HTML)",
            data=html_report.encode("utf-8"),
            file_name="side_channel_ai_report.html",
            mime="text/html",
            key="side_ai_download_html",
            width="stretch",
        )

    if pdf_bytes is not None:
        st.download_button(
            "导出报告 (PDF)",
            data=pdf_bytes,
            file_name="side_channel_ai_report.pdf",
            mime="application/pdf",
            key="side_ai_download_pdf",
            width="stretch",
        )

    st.download_button(
        "下载证据链 (JSON)",
        data=json.dumps(evidence_text, ensure_ascii=False, indent=2, default=str).encode("utf-8"),
        file_name="side_channel_evidence.json",
        mime="application/json",
        key="side_ai_download_evidence",
        width="stretch",
    )


def _render_side_ai_report_dialog(report_text: str, evidence: Dict[str, Any]) -> None:
    def _render_dialog_body() -> None:
        st.markdown("#### AI研判结果")
        st.markdown(report_text)

        st.markdown("#### 异常证据链")
        summary = evidence.get("summary", {}) if isinstance(evidence, dict) else {}
        metric_cols = st.columns(3, gap="small")
        metric_cols[0].metric("总包数", str(summary.get("total_packets", "-")))
        metric_cols[1].metric("异常包数", str(summary.get("anomaly_packets", "-")))
        ratio = summary.get("anomaly_ratio", 0)
        metric_cols[2].metric("异常占比", f"{float(ratio):.2%}" if isinstance(ratio, (int, float)) else "-")

        timeline_records = evidence.get("timeline_tail", []) if isinstance(evidence, dict) else []
        detail_records = evidence.get("top_anomalies", []) if isinstance(evidence, dict) else []

        tab1, tab2, tab3 = st.tabs(["异常时序图", "指令详情", "原始证据"])
        with tab1:
            if timeline_records:
                timeline_df = pd.DataFrame(timeline_records)
                if {"idx", "anomaly_score"}.issubset(timeline_df.columns):
                    timeline_df = timeline_df.sort_values("idx")
                    st.line_chart(timeline_df.set_index("idx")["anomaly_score"], height=260)
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
        _render_side_report_downloads(report_text, evidence if isinstance(evidence, dict) else {})
        if st.button("关闭", key="side_ai_dialog_close", width="stretch"):
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


def _render_ai_report_actions(df: pd.DataFrame, anomalies: pd.DataFrame, features: List[str], contamination: float) -> None:
    st.subheader("AI检测报告")
    st.caption("报告输入: AI研判结果 + 异常证据链 + 原始流量；输出: 异常时序图、指令详情、漏洞分析、危害预测。")
    st.caption("DeepSeek 配置已从项目根目录 .env 自动读取。")

    cfg = get_deepseek_runtime_config()
    if not cfg.get("api_key"):
        st.warning("未检测到 DeepSeek API Key。请在 .env 中配置 DEEPSEEK_API_KEY 后再生成报告。")

    has_cached_report = bool(st.session_state.get("side_ai_report"))
    action_cols = st.columns([1.2, 1.0], gap="small")
    with action_cols[0]:
        trigger_generate = st.button(
            "重新生成AI检测报告" if has_cached_report else "AI检测报告",
            type="primary",
            key="side_ai_generate_modal",
            width="stretch",
        )
    with action_cols[1]:
        open_cached = st.button(
            "查看最近AI检测报告",
            key="side_ai_open_cached",
            width="stretch",
            disabled=not has_cached_report,
        )

    show_modal = False
    if trigger_generate:
        evidence = _build_side_channel_evidence(df, anomalies, features, contamination)
        with st.spinner("AI 正在基于证据链生成报告，请稍候..."):
            try:
                report = generate_security_report(
                    scene_name="侧信道分析",
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
                st.session_state["side_ai_report"] = report
                st.session_state["side_ai_evidence"] = evidence
                st.success("AI检测报告已生成。")
                show_modal = True

    if open_cached:
        show_modal = True

    report_text = st.session_state.get("side_ai_report", "")
    evidence_text = st.session_state.get("side_ai_evidence", {})
    if show_modal and report_text:
        _render_side_ai_report_dialog(str(report_text), evidence_text if isinstance(evidence_text, dict) else {})


def main() -> None:
    st.set_page_config(page_title="侧信道分析", layout="wide", initial_sidebar_state="collapsed")

    apply_modern_theme()
    render_top_nav(active="side")
    left_col, right_col = st.columns([1, 2.45], gap="large")

    with left_col:
        uploaded_file, features, contamination, run_button = _render_control_panel()

    with right_col:
        render_hero(
            "侧信道分析",
            "基于流量统计特征与离群检测识别异常通信行为，提供可视化审计与重点目标追踪。",
        )

        if run_button:
            if not uploaded_file:
                st.warning("请先上传 PCAP 文件。")
            elif not features:
                st.error("请至少选择一个分析维度。")
            else:
                with open(TEMP_PCAP_PATH, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                with st.spinner("正在解析流量并计算离群得分，请稍候..."):
                    df, anomalies = _run_detection(TEMP_PCAP_PATH, features, contamination)

                st.session_state[SIDE_RESULT_STATE_KEY] = {
                    "df": df,
                    "anomalies": anomalies,
                    "features": features,
                    "contamination": contamination,
                }
                st.session_state.pop("side_ai_report", None)
                st.session_state.pop("side_ai_evidence", None)

        detection_state = st.session_state.get(SIDE_RESULT_STATE_KEY)
        if not detection_state:
            st.info("上传 PCAP 后点击“启动侧信道审计”，即可生成检测结果、图表分析与证据链输出。")
            return

        df = detection_state["df"]
        anomalies = detection_state["anomalies"]
        features = detection_state["features"]
        contamination = float(detection_state["contamination"])

        _render_overview(df, anomalies)

        tab1, tab2 = st.tabs(["可视化分析", "审计明细"])
        with tab1:
            _render_visuals(df, anomalies, features)
        with tab2:
            _render_anomaly_table(anomalies)

        _render_ai_report_actions(df, anomalies, features, contamination)
