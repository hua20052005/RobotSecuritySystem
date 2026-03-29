import json

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="载荷检测页面", layout="wide")

st.title("Payload-Detection 独立检测页面")
st.caption("该页面通过独立后端服务执行检测，不影响主页面的旧检测逻辑。")

with st.sidebar:
    st.subheader("后端连接")
    backend_url = st.text_input("Payload后端地址", "http://127.0.0.1:8010")
    limit = st.number_input("最多处理包数 (0 表示不限)", min_value=0, value=0, step=100)
    verbose = st.checkbox("显示详细日志", value=False)
    uploaded_file = st.file_uploader("上传 .pcap / .pcapng", type=["pcap", "pcapng"])
    run_button = st.button("开始执行载荷检测", type="primary")


def _build_url(base: str, suffix: str) -> str:
    return f"{base.rstrip('/')}{suffix}"


if run_button:
    if uploaded_file is None:
        st.warning("请先上传 pcap 文件。")
    else:
        files = {
            "file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream"),
        }
        data = {
            "verbose": "true" if verbose else "false",
        }
        if limit > 0:
            data["limit"] = str(limit)

        endpoint = _build_url(backend_url, "/detect-file")
        with st.spinner("正在调用独立后端执行检测..."):
            try:
                resp = requests.post(endpoint, files=files, data=data, timeout=1800)
            except requests.RequestException as e:
                st.error(f"后端连接失败: {e}")
                st.stop()

        if resp.status_code != 200:
            st.error(f"检测失败，状态码: {resp.status_code}")
            try:
                st.json(resp.json())
            except Exception:
                st.text(resp.text)
            st.stop()

        result = resp.json()
        summary = result.get("summary", {})
        preview = result.get("preview", [])

        st.success("检测完成")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("处理包数", summary.get("processed_packets", 0))
        with col2:
            st.metric("平均风险分", summary.get("avg_final_score", 0))
        with col3:
            st.metric("高危占比", summary.get("high_or_critical_ratio", 0))

        st.subheader("文件级汇总")
        st.json(summary)

        if preview:
            st.subheader("逐包结果预览")
            df_preview = pd.DataFrame(preview)
            st.dataframe(df_preview, use_container_width=True)
        else:
            st.info("无可展示的逐包预览数据。")

        run_id = result.get("run_id")
        csv_url = result.get("download_csv_url")
        summary_url = result.get("download_summary_url")

        if run_id and csv_url and summary_url:
            csv_full_url = _build_url(backend_url, csv_url)
            summary_full_url = _build_url(backend_url, summary_url)

            try:
                csv_resp = requests.get(csv_full_url, timeout=120)
                summary_resp = requests.get(summary_full_url, timeout=120)
                if csv_resp.status_code == 200:
                    st.download_button(
                        "下载完整逐包CSV",
                        data=csv_resp.content,
                        file_name=f"{run_id}_results.csv",
                        mime="text/csv",
                    )
                if summary_resp.status_code == 200:
                    st.download_button(
                        "下载汇总JSON",
                        data=summary_resp.content,
                        file_name=f"{run_id}_summary.json",
                        mime="application/json",
                    )
            except requests.RequestException:
                st.warning("下载结果文件失败，可检查后端日志后重试。")

        logs = result.get("stdout_tail", [])
        if logs:
            st.subheader("后端日志尾部")
            st.code("\n".join(logs))
else:
    st.info("在左侧上传文件后，点击开始执行载荷检测。")
