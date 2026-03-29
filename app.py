import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from core.feature_eng import pcap_to_dataframe
import os

# 页面配置
st.set_page_config(page_title="具身智能安全审计系统", layout="wide")

st.title("🛡️ 具身智能控制链路安全审计系统")
st.markdown("---")

# 1. 侧边栏：文件上传与参数设置
with st.sidebar:
    st.header("控制面板")
    uploaded_file = st.file_uploader("上传流量包 (.pcap)", type=["pcap"])
    
    st.subheader("分析维度选择")
    f_ip = st.checkbox("目的IP编号", value=True)
    f_port = st.checkbox("目的端口", value=True)
    f_size = st.checkbox("报文长度", value=False)
    f_entropy = st.checkbox("载荷熵值", value=False)
    f_src = st.checkbox("源IP编号", value=False)
    
    contamination = st.slider("异常比例阈值 (Contamination)", 0.01, 0.20, 0.06)
    run_button = st.button("开始深度审计", type="primary")

# 2. 执行逻辑
if uploaded_file is not None and run_button:
    # 保存上传的文件到临时目录
    temp_path = os.path.join("data", "temp_upload.pcap")
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    with st.spinner("正在解析 PCAP 文件并计算离群得分..."):
        # 提取特征
        df = pcap_to_dataframe(temp_path)
        
        # 构建特征列表
        features = []
        if f_ip: features.append('dst_ip_num')
        if f_port: features.append('port')
        if f_size: features.append('size')
        if f_entropy: features.append('entropy')
        if f_src: features.append('src_ip_num')
        
        if not features:
            st.error("请至少选择一个分析维度！")
        else:
            # 训练模型
            model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
            X = df[features]
            df['anomaly_label'] = model.fit_predict(X)
            df['anomaly_score'] = model.decision_function(X)
            
            # 排序数据
            anomalies = df[df['anomaly_label'] == -1].sort_values(by='anomaly_score')
            
            # 3. 结果展示：布局分为左右两栏
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.subheader("📊 异常分布可视化")
                fig, ax = plt.subplots(figsize=(10, 6))
                # 选取前两个特征进行绘图
                x_axis = features[0]
                y_axis = features[1] if len(features) > 1 else 'idx'
                
                scatter = ax.scatter(df[x_axis], df[y_axis], c=df['anomaly_score'], 
                                   cmap='RdYlBu', s=15, alpha=0.6)
                plt.colorbar(scatter, ax=ax, label="Anomaly Score")
                ax.set_xlabel(x_axis)
                ax.set_ylabel(y_axis)
                st.pyplot(fig)

            with col2:
                st.subheader("🎯 重点目标追踪 (10.4.0.3)")
                target_hits = anomalies[anomalies['dst'] == "10.4.0.3"]
                if not target_hits.empty:
                    st.success(f"成功捕获 {len(target_hits)} 个注入包！")
                    st.dataframe(target_hits[['idx', 'port', 'size', 'anomaly_score']])
                else:
                    st.warning("在当前异常清单中未发现目标 IP。")

            # 4. 全量异常清单
            st.markdown("---")
            st.subheader("📑 异常通信包详细审计清单 (可供排查)")
            st.write(f"算法判定的前 {len(anomalies)} 个最可疑数据包：")
            st.dataframe(anomalies[['idx', 'src', 'dst', 'port', 'size', 'entropy', 'anomaly_score']], use_container_width=True)
            
            # 下载按钮
            csv = anomalies.to_csv(index=False).encode('utf-8')
            st.download_button("导出审计报告 (CSV)", csv, "audit_report.csv", "text/csv")

else:
    st.info("请在左侧上传 PCAP 流量包并点击『开始深度审计』")