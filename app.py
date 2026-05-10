import streamlit as st

st.set_page_config(page_title="Robot Security System", page_icon="R", layout="centered")

st.title("Robot Security System")
st.subheader("新版前端已迁移到 Vue + FastAPI")

st.write("当前检测能力和 AI 报告功能都在新版前后端中维护。")
st.code(
    "python -m uvicorn backend.payload_api.main:app --host 127.0.0.1 --port 8010\n"
    "cd web\n"
    "npm.cmd run dev",
    language="powershell",
)

st.info("后端默认地址为 http://127.0.0.1:8010，前端默认由 Vite 输出本地访问地址。")
