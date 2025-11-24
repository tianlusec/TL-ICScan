import streamlit as st
import sqlite3
import pandas as pd
import json
from datetime import datetime

# 设置页面配置
st.set_page_config(
    page_title="Tianlu 情报看板",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Tianlu 漏洞情报收集系统")

# 侧边栏：筛选条件
st.sidebar.header("🔍 筛选条件")

# 搜索框
search_term = st.sidebar.text_input("关键字搜索 (标题/描述)", "")

# 严重等级筛选
severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
selected_severity = st.sidebar.multiselect("严重等级", severity_options, default=["CRITICAL", "HIGH"])

# 日期范围
# 默认展示最近 30 天
default_start = datetime.now().date().replace(day=1)
date_range = st.sidebar.date_input("发布时间范围", [])

# 连接数据库
@st.cache_data(ttl=60)  # 缓存数据 60 秒
def load_data(severity_list, search_text, date_filter):
    db_path = "tianlu_intel_v2.db"
    import os
    
    # Try to find DB in current or parent directory
    if not os.path.exists(db_path):
        if os.path.exists("../tianlu_intel_v2.db"):
            db_path = "../tianlu_intel_v2.db"
        elif os.path.exists("tianlu_intel.db"):
            db_path = "tianlu_intel.db"
        elif os.path.exists("../tianlu_intel.db"):
            db_path = "../tianlu_intel.db"

    conn = sqlite3.connect(db_path)
    
    # Check if is_in_kev column exists (for backward compatibility)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(cve_records)")
    columns = [info[1] for info in cursor.fetchall()]
    has_kev = "is_in_kev" in columns
    
    select_cols = "cve_id, severity, cvss_v3_score, title, publish_date, vendors, products, sources"
    if has_kev:
        select_cols += ", is_in_kev, attack_vector"

    query = f"SELECT {select_cols} FROM cve_records WHERE 1=1"
    params = []

    # 严重等级过滤
    if severity_list:
        placeholders = ",".join("?" * len(severity_list))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity_list)
    
    # 关键字过滤
    if search_text:
        query += " AND (title LIKE ? OR description LIKE ? OR cve_id LIKE ?)"
        wildcard = f"%{search_text}%"
        params.extend([wildcard, wildcard, wildcard])

    # 日期过滤 (简单处理，假设 date_filter 是个列表)
    if len(date_filter) == 2:
        start_date, end_date = date_filter
        query += " AND publish_date >= ? AND publish_date <= ?"
        params.extend([start_date.isoformat(), end_date.isoformat()])

    query += " ORDER BY publish_date DESC LIMIT 500"
    
    try:
        df = pd.read_sql_query(query, conn, params=params)
    finally:
        conn.close()
    
    return df

# 加载数据
df = load_data(selected_severity, search_term, date_range)

# 展示统计信息
col1, col2, col3 = st.columns(3)
col1.metric("当前展示数量", len(df))
if not df.empty:
    col2.metric("最高 CVSS 分数", df["cvss_v3_score"].max())
    latest_date = pd.to_datetime(df["publish_date"]).max()
    col3.metric("最新收录", latest_date.strftime("%Y-%m-%d") if pd.notnull(latest_date) else "-")

# 主表格展示
st.subheader("📋 漏洞列表")

if not df.empty:
    # 格式化一下数据，让 JSON 字段好看点
    # 但 Streamlit 的 dataframe 交互性已经不错了，直接展示
    
    # 自定义列配置
    column_config = {
        "cve_id": "CVE ID",
        "severity": st.column_config.TextColumn("严重等级", help="Low, Medium, High, Critical"),
        "cvss_v3_score": st.column_config.NumberColumn("CVSS v3", format="%.1f"),
        "title": "标题",
        "publish_date": st.column_config.DatetimeColumn("发布时间", format="YYYY-MM-DD HH:mm"),
        "vendors": "厂商",
        "products": "产品",
        "sources": "来源",
    }
    
    if "is_in_kev" in df.columns:
        column_config["is_in_kev"] = st.column_config.CheckboxColumn("KEV?", help="是否在 CISA KEV 列表中")
    if "attack_vector" in df.columns:
        column_config["attack_vector"] = "攻击向量"

    st.dataframe(
        df,
        column_config=column_config,
        use_container_width=True,
        hide_index=True,
        height=600
    )
else:
    st.info("没有找到符合条件的漏洞情报。请尝试调整左侧的筛选条件。")

# 详情查看器 (简单版)
st.divider()
st.subheader("📝 快速详情查看")
cve_to_check = st.text_input("输入 CVE ID 查看完整详情 (例如 CVE-2025-13576)", "")

if cve_to_check:
    conn = sqlite3.connect("tianlu_intel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_records WHERE cve_id = ?", (cve_to_check,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        # 获取列名
        col_names = [description[0] for description in cursor.description]
        data = dict(zip(col_names, row))
        
        st.markdown(f"### {data['cve_id']}")
        st.markdown(f"**标题**: {data['title']}")
        
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**严重等级**: {data['severity']}")
        c2.markdown(f"**CVSS v3**: {data['cvss_v3_score']}")
        c3.markdown(f"**发布时间**: {data['publish_date']}")
        
        st.markdown("#### 描述")
        st.info(data['description'])
        
        st.markdown("#### 影响范围")
        st.json({
            "Vendors": json.loads(data['vendors']),
            "Products": json.loads(data['products'])
        })
        
        st.markdown("#### 参考链接")
        for ref in json.loads(data['references']):
            st.markdown(f"- {ref}")
            
    else:
        st.error("未找到该 CVE ID。")
