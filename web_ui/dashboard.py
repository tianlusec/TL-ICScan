import streamlit as st
import streamlit.components.v1 as components
import sqlite3
import pandas as pd
import json
import re
import subprocess
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

log_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(log_dir, 'web_ui_errors.log')

logger = logging.getLogger()
logger.setLevel(logging.ERROR)
handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

st.set_page_config(
    page_title="TL-ICScan",
    page_icon="logo.ico",
    layout="wide",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "TL-ICScan (个人版)"
    },
    initial_sidebar_state="expanded"
)

hide_streamlit_style = """
<style>
header[data-testid="stHeader"] button {
    display: none !important;
}

section[data-testid="stSidebar"] button {
    display: none !important;
}

[data-testid="stSidebarCollapsedControl"] {
    display: none !important;
}
[data-testid="stToolbar"] {
    display: none !important;
}
[data-testid="stDeployButton"] {
    display: none !important;
}
#MainMenu {
    display: none !important;
}
footer {
    display: none !important;
}

[data-testid="stDecoration"] {
    display: none !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    pointer-events: none !important;
    height: 0px !important; 
}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("TL-ICScan 漏洞情报聚合与分析工具")

st.sidebar.header("筛选条件")

search_term = st.sidebar.text_input("关键字搜索 (标题/描述)", "")

severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
selected_severity = st.sidebar.multiselect("严重等级", severity_options, default=["CRITICAL", "HIGH"])

source_options = ["nvd", "cisa_kev", "msrc", "exploit_db", "github_poc"]
selected_sources = st.sidebar.multiselect("数据源", source_options, default=source_options)

today = datetime.now().date()
last_30_days = today - pd.Timedelta(days=30)
date_range = st.sidebar.date_input("发布时间范围", [last_30_days, today])

sort_mode = st.sidebar.selectbox(
    "数据排序 (影响 Top 500 选取)",
    ["发布时间 (最新)", "CVSS 分数 (最高)", "严重等级 (最高)"]
)

def get_db_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(base_dir, "tianlu_intel_v2.db"),
        os.path.join(base_dir, "../tianlu_intel_v2.db"),
        os.path.join(base_dir, "tianlu_intel.db"),
        os.path.join(base_dir, "../tianlu_intel.db"),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return os.path.abspath(path)
            
    return os.path.abspath(os.path.join(base_dir, "../tianlu_intel_v2.db"))

@st.cache_data(ttl=3600)
def load_data(severity_list, search_text, date_filter, source_filter, sort_mode):
    db_path = get_db_path()
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(cve_records)")
    columns = [info[1] for info in cursor.fetchall()]
    has_kev = "is_in_kev" in columns
    
    select_cols = 'cve_id, severity, cvss_v3_score, title, publish_date, vendors, products, sources, "references"'
    if has_kev:
        select_cols += ", is_in_kev, attack_vector"

    query = f"SELECT {select_cols} FROM cve_records WHERE 1=1"
    params = []

    if severity_list:
        placeholders = ",".join("?" * len(severity_list))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity_list)
    
    if source_filter:
        source_conditions = []
        for source in source_filter:
            source_conditions.append("sources LIKE ?")
            params.append(f'%"{source}"%')
        
        if source_conditions:
            query += " AND (" + " OR ".join(source_conditions) + ")"
    
    if search_text:
        query += " AND (title LIKE ? OR description LIKE ? OR cve_id LIKE ?)"
        wildcard = f"%{search_text}%"
        params.extend([wildcard, wildcard, wildcard])

    if len(date_filter) == 2:
        start_date, end_date = date_filter
        import datetime as dt
        next_day = end_date + dt.timedelta(days=1)
        
        query += " AND publish_date >= ? AND publish_date < ?"
        params.extend([start_date.isoformat(), next_day.isoformat()])

    if sort_mode == "CVSS 分数 (最高)":
        query += " ORDER BY cvss_v3_score DESC, publish_date DESC"
    elif sort_mode == "严重等级 (最高)":
        query += """ ORDER BY 
            CASE 
                WHEN severity LIKE 'CRITICAL' THEN 1 
                WHEN severity LIKE 'HIGH' THEN 2 
                WHEN severity LIKE 'MEDIUM' THEN 3 
                WHEN severity LIKE 'LOW' THEN 4 
                ELSE 5 
            END ASC, cvss_v3_score DESC, publish_date DESC"""
    else:
        query += " ORDER BY publish_date DESC"

    query += " LIMIT 500"
    
    try:
        df = pd.read_sql_query(query, conn, params=params)
    finally:
        conn.close()
    
    if 'severity' in df.columns:
        df['severity'] = df['severity'].astype(str).str.upper().str.strip()
        
        df['severity'] = df['severity'].replace(['NONE', 'NAN', 'NULL', ''], 'UNKNOWN').fillna('UNKNOWN')
        
        severity_order = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        df['severity'] = pd.Categorical(df['severity'], categories=severity_order, ordered=True)
        
        if df['severity'].isnull().any():
             df['severity'] = df['severity'].fillna('UNKNOWN')

    if 'publish_date' in df.columns:
        df['publish_date'] = pd.to_datetime(df['publish_date'], errors='coerce')

    return df

df = load_data(selected_severity, search_term, date_range, selected_sources, sort_mode)


def get_total_vuln_count():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_records")
        total = cursor.fetchone()[0]
    except Exception:
        total = '-'
    finally:
        conn.close()
    return total

total_vuln_count = get_total_vuln_count()
col1, col2, col3, col4 = st.columns(4)
col1.metric("漏洞库总数", total_vuln_count)
col2.metric("当前展示数量", len(df))
if not df.empty:
    col3.metric("最高 CVSS 分数", df["cvss_v3_score"].max())
    latest_date = pd.to_datetime(df["publish_date"], format='mixed', errors='coerce').max()
    col4.metric("最新收录", latest_date.strftime("%Y-%m-%d") if pd.notnull(latest_date) else "-")

st.subheader("漏洞列表")

if not df.empty:
    def extract_first_url(refs_json):
        try:
            if not refs_json: return None
            refs = json.loads(refs_json)
            if isinstance(refs, list) and len(refs) > 0:
                return refs[0]
        except:
            pass
        return None

    df["url"] = df["references"].apply(extract_first_url)
    df = df.drop(columns=["references"])

    column_config = {
        "cve_id": "CVE ID",
        "severity": st.column_config.Column("严重等级", help="Low, Medium, High, Critical"),
        "cvss_v3_score": st.column_config.NumberColumn("CVSS v3", format="%.1f"),
        "title": "标题",
        "publish_date": st.column_config.DatetimeColumn("发布时间", format="YYYY-MM-DD HH:mm"),
        "vendors": "厂商",
        "products": "产品",
        "sources": "来源",
        "url": st.column_config.LinkColumn("链接", display_text="点击跳转"),
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

st.divider()
st.subheader("快速详情查看")
cve_to_check = st.text_input("输入 CVE ID 查看完整详情 (例如 CVE-2025-13576)", "")

data = None
if cve_to_check:
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cve_records WHERE cve_id = ?", (cve_to_check,))
        row = cursor.fetchone()
        if row:
            col_names = [description[0] for description in cursor.description] if cursor.description else []
            data = dict(zip(col_names, row))
        else:
            data = None
    finally:
        conn.close()

import html

if data:
    st.markdown(f"### {data.get('cve_id', '')}")
    safe_title = html.escape(data.get('title') or "")
    st.markdown(f"**标题**: {safe_title}")
    
    c1, c2, c3 = st.columns(3)
    c1.markdown(f"**严重等级**: {data['severity']}")
    c2.markdown(f"**CVSS v3**: {data['cvss_v3_score']}")
    c3.markdown(f"**发布时间**: {data['publish_date']}")
    
    st.markdown("#### 描述")
    safe_description = html.escape(data.get('description') or "")
    st.info(safe_description)
    
    st.markdown("#### 影响范围")
    try:
        vendors = json.loads(data.get('vendors') or '[]')
    except Exception:
        vendors = []
    try:
        products = json.loads(data.get('products') or '[]')
    except Exception:
        products = []
    st.json({
        "Vendors": vendors,
        "Products": products
    })
    
    st.markdown("#### 参考链接")
    try:
        refs_list = json.loads(data.get('references') or '[]')
    except Exception:
        refs_list = []
    for ref in refs_list:
        st.markdown(f"- {ref}")
            
    else:
        st.warning(f"本地数据库中未找到 {cve_to_check}。")
        
        if st.button(f"尝试在线查询并入库 {cve_to_check}"):
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_to_check):
                st.error("无效的 CVE ID 格式。")
                st.stop()

            status_text = st.empty()
            status_text.info("正在从 NVD 查询数据，请稍候...")
            
            python_exe = sys.executable
            
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(current_dir, ".."))
            
            rust_bin_rel = os.path.join("tianlu-intel-core", "target", "release", "tianlu-intel-core")
            if os.name == 'nt':
                rust_bin_rel += ".exe"
            
            rust_bin = os.path.join(project_root, rust_bin_rel)
            
            if not os.path.exists(rust_bin):
                st.error(f"找不到 tianlu-intel-core 二进制文件: {rust_bin}")
            else:
                try:
                    env = os.environ.copy()
                    env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")
                    
                    collect_cmd = [python_exe, "-m", "tianlu_intel_collectors.nvd", "--cve-id", cve_to_check]
                    try:
                        proc_collect = subprocess.run(
                            collect_cmd, 
                            capture_output=True, 
                            text=True, 
                            timeout=120, 
                            env=env,
                            cwd=project_root 
                        )
                    except subprocess.TimeoutExpired:
                        logging.error(f"采集超时 (CVE: {cve_to_check}) after 120s")
                        status_text.error("采集超时，请稍后重试或联系管理员。")
                        raise

                    if proc_collect.returncode != 0:
                        stdout_snip = (proc_collect.stdout or "")[:2000]
                        stderr_snip = (proc_collect.stderr or "")[:2000]
                        logging.error(f"采集失败 (CVE: {cve_to_check}):\nSTDOUT: {stdout_snip}... (truncated)\nSTDERR: {stderr_snip}... (truncated)")
                        status_text.error("采集失败，请联系管理员查看 web_ui_errors.log 日志。")
                    else:
                        max_input = 5 * 1024 * 1024
                        payload = (proc_collect.stdout or "")[:max_input]

                        ingest_cmd = [rust_bin, "ingest", "--source", "nvd", "--db", db_path]
                        try:
                            proc_ingest = subprocess.run(ingest_cmd, input=payload, capture_output=True, text=True, timeout=120, env=os.environ.copy())
                        except subprocess.TimeoutExpired:
                            logging.error(f"入库超时 (CVE: {cve_to_check}) after 120s")
                            status_text.error("入库超时，请稍后重试或联系管理员。")
                            raise

                        if proc_ingest.returncode == 0:
                            status_text.success("查询并入库成功！请重新点击查询或刷新页面。")
                            st.balloons()
                            load_data.clear()
                        else:
                            out_snip = (proc_ingest.stdout or "")[:2000]
                            err_snip = (proc_ingest.stderr or "")[:2000]
                            logging.error(f"入库失败 (CVE: {cve_to_check}):\nSTDOUT: {out_snip}... (truncated)\nSTDERR: {err_snip}... (truncated)")
                            status_text.error("入库失败，请联系管理员查看 web_ui_errors.log 日志。")

                except Exception as e:
                    logging.error(f"执行出错 (CVE: {cve_to_check}): {e}", exc_info=True)
                    status_text.error("系统内部错误，请联系管理员。")
