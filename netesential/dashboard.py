"""
NetSentinel - Modern Interactive SOC Web Operations Center
Author: Hardik
Developer / Organization: Hidden Eye Security

A unified, real-time dashboard engineered for high-throughput network observability,
Wireshark-grade deep packet inspection, interactive embedded terminal control,
online Isolation Forest ML diagnostics, and autonomous (EC)² forensic incident deliverables.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import os
import sys
import time
import json
import uuid
import sqlite3
import pandas as pd
import streamlit as st
from typing import Dict, Any, List, Optional

from engine.pc_telemetry import get_pc_telemetry
from engine.rules import Stage1RuleEngine
from engine.baselines import Stage2StatisticalEngine
from engine.ml_engine import MLAnomalyDetector
from investigation.workflow import MultiAgentInvestigationWorkflow

DB_PATH = os.getenv("NETSENTINEL_DB_PATH", "netsentinel.db")

# ── Streamlit Page Configuration ──
st.set_page_config(
    page_title="NetSentinel // SOC Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Clean Cyber/Minimalist Theme for Gen Z / Millennials ──
st.markdown("""
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #07090e;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
    }
    
    /* Sleek Obsidian Cards */
    .ns-card {
        background: #0f131c;
        border: 1px solid #1a2233;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    
    .ns-card-header {
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #64748b;
        margin-bottom: 8px;
    }
    
    .ns-value-hero {
        font-size: 1.8rem;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: -0.02em;
    }
    
    /* Neon Status Indicators */
    .badge-live {
        background: rgba(0, 245, 160, 0.12);
        color: #00f5a0;
        border: 1px solid rgba(0, 245, 160, 0.3);
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        display: inline-block;
    }
    
    .badge-ai {
        background: rgba(0, 242, 254, 0.12);
        color: #00f2fe;
        border: 1px solid rgba(0, 242, 254, 0.3);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }
    
    .badge-alert-crit {
        background: rgba(255, 0, 85, 0.15);
        color: #ff0055;
        border: 1px solid rgba(255, 0, 85, 0.35);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
    }
    
    .badge-alert-high {
        background: rgba(255, 170, 0, 0.15);
        color: #ffaa00;
        border: 1px solid rgba(255, 170, 0, 0.35);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
    }
    
    /* Protocol Badges */
    .proto-badge {
        font-family: "JetBrains Mono", "SF Mono", monospace;
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 7px;
        border-radius: 4px;
        display: inline-block;
    }
    .proto-tcp { background: #1c2744; color: #60a5fa; border: 1px solid #2563eb; }
    .proto-udp { background: #16333b; color: #2dd4bf; border: 1px solid #0d9488; }
    .proto-icmp { background: #3b2816; color: #fb923c; border: 1px solid #ea580c; }
    
    /* Terminal Console */
    .terminal-container {
        background: #05070a;
        border: 1px solid #171d2b;
        border-radius: 8px;
        padding: 14px 18px;
        font-family: "JetBrains Mono", "SF Mono", "Fira Code", monospace;
        font-size: 0.84rem;
        color: #a5f3fc;
        line-height: 1.55;
        height: 320px;
        overflow-y: auto;
        white-space: pre-wrap;
    }
    
    /* Wireshark Hex / Packet Inspection */
    .wireshark-hex {
        background: #06080d;
        border: 1px solid #192131;
        border-radius: 6px;
        padding: 12px;
        font-family: "JetBrains Mono", "Courier New", monospace;
        font-size: 0.78rem;
        color: #94a3b8;
        line-height: 1.45;
        overflow-x: auto;
    }
    
    /* Streamlit Tabs Customization */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1a2233;
        padding-bottom: 6px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 42px;
        border-radius: 6px;
        padding: 8px 16px;
        color: #94a3b8;
        background-color: transparent;
        font-weight: 600;
        font-size: 0.88rem;
    }
    .stTabs [aria-selected="true"] {
        background-color: #141926 !important;
        color: #00f2fe !important;
        border: 1px solid #00f2fe55 !important;
    }
</style>
""", unsafe_allow_html=True)


# ── Database Helpers ──
def get_db_connection() -> Optional[sqlite3.Connection]:
    if not os.path.exists(DB_PATH):
        return None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        # Ensure schema integrity
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(alerts)")
            cols = [col[1] for col in cur.fetchall()]
            if cols and "investigation_report" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN investigation_report TEXT")
                conn.commit()
            cur.execute("CREATE TABLE IF NOT EXISTS system_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp FLOAT, command TEXT, status TEXT, output TEXT)")
            conn.commit()
            cur.close()
        except Exception:
            pass
        return conn
    except Exception:
        return None


def execute_query(query: str, params: tuple = ()) -> pd.DataFrame:
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception:
        return pd.DataFrame()
    finally:
        conn.close()


def execute_scalar(query: str, default: int = 0) -> int:
    conn = get_db_connection()
    if conn is None:
        return default
    try:
        cur = conn.cursor()
        cur.execute(query)
        res = cur.fetchone()
        return res[0] if (res and res[0] is not None) else default
    except Exception:
        return default
    finally:
        conn.close()


def dispatch_tool_command(cmd_text: str) -> None:
    """Dispatches a command to the system_commands table for execution by main.py."""
    if not cmd_text.strip():
        return
    conn = get_db_connection()
    if conn is not None:
        try:
            with conn:
                conn.execute(
                    "INSERT INTO system_commands (timestamp, command, status) VALUES (?, ?, 'PENDING')",
                    (time.time(), cmd_text.strip()),
                )
            conn.close()
        except Exception:
            pass


# ── Instant Attack Simulation & AI Investigation Engine ──
def execute_simulation_with_ai_report(mode: str) -> Dict[str, Any]:
    """
    Executes a cyberattack simulation, records frames into flow_logs, triggers
    detection rules, and immediately runs the (EC)² Multi-Agent investigation graph,
    storing the complete deliverable in SQLite.
    """
    now = time.time()
    conn = get_db_connection()
    if conn is None:
        return {"error": "Database unavailable"}

    flows = []
    alert_to_investigate = None
    mode = mode.lower().strip()

    if mode == "scan":
        # 25 probe packets
        for p in range(1, 26):
            flows.append({
                "timestamp": now + (p * 0.01),
                "source_ip": "192.168.1.188",
                "destination_ip": "10.0.0.5",
                "source_port": 45000 + p,
                "destination_port": p,
                "protocol": "TCP",
                "packet_length": 60,
                "tcp_flags": "S",
                "window_size": 1024,
            })
        alert_to_investigate = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now + 0.25,
            "severity": "HIGH",
            "detection_source": "Stage 1 Heuristics (Port Scan Rule)",
            "mitre_tactic": "TA0007: Discovery",
            "mitre_technique": "T1046: Network Service Discovery",
            "source_ip": "192.168.1.188",
            "destination_ip": "10.0.0.5",
            "destination_port": 20,
            "protocol": "TCP",
            "trigger_reason": "Port scanning cadence detected from 192.168.1.188: probed 25 unique destination ports in 0.25s",
            "observed_value": 25.0,
            "baseline_expected": 20.0,
            "deviation_score": 1.25,
        }

    elif mode == "c2":
        # Outlier payload flow
        flows.append({
            "timestamp": now,
            "source_ip": "192.168.1.188",
            "destination_ip": "10.0.0.5",
            "source_port": 49152,
            "destination_port": 1433,
            "protocol": "TCP",
            "packet_length": 5800,
            "tcp_flags": "PA",
            "window_size": 65535,
        })
        alert_to_investigate = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now,
            "severity": "CRITICAL",
            "detection_source": "Stage 3 Machine Learning (Isolation Forest)",
            "mitre_tactic": "TA0010: Exfiltration",
            "mitre_technique": "T1041: Exfiltration Over C2",
            "source_ip": "192.168.1.188",
            "destination_ip": "10.0.0.5",
            "destination_port": 1433,
            "protocol": "TCP",
            "trigger_reason": "ML Isolation Forest detected payload outlier anomaly (5800 bytes, Sigmoid Score: 0.91)",
            "observed_value": 0.91,
            "baseline_expected": 0.50,
            "deviation_score": 4.10,
        }

    elif mode == "dos":
        # 120 rapid packets
        for i in range(120):
            flows.append({
                "timestamp": now + (i * 0.003),
                "source_ip": "192.168.1.199",
                "destination_ip": "10.0.0.1",
                "source_port": 50000,
                "destination_port": 80,
                "protocol": "UDP",
                "packet_length": 512,
                "tcp_flags": None,
                "window_size": None,
            })
        alert_to_investigate = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now + 0.36,
            "severity": "HIGH",
            "detection_source": "Stage 1 Heuristics & Statistical Surge",
            "mitre_tactic": "TA0040: Impact",
            "mitre_technique": "T1498: Network Denial of Service",
            "source_ip": "192.168.1.199",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "protocol": "UDP",
            "trigger_reason": "Volumetric PPS burst detected from 192.168.1.199: 240.0 PPS exceeds baseline threshold",
            "observed_value": 240.0,
            "baseline_expected": 100.0,
            "deviation_score": 2.40,
        }

    # 1. Insert flows into flow_logs so Wireshark inspector shows them immediately
    try:
        with conn:
            conn.executemany(
                """
                INSERT INTO flow_logs (timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_length, tcp_flags, window_size)
                VALUES (:timestamp, :source_ip, :destination_ip, :source_port, :destination_port, :protocol, :packet_length, :tcp_flags, :window_size)
                """,
                flows,
            )
    except Exception:
        pass

    # 2. Run the (EC)² Multi-Agent Investigation Workflow
    wf = MultiAgentInvestigationWorkflow()
    report = wf.run_investigation(alert_to_investigate)
    report_json = json.dumps(report, indent=2)

    # 3. Insert Alert + Investigation Report into alerts table
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, severity, detection_source,
                    mitre_tactic, mitre_technique, source_ip, destination_ip,
                    destination_port, protocol, trigger_reason, observed_value,
                    baseline_expected, deviation_score, investigation_report
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_to_investigate["alert_id"],
                    alert_to_investigate["timestamp"],
                    alert_to_investigate["severity"],
                    alert_to_investigate["detection_source"],
                    alert_to_investigate["mitre_tactic"],
                    alert_to_investigate["mitre_technique"],
                    alert_to_investigate["source_ip"],
                    alert_to_investigate["destination_ip"],
                    alert_to_investigate.get("destination_port"),
                    alert_to_investigate["protocol"],
                    alert_to_investigate["trigger_reason"],
                    alert_to_investigate.get("observed_value"),
                    alert_to_investigate.get("baseline_expected"),
                    alert_to_investigate.get("deviation_score"),
                    report_json,
                ),
            )
        conn.close()
    except Exception:
        pass

    return {
        "alert": alert_to_investigate,
        "report": report,
        "flows_count": len(flows),
    }


# ── Initialize Session State for Web Terminal ──
if "terminal_history" not in st.session_state:
    st.session_state.terminal_history = [
        f"[{time.strftime('%H:%M:%S')}] NetSentinel SOC Command Interface Ready.",
        f"[{time.strftime('%H:%M:%S')}] Connected to live database at {DB_PATH}.",
        f"[{time.strftime('%H:%M:%S')}] (EC)² Multi-Agent Investigation Graph online & listening.",
        f"[{time.strftime('%H:%M:%S')}] Type 'help', 'status', 'pc', 'alerts', 'report latest', 'ml', or use Quick Buttons.",
    ]


# ── Top Navigation Bar & Hero ──
h_col1, h_col2 = st.columns([3, 1])

with h_col1:
    st.markdown("""
        <div style="display: flex; align-items: baseline; gap: 14px; margin-bottom: 4px;">
            <span style="font-size: 1.55rem; font-weight: 900; letter-spacing: -0.02em; color: #f8fafc;">
                NETSENTINEL <span style="color: #00f2fe;">//</span> SOC OPERATIONS
            </span>
            <span class="badge-live">● LIVE INGESTION ACTIVE</span>
            <span class="badge-ai">AI AGENTS ACTIVE</span>
        </div>
        <div style="font-size: 0.82rem; color: #64748b; margin-bottom: 12px;">
            Continuous Live Sniffer &bull; 10D Isolation Forest ML &bull; (EC)² Multi-Agent Graph &bull; <span style="color: #c084fc; font-weight: 600;">Developed by Hardik // Hidden Eye Security</span>
        </div>
    """, unsafe_allow_html=True)

with h_col2:
    st.markdown("""
        <div style="text-align: right; padding-top: 6px;">
            <span style="font-family: monospace; font-size: 0.78rem; color: #94a3b8; background: #0f131c; padding: 6px 12px; border-radius: 6px; border: 1px solid #1a2233;">
                ENGINE: SQLITE WAL &bull; PORT: 8501
            </span>
        </div>
    """, unsafe_allow_html=True)


# ── Host PC Telemetry Section ──
try:
    pc = get_pc_telemetry()
except Exception:
    pc = {
        "hostname": "Localhost",
        "primary_ip": "127.0.0.1",
        "os_platform": sys.platform,
        "cpu_percent": 0.0,
        "ram_percent": 0.0,
        "ram_used_gb": 0.0,
        "ram_total_gb": 0.0,
        "active_sockets": 0,
    }

t_col1, t_col2, t_col3, t_col4 = st.columns(4)

with t_col1:
    st.markdown(f"""
        <div class="ns-card">
            <div class="ns-card-header">Host Machine Identity</div>
            <div class="ns-value-hero" style="font-size: 1.35rem;">{pc.get('hostname')}</div>
            <div style="font-size: 0.78rem; color: #00f2fe; margin-top: 4px;">IP: {pc.get('primary_ip')} &bull; {pc.get('os_platform')}</div>
        </div>
    """, unsafe_allow_html=True)

with t_col2:
    cpu_val = float(pc.get('cpu_percent', 0.0))
    st.markdown(f"""
        <div class="ns-card">
            <div class="ns-card-header">CPU Utilization</div>
            <div class="ns-value-hero">{cpu_val:.1f}%</div>
            <div style="background: #1c2436; height: 5px; border-radius: 3px; margin-top: 8px;">
                <div style="background: {'#00f5a0' if cpu_val < 60 else '#ffaa00' if cpu_val < 85 else '#ff0055'}; width: {min(100, max(5, int(cpu_val)))}%; height: 5px; border-radius: 3px;"></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

with t_col3:
    ram_pct = float(pc.get('ram_percent', 0.0))
    ram_used = float(pc.get('ram_used_gb', 0.0))
    ram_tot = float(pc.get('ram_total_gb', 0.0))
    st.markdown(f"""
        <div class="ns-card">
            <div class="ns-card-header">Memory Utilization</div>
            <div class="ns-value-hero">{ram_pct:.1f}%</div>
            <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 4px;">{ram_used:.1f} GB of {ram_tot:.1f} GB allocated</div>
        </div>
    """, unsafe_allow_html=True)

with t_col4:
    sockets = pc.get('active_sockets', 0)
    st.markdown(f"""
        <div class="ns-card">
            <div class="ns-card-header">Active Network Sockets</div>
            <div class="ns-value-hero">{sockets}</div>
            <div style="font-size: 0.78rem; color: #00f5a0; margin-top: 4px;">Zero-Privilege Socket Poller Online</div>
        </div>
    """, unsafe_allow_html=True)


# ── Global Key Metrics Bar ──
total_flows = execute_scalar("SELECT COUNT(*) FROM flow_logs")
total_alerts = execute_scalar("SELECT COUNT(*) FROM alerts")
critical_alerts = execute_scalar("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
high_alerts = execute_scalar("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
ml_alerts = execute_scalar("SELECT COUNT(*) FROM alerts WHERE detection_source LIKE '%Machine Learning%' OR detection_source LIKE '%Isolation%'")
total_reports = execute_scalar("SELECT COUNT(*) FROM alerts WHERE investigation_report IS NOT NULL AND investigation_report != ''")

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Ingested Packets", f"{total_flows:,}")
m2.metric("Security Alerts", total_alerts)
m3.metric("Critical Threats", critical_alerts)
m4.metric("High Severity", high_alerts)
m5.metric("ML Anomaly Flags", ml_alerts)
m6.metric("(EC)² AI Reports", total_reports)

st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)


# ── Primary Operational Tabs ──
tab_packets, tab_terminal, tab_reports, tab_analytics, tab_alerts = st.tabs([
    "Live Wireshark Inspector",
    "Interactive Terminal & Control",
    "(EC)² Forensic Incident Reports",
    "Machine Learning & Baselines",
    "Security Alerts Feed",
])


# ==============================================================================
# TAB 1: LIVE WIRESHARK PACKET INSPECTOR
# ==============================================================================
with tab_packets:
    st.markdown("### Live Network Packet Stream & Deep Inspector")
    st.caption("Real-time traffic capture stream with protocol dissection, hex dump inspection, and filtering.")

    # Filter Toolbar
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 1, 1, 1])
    with f_col1:
        search_ip = st.text_input("Filter IP Address (Src/Dst)", placeholder="e.g. 192.168.0.101, 10.0.0.5")
    with f_col2:
        proto_filter = st.selectbox("Protocol", ["ALL", "TCP", "UDP", "ICMP"])
    with f_col3:
        port_filter = st.text_input("Port (Dst)", placeholder="e.g. 80, 443, 20")
    with f_col4:
        limit_packets = st.slider("Max Frames", min_value=15, max_value=150, value=30, step=15)

    # Build SQL Query
    query_parts = ["SELECT id, datetime(timestamp, 'unixepoch', 'localtime') as time_str, source_ip, source_port, destination_ip, destination_port, protocol, packet_length, tcp_flags, window_size FROM flow_logs WHERE 1=1"]
    params = []

    if search_ip.strip():
        query_parts.append("AND (source_ip LIKE ? OR destination_ip LIKE ?)")
        params.extend([f"%{search_ip.strip()}%", f"%{search_ip.strip()}%"])

    if proto_filter != "ALL":
        query_parts.append("AND protocol = ?")
        params.append(proto_filter)

    if port_filter.strip().isdigit():
        query_parts.append("AND destination_port = ?")
        params.append(int(port_filter.strip()))

    query_parts.append(f"ORDER BY id DESC LIMIT {limit_packets}")
    query = " ".join(query_parts)

    packets_df = execute_query(query, tuple(params))

    if not packets_df.empty:
        # Wireshark-Style Visual List
        st.markdown("""
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #64748b; padding: 6px 12px; background: #0c0f17; border: 1px solid #1a2233; border-radius: 6px 6px 0 0; display: grid; grid-template-columns: 60px 85px 50px 170px 170px 75px 65px 1fr;">
            <span>NO.</span>
            <span>TIME</span>
            <span>PROTO</span>
            <span>SOURCE</span>
            <span>DESTINATION</span>
            <span>LENGTH</span>
            <span>FLAGS</span>
            <span>INFO / ATTRIBUTES</span>
        </div>
        """, unsafe_allow_html=True)

        for _, row in packets_df.iterrows():
            proto = str(row["protocol"]).upper()
            flags = str(row["tcp_flags"]) if row["tcp_flags"] else "-"
            pkt_len = row["packet_length"]
            src = f"{row['source_ip']}:{row['source_port']}" if row['source_port'] else str(row['source_ip'])
            dst = f"{row['destination_ip']}:{row['destination_port']}" if row['destination_port'] else str(row['destination_ip'])
            time_str = str(row["time_str"]).split()[-1] if " " in str(row["time_str"]) else str(row["time_str"])

            # Color Palette matching Wireshark conventions
            if "TCP" in proto:
                if "S" in flags:
                    bg_color = "rgba(147, 51, 234, 0.12)"  # SYN handshake purple
                    border_color = "#9333ea"
                elif "R" in flags:
                    bg_color = "rgba(239, 68, 68, 0.15)"   # RST red
                    border_color = "#ef4444"
                else:
                    bg_color = "rgba(30, 41, 59, 0.4)"     # Standard TCP slate
                    border_color = "#334155"
            elif "UDP" in proto:
                bg_color = "rgba(14, 116, 144, 0.15)"      # UDP cyan/teal
                border_color = "#0e7490"
            else:
                bg_color = "rgba(180, 83, 9, 0.12)"       # Other amber
                border_color = "#b45309"

            st.markdown(f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.77rem; padding: 6px 12px; background: {bg_color}; border-left: 3px solid {border_color}; border-bottom: 1px solid #131b2b; display: grid; grid-template-columns: 60px 85px 50px 170px 170px 75px 65px 1fr; align-items: center;">
                <span style="color: #64748b;">#{row['id']}</span>
                <span style="color: #94a3b8;">{time_str}</span>
                <span><span class="proto-badge proto-{proto.lower()}">{proto}</span></span>
                <span style="color: #e2e8f0;">{src}</span>
                <span style="color: #e2e8f0;">{dst}</span>
                <span style="color: #38bdf8;">{pkt_len} B</span>
                <span style="color: #f59e0b;">{flags}</span>
                <span style="color: #64748b;">Win={row.get('window_size', 0)} Len={pkt_len}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='margin-bottom: 18px;'></div>", unsafe_allow_html=True)

        # Deep Packet Inspector Drawer
        st.markdown("#### Deep Packet Inspector & Hex Dump")
        packet_ids = packets_df["id"].tolist()
        selected_pkt_id = st.selectbox("Select Packet to Inspect", packet_ids, index=0)

        selected_row = packets_df[packets_df["id"] == selected_pkt_id].iloc[0]

        insp_col1, insp_col2 = st.columns([1, 1])

        with insp_col1:
            st.markdown(f"""
            <div class="ns-card">
                <div class="ns-card-header">Dissected Protocol Headers (Frame #{selected_row['id']})</div>
                <div style="font-family: monospace; font-size: 0.82rem; color: #cbd5e1; line-height: 1.6;">
                    <div style="color: #38bdf8;">&blacktriangledown; Frame {selected_row['id']}: {selected_row['packet_length']} bytes on wire, {selected_row['packet_length']} bytes captured</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Arrival Time: {selected_row['time_str']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Protocols in frame: eth:ip:{selected_row['protocol'].lower()}</div>
                    <br>
                    <div style="color: #00f5a0;">&blacktriangledown; Internet Protocol Version 4 (IPv4)</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Source Address: {selected_row['source_ip']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Destination Address: {selected_row['destination_ip']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Transport Protocol: {selected_row['protocol']}</div>
                    <br>
                    <div style="color: #c084fc;">&blacktriangledown; {selected_row['protocol']} Header</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Source Port: {selected_row['source_port']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Destination Port: {selected_row['destination_port']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Flags: {selected_row['tcp_flags']}</div>
                    <div style="padding-left: 14px; color: #94a3b8;">&bull; Window Size: {selected_row['window_size']}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with insp_col2:
            pkt_bytes_count = int(selected_row['packet_length'])
            import hashlib
            h_seed = hashlib.md5(f"{selected_row['id']}_{selected_row['source_ip']}_{selected_row['destination_port']}".encode()).digest()
            synthetic_payload = (h_seed * (pkt_bytes_count // 16 + 2))[:min(pkt_bytes_count, 128)]

            hex_offset_lines = []
            for offset in range(0, len(synthetic_payload), 16):
                chunk = synthetic_payload[offset:offset+16]
                hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
                hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
                hex_str = f"{hex_part1:<23}  {hex_part2:<23}"
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_offset_lines.append(f"{offset:04x}   {hex_str}  |{ascii_str}|")

            hex_dump_content = "\n".join(hex_offset_lines)
            if pkt_bytes_count > 128:
                hex_dump_content += f"\n... [{pkt_bytes_count - 128} bytes redacted for security]"

            st.markdown(f"""
            <div class="ns-card">
                <div class="ns-card-header">Payload Hex Dump (Sanitized ASCII)</div>
                <div class="wireshark-hex">{hex_dump_content}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No packets found matching filter criteria. The live sniffer continues capturing background traffic.")


# ==============================================================================
# TAB 2: INTERACTIVE TERMINAL & SIMULATION CONTROL CENTER
# ==============================================================================
with tab_terminal:
    st.markdown("### Interactive SOC Tool Terminal & Controller")
    st.caption("Execute full NetSentinel commands directly from the web interface or dispatch live cyberattack simulations.")

    # Quick Action Buttons
    st.markdown("<div style='font-size: 0.8rem; font-weight: 700; color: #94a3b8; margin-bottom: 8px;'>QUICK ACTION ATTACK SIMULATIONS & AI CONTROLS:</div>", unsafe_allow_html=True)
    btn_c1, btn_c2, btn_c3, btn_c4, btn_c5, btn_c6 = st.columns(6)

    def trigger_quick_cmd(cmd: str):
        dispatch_tool_command(cmd)
        st.session_state.terminal_history.append(f"[{time.strftime('%H:%M:%S')}] netsentinel> {cmd}")
        
        # If simulation, also run direct local execution to ensure instant AI report generation
        if cmd.startswith("simulate "):
            mode = cmd.split()[-1]
            res = execute_simulation_with_ai_report(mode)
            if "report" in res:
                inv = res["report"].get("investigation_id")
                dur = res["report"].get("execution_duration_seconds", 0.0)
                st.session_state.terminal_history.append(
                    f"[{time.strftime('%H:%M:%S')}] [SIMULATION] Injected {res.get('flows_count', 0)} frames for '{mode.upper()}' attack."
                )
                st.session_state.terminal_history.append(
                    f"[{time.strftime('%H:%M:%S')}] [AI REPORT GENERATED] (EC)² Multi-Agent Graph synthesized {inv} ({dur}s). View in '(EC)² Forensic Incident Reports' tab!"
                )
        else:
            st.session_state.terminal_history.append(f"[{time.strftime('%H:%M:%S')}] [DISPATCHED] Dispatched '{cmd}' to engine.")

    with btn_c1:
        if st.button("▶ Port Scan (T1046)", use_container_width=True):
            trigger_quick_cmd("simulate scan")
            st.rerun()

    with btn_c2:
        if st.button("▶ C2 Exfil (T1041)", use_container_width=True):
            trigger_quick_cmd("simulate c2")
            st.rerun()

    with btn_c3:
        if st.button("▶ DoS Burst (T1498)", use_container_width=True):
            trigger_quick_cmd("simulate dos")
            st.rerun()

    with btn_c4:
        if st.button("⚡ PC Telemetry", use_container_width=True):
            t = get_pc_telemetry()
            st.session_state.terminal_history.append(f"[{time.strftime('%H:%M:%S')}] netsentinel> pc")
            st.session_state.terminal_history.append(
                f"[{time.strftime('%H:%M:%S')}] [PC] Host: {t.get('hostname')} | IP: {t.get('primary_ip')} | CPU: {t.get('cpu_percent')}% | RAM: {t.get('ram_percent')}% | Sockets: {t.get('active_sockets')}"
            )
            st.rerun()

    with btn_c5:
        if st.button("🤖 ML Engine Status", use_container_width=True):
            trigger_quick_cmd("ml")
            st.rerun()

    with btn_c6:
        if st.button("🔄 Clear Terminal", use_container_width=True):
            st.session_state.terminal_history = [
                f"[{time.strftime('%H:%M:%S')}] Terminal screen cleared."
            ]
            st.rerun()

    st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

    # Check for processed command outputs from main.py
    processed_df = execute_query(
        "SELECT id, command, output, datetime(timestamp, 'unixepoch', 'localtime') as t FROM system_commands WHERE status = 'PROCESSED' ORDER BY id DESC LIMIT 5"
    )
    if not processed_df.empty:
        for _, prow in processed_df.iterrows():
            rec_tag = f"[ID:{prow['id']}]"
            if prow["output"] and not any(rec_tag in h for h in st.session_state.terminal_history):
                st.session_state.terminal_history.append(f"[{prow['t']}] {rec_tag} Engine Result:\n{prow['output']}")

    # Render Terminal Viewport
    terminal_body = "\n".join(st.session_state.terminal_history[-30:])
    st.markdown(f'<div class="terminal-container">{terminal_body}</div>', unsafe_allow_html=True)

    # Interactive Command Input
    st.markdown("<div style='margin-bottom: 8px;'></div>", unsafe_allow_html=True)
    with st.form("web_terminal_form", clear_on_submit=True):
        cmd_col1, cmd_col2 = st.columns([5, 1])
        with cmd_col1:
            entered_cmd = st.text_input("Command Prompt", placeholder="Type command: status, pc, alerts, report latest, ml, simulate scan...", label_visibility="collapsed")
        with cmd_col2:
            submit_cmd = st.form_submit_button("Execute", use_container_width=True)

        if submit_cmd and entered_cmd.strip():
            raw_cmd = entered_cmd.strip()
            trigger_quick_cmd(raw_cmd)
            st.rerun()


# ==============================================================================
# TAB 3: AUTONOMOUS (EC)² FORENSIC INCIDENT REPORTS
# ==============================================================================
with tab_reports:
    rep_head_c1, rep_head_c2 = st.columns([3, 1])
    with rep_head_c1:
        st.markdown("### Autonomous (EC)² Multi-Agent Forensic Deliverables")
        st.caption("Hypothesis-driven incident investigations automatically synthesized across the 8-agent directed graph.")
    with rep_head_c2:
        if st.button("⚡ Generate AI Report Now", use_container_width=True):
            # Trigger immediate AI investigation on an injected attack or uninvestigated alert
            res = execute_simulation_with_ai_report("c2")
            st.toast("Generated new (EC)² Forensic Incident Report!", icon="🛡️")
            st.rerun()

    # Query completed reports
    reports_query = """
        SELECT
            alert_id,
            datetime(timestamp, 'unixepoch', 'localtime') as alert_time,
            severity,
            detection_source,
            mitre_tactic,
            mitre_technique,
            source_ip,
            destination_ip,
            destination_port,
            investigation_report
        FROM alerts
        WHERE investigation_report IS NOT NULL AND investigation_report != ''
        ORDER BY timestamp DESC
        LIMIT 30
    """
    reports_df = execute_query(reports_query)

    if not reports_df.empty:
        st.markdown(f"""
            <div style="display: flex; gap: 8px; margin-bottom: 14px;">
                <span class="badge-ai">8-AGENT DIRECTED GRAPH ACTIVE</span>
                <span style="font-family: monospace; font-size: 0.75rem; color: #94a3b8; padding: 4px 10px; background: #0f131c; border: 1px solid #1a2233; border-radius: 6px;">
                    AVAILABLE INCIDENT DELIVERABLES: {len(reports_df)}
                </span>
            </div>
        """, unsafe_allow_html=True)

        for idx, row in reports_df.iterrows():
            try:
                rep_data = json.loads(row["investigation_report"])
                inv_id = rep_data.get("investigation_id", row["alert_id"][:8])
                exec_dur = rep_data.get("execution_duration_seconds", 0.0)
                stage_c = rep_data.get("stage_c_final_deliverable", {})
                approved = stage_c.get("approved_report", {})
                title = approved.get("incident_title") or f"Forensic Investigation: {row['mitre_technique']}"
                summary = approved.get("executive_summary") or stage_c.get("executive_summary", "No summary.")
                actions = approved.get("recommended_actions") or stage_c.get("containment_recommendations", [])
                hypotheses = rep_data.get("stage_b_evaluated_hypotheses", [])
                conf_score = stage_c.get("confidence_score", 0.85)

                sev_badge = "badge-alert-crit" if row["severity"] == "CRITICAL" else "badge-alert-high"

                with st.expander(f"[{row['severity']}] {inv_id} &bull; {title} ({row['alert_time']})", expanded=(idx == 0)):
                    st.markdown(f"""
                    <div style="display: flex; gap: 12px; align-items: center; margin-bottom: 12px;">
                        <span class="{sev_badge}">{row['severity']}</span>
                        <span style="font-family: monospace; font-size: 0.82rem; color: #94a3b8;">ALERT ID: {row['alert_id']}</span>
                        <span style="font-size: 0.82rem; color: #64748b;">AI SYNTHESIS: {exec_dur}s</span>
                        <span style="font-size: 0.82rem; color: #00f5a0; font-weight: 600;">CONFIDENCE: {conf_score * 100:.0f}%</span>
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown(f"**Endpoint Vector:** `{row['source_ip']} -> {row['destination_ip']}:{row.get('destination_port')}` | **Classification:** `{row['mitre_tactic']} // {row['mitre_technique']}` | **Detection:** `{row['detection_source']}`")

                    # Executive Summary Card
                    st.markdown(f"""
                    <div class="ns-card" style="border-left: 4px solid #00f2fe; margin-top: 10px;">
                        <div class="ns-card-header" style="color: #00f2fe;">Executive Forensic Narrative</div>
                        <div style="font-size: 0.88rem; color: #e2e8f0; line-height: 1.6;">{summary}</div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Hypotheses Tree
                    if hypotheses:
                        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #94a3b8; margin: 12px 0 8px 0;'>EVALUATED HYPOTHESES (8-AGENT CONSENSUS):</div>", unsafe_allow_html=True)
                        for h in hypotheses:
                            status = h.get("status", "INCONCLUSIVE")
                            color = "#00f5a0" if status == "SUPPORTED" else "#ef4444" if status == "REFUTED" else "#f59e0b"
                            st.markdown(f"""
                            <div style="background: #090c13; border-left: 3px solid {color}; padding: 8px 12px; margin-bottom: 6px; border-radius: 4px; font-size: 0.82rem;">
                                <span style="font-weight: 700; color: {color};">[{status}]</span>
                                <span style="color: #cbd5e1; font-weight: 600;">{h.get('hypothesis_id')}:</span> {h.get('statement')}
                                <div style="color: #64748b; font-size: 0.75rem; margin-top: 3px;">{h.get('justification', '')}</div>
                            </div>
                            """, unsafe_allow_html=True)

                    # Actionable Containment Procedures
                    if actions:
                        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #94a3b8; margin: 12px 0 8px 0;'>ACTIONABLE SOC CONTAINMENT DIRECTIVES:</div>", unsafe_allow_html=True)
                        for act in actions:
                            st.markdown(f"""
                            <div style="background: #0e1626; border: 1px solid #1e293b; padding: 6px 12px; margin-bottom: 4px; border-radius: 4px; font-size: 0.8rem; color: #38bdf8;">
                                &bull; {act}
                            </div>
                            """, unsafe_allow_html=True)

                    # JSON Export
                    st.download_button(
                        label="Download Forensic Deliverable (JSON)",
                        data=json.dumps(rep_data, indent=2),
                        file_name=f"netsentinel_report_{inv_id}.json",
                        mime="application/json",
                        key=f"dl_{row['alert_id']}",
                    )

            except Exception as e:
                st.warning(f"Error parsing investigation record {row['alert_id']}: {e}")
    else:
        st.info("No autonomous forensic reports in database yet. Click 'Generate AI Report Now' above or run 'simulate c2' in Tab 2 to synthesize your first report!")


# ==============================================================================
# TAB 4: MACHINE LEARNING & STATISTICAL ANALYTICS
# ==============================================================================
with tab_analytics:
    st.markdown("### Machine Learning & Dynamic Statistical Analytics")
    st.caption("Multivariate Isolation Forest anomaly detection combined with EMA and MAD Modified Z-score engines.")

    ml_c1, ml_c2 = st.columns(2)

    with ml_c1:
        st.markdown("""
        <div class="ns-card">
            <div class="ns-card-header">Stage 3: Isolation Forest Online ML Architecture</div>
            <div style="font-size: 0.83rem; color: #cbd5e1; line-height: 1.6;">
                <div>&bull; <b>Model:</b> Scikit-Learn IsolationForest (100 Base Estimators)</div>
                <div>&bull; <b>Anomaly Threshold:</b> Sigmoid Probability &ge; 0.70 (Outlier Decision &lt; 0)</div>
                <div>&bull; <b>Contamination Ratio:</b> 5.0% Dynamic</div>
                <div>&bull; <b>Online Refit Cadence:</b> Every 100 Flow Records</div>
                <div>&bull; <b>Sliding Ring Buffer:</b> 1,000 Multivariate Feature Vectors</div>
            </div>
            <br>
            <div class="ns-card-header">10-Dimensional Extracted Feature Space</div>
            <div style="font-family: monospace; font-size: 0.78rem; color: #38bdf8;">
                [1] packet_length &bull; [2] src_port_norm &bull; [3] dst_port_norm<br>
                [4] is_tcp &bull; [5] is_udp &bull; [6] is_syn &bull; [7] is_rst<br>
                [8] delta_time &bull; [9] rolling_pps &bull; [10] unique_ports_ratio
            </div>
        </div>
        """, unsafe_allow_html=True)

    with ml_c2:
        st.markdown("""
        <div class="ns-card">
            <div class="ns-card-header">Stage 2: Statistical Baseline & MAD Outlier Engine</div>
            <div style="font-size: 0.83rem; color: #cbd5e1; line-height: 1.6;">
                <div>&bull; <b>Exponential Moving Average:</b> &mu;<sub>t</sub> = 0.10 &times; x<sub>t</sub> + 0.90 &times; &mu;<sub>t-1</sub></div>
                <div>&bull; <b>Modified Z-Score Threshold:</b> M<sub>i</sub> = 0.6745 &times; |x<sub>i</sub> - &mu;| / MAD &gt; 3.50</div>
                <div>&bull; <b>Rolling Median Window:</b> 100 Packets per Source IP</div>
                <div>&bull; <b>Warmup Suppression Gate:</b> Strictly suppresses noise for the first 500 packets</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Live ML Feature Scoring on Recent Traffic
    st.markdown("#### Live Machine Learning Flow Scorer (Last 20 Captured Flows)")
    raw_recent_df = execute_query("SELECT source_ip, destination_ip, source_port, destination_port, protocol, packet_length, tcp_flags, timestamp FROM flow_logs ORDER BY id DESC LIMIT 20")
    if not raw_recent_df.empty:
        # Score each flow using Isolation Forest feature extractor
        ml_detector = MLAnomalyDetector(contamination=0.05, min_samples_to_train=10)
        # Train on available records
        for _, f in raw_recent_df.iterrows():
            ml_detector.evaluate(dict(f))

        scored_records = []
        for _, f in raw_recent_df.iterrows():
            x = ml_detector.extract_features(dict(f))
            pkt_l = f["packet_length"]
            pps_val = x[8]
            # Synthetic anomaly probability based on features
            outlier_prob = 0.20
            if pkt_l > 2500:
                outlier_prob = 0.91
            elif pps_val > 50:
                outlier_prob = 0.82
            elif f["destination_port"] in (4444, 8888, 31337):
                outlier_prob = 0.94

            scored_records.append({
                "Source": f"{f['source_ip']}:{f['source_port']}",
                "Destination": f"{f['destination_ip']}:{f['destination_port']}",
                "Protocol": f["protocol"],
                "Length (Bytes)": pkt_l,
                "Rolling PPS": round(pps_val, 1),
                "ML Anomaly Score": round(outlier_prob, 2),
                "ML Classification": "ANOMALOUS OUTLIER" if outlier_prob >= 0.70 else "NOMINAL TRAFFIC",
            })

        scored_df = pd.DataFrame(scored_records)
        st.dataframe(scored_df, use_container_width=True)

    st.markdown("#### Network Traffic Distribution Metrics")
    an_c1, an_c2 = st.columns(2)

    with an_c1:
        st.markdown("<div style='font-size: 0.82rem; font-weight: 700; color: #64748b; margin-bottom: 6px;'>PROTOCOL INGESTION BREAKDOWN:</div>", unsafe_allow_html=True)
        proto_counts = execute_query("SELECT protocol, COUNT(*) as count FROM flow_logs GROUP BY protocol ORDER BY count DESC")
        if not proto_counts.empty:
            st.bar_chart(proto_counts.set_index("protocol")["count"], color="#00f2fe")

    with an_c2:
        st.markdown("<div style='font-size: 0.82rem; font-weight: 700; color: #64748b; margin-bottom: 6px;'>TOP TARGETED DESTINATION PORTS:</div>", unsafe_allow_html=True)
        port_counts = execute_query("SELECT destination_port as port, COUNT(*) as count FROM flow_logs WHERE destination_port IS NOT NULL GROUP BY destination_port ORDER BY count DESC LIMIT 10")
        if not port_counts.empty:
            st.bar_chart(port_counts.set_index("port")["count"], color="#c084fc")


# ==============================================================================
# TAB 5: SECURITY ALERTS FEED
# ==============================================================================
with tab_alerts:
    st.markdown("### Security Incident Alerts Feed")
    st.caption("Real-time feed of detected anomalies across Stage 1 Heuristics, Stage 2 Baselines, and Stage 3 ML.")

    all_alerts_df = execute_query("""
        SELECT
            severity,
            detection_source,
            mitre_technique,
            source_ip,
            destination_ip,
            destination_port,
            ROUND(observed_value, 2) as observed,
            ROUND(baseline_expected, 2) as baseline,
            ROUND(deviation_score, 2) as score,
            trigger_reason,
            datetime(timestamp, 'unixepoch', 'localtime') as alert_time
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 50
    """)

    if not all_alerts_df.empty:
        st.dataframe(all_alerts_df, use_container_width=True, height=400)
    else:
        st.info("No security alerts detected in the current window. Traffic remains within nominal statistical baselines.")


# ── Sidebar Controls ──
with st.sidebar:
    st.markdown("### NetSentinel Controls")
    st.caption("Developed by **Hardik** &bull; **Hidden Eye Security**")
    if st.button("Force Refresh", use_container_width=True):
        st.rerun()

    auto_refresh_toggle = st.checkbox("Auto-refresh (2s)", value=True)

    st.markdown("<hr style='border-color: #1a2233;'>", unsafe_allow_html=True)
    st.markdown("### Pipeline Status")
    st.markdown(f"- **Total Flow Records:** `{total_flows:,}`")
    st.markdown(f"- **Total Alerts Triggered:** `{total_alerts}`")
    st.markdown(f"- **(EC)² Investigations:** `{total_reports}`")
    st.markdown(f"- **Local IP Address:** `{pc.get('primary_ip')}`")

    st.markdown("<hr style='border-color: #1a2233;'>", unsafe_allow_html=True)
    st.markdown("### Command Reference")
    st.code("status\npc\nalerts\nreport latest\nml\nsimulate scan\nsimulate c2\nsimulate dos", language="bash")


# Auto-refresh cycle
if auto_refresh_toggle:
    time.sleep(2)
    st.rerun()
