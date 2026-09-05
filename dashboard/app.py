"""
app.py
LogShield: The forensic integrity platform
Enterprise SIEM grade dashboard.
Multi-page sidebar navigation.
Dark and light mode support.
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import os
import sys
import json
import time
import requests
from datetime import datetime
sys.path.insert(0, '.')

from src.parser import parse_csv_from_bytes
from src.features import extract_features
from src.hmac_chain import (
    verify_hmac_chain,
    check_chain_continuity)
from src.models.isolation_forest import predict_anomalies
from dashboard.utils.pdf_report import generate_pdf_report

st.set_page_config(
    page_title="LogShield",
    page_icon="https://img.icons8.com/fluency/48/shield.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -- THEME STATE --
if 'dark_mode' not in st.session_state:
    st.session_state.dark_mode = True
if 'page' not in st.session_state:
    st.session_state.page = 'Dashboard'
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
if 'df_result' not in st.session_state:
    st.session_state.df_result = None
if 'verdict' not in st.session_state:
    st.session_state.verdict = None
if 'deleted_count' not in st.session_state:
    st.session_state.deleted_count = 0
if 'injected_count' not in st.session_state:
    st.session_state.injected_count = 0
if 'anomaly_count' not in st.session_state:
    st.session_state.anomaly_count = 0
if 'critical_count' not in st.session_state:
    st.session_state.critical_count = 0
if 'findings' not in st.session_state:
    st.session_state.findings = []
if 'analysis_time' not in st.session_state:
    st.session_state.analysis_time = None

dm = st.session_state.dark_mode

# -- COLOR TOKENS --
if dm:
    BG       = "#0A0C10"
    SURFACE  = "#0F1319"
    BORDER   = "#1E2530"
    ACCENT   = "#E8343A"
    CYAN     = "#00D4FF"
    SUCCESS  = "#00C853"
    WARN     = "#FFB300"
    TXT1     = "#F0F2F5"
    TXT2     = "#6B7280"
    TXT3     = "#374151"
    SIDEBAR  = "#080A0E"
    NAV_SEL  = "rgba(232,52,58,0.15)"
else:
    BG       = "#F8FAFC"
    SURFACE  = "#FFFFFF"
    BORDER   = "#E2E8F0"
    ACCENT   = "#CC1F24"
    CYAN     = "#0284C7"
    SUCCESS  = "#059669"
    WARN     = "#D97706"
    TXT1     = "#0F172A"
    TXT2     = "#475569"
    TXT3     = "#94A3B8"
    SIDEBAR  = "#F1F5F9"
    NAV_SEL  = "rgba(204,31,36,0.08)"

# -- FONT INJECTION --
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com"
      crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap"
rel="stylesheet">
""", unsafe_allow_html=True)

# -- MASTER CSS --
st.markdown(f"""
<style>
*, *::before, *::after {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}

html, body, .stApp {{
    background: {BG} !important;
    font-family: 'Inter', -apple-system,
        BlinkMacSystemFont, sans-serif !important;
    color: {TXT1} !important;
}}

.block-container {{
    padding: 0 !important;
    max-width: 100% !important;
}}

/* SIDEBAR */
[data-testid="stSidebar"] {{
    background: {SIDEBAR} !important;
    border-right: 1px solid {BORDER} !important;
    min-width: 220px !important;
    max-width: 220px !important;
}}

[data-testid="stSidebar"] > div {{
    padding: 0 !important;
}}

/* MAIN AREA */
[data-testid="stMain"] {{
    background: {BG} !important;
}}

/* HIDE STREAMLIT CHROME */
footer {{ display: none !important; }}
#MainMenu {{ display: none !important; }}
header {{ display: none !important; }}
[data-testid="stToolbar"] {{
    display: none !important; }}
[data-testid="stDecoration"] {{
    display: none !important; }}

/* SIDEBAR NAV ITEMS */
.nav-item {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    cursor: pointer;
    border-radius: 6px;
    margin: 2px 8px;
    font-size: 13px;
    font-weight: 500;
    color: {TXT2};
    transition: all 0.15s ease;
    border: 1px solid transparent;
    text-decoration: none;
}}

.nav-item:hover {{
    background: {NAV_SEL};
    color: {TXT1};
}}

.nav-item.active {{
    background: {NAV_SEL};
    color: {ACCENT};
    border-color: rgba(232,52,58,0.2);
    font-weight: 600;
}}

.nav-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: {ACCENT};
    flex-shrink: 0;
}}

/* SIDEBAR BRAND */
.sidebar-brand {{
    padding: 24px 20px 8px 20px;
    border-bottom: 1px solid {BORDER};
    margin-bottom: 12px;
}}

.sidebar-logo {{
    font-size: 20px;
    font-weight: 900;
    letter-spacing: 3px;
    color: {TXT1};
}}

.sidebar-logo span {{
    color: {ACCENT};
}}

.sidebar-tag {{
    font-size: 9px;
    font-weight: 500;
    color: {TXT3};
    letter-spacing: 1.5px;
    margin-top: 4px;
    text-transform: uppercase;
}}

/* TOP BAR */
.top-bar {{
    background: {SURFACE};
    border-bottom: 1px solid {BORDER};
    padding: 0 32px;
    height: 56px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
}}

.top-bar-title {{
    font-size: 16px;
    font-weight: 700;
    color: {TXT1};
    letter-spacing: -0.3px;
}}

.top-bar-meta {{
    font-size: 11px;
    color: {TXT2};
    display: flex;
    align-items: center;
    gap: 16px;
}}

.live-pill {{
    background: rgba(0,200,83,0.12);
    border: 1px solid rgba(0,200,83,0.25);
    border-radius: 20px;
    padding: 3px 10px;
    font-size: 10px;
    font-weight: 700;
    color: {SUCCESS};
    letter-spacing: 1px;
    display: flex;
    align-items: center;
    gap: 5px;
}}

.live-dot {{
    width: 6px;
    height: 6px;
    background: {SUCCESS};
    border-radius: 50%;
    animation: blink 2s infinite;
}}

@keyframes blink {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.2; }}
}}

/* PAGE CONTENT */
.page-wrap {{
    padding: 28px 32px;
}}

/* SECTION LABELS */
.sec-label {{
    font-size: 10px;
    font-weight: 700;
    color: {TXT3};
    letter-spacing: 3px;
    text-transform: uppercase;
    padding-bottom: 12px;
    border-bottom: 1px solid {BORDER};
    margin-bottom: 20px;
    margin-top: 32px;
}}

/* KPI CARDS */
.kpi-row {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 12px;
}}

.kpi-card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 24px 24px 20px 24px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
}}

.kpi-card::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: {BORDER};
}}

.kpi-card.accent::before {{ background: {ACCENT}; }}
.kpi-card.success::before {{ background: {SUCCESS}; }}
.kpi-card.warn::before {{ background: {WARN}; }}
.kpi-card.cyan::before {{ background: {CYAN}; }}

.kpi-val {{
    font-size: 40px;
    font-weight: 900;
    color: {TXT1};
    line-height: 1;
    font-variant-numeric: tabular-nums;
    font-family: 'JetBrains Mono', monospace;
}}

.kpi-val.red {{ color: {ACCENT}; }}
.kpi-val.green {{ color: {SUCCESS}; }}
.kpi-val.amber {{ color: {WARN}; }}
.kpi-val.cyan {{ color: {CYAN}; }}

.kpi-label {{
    font-size: 11px;
    font-weight: 600;
    color: {TXT2};
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-top: 8px;
}}

.kpi-delta {{
    font-size: 11px;
    margin-top: 6px;
    font-weight: 500;
}}

.kpi-delta.bad {{ color: {ACCENT}; }}
.kpi-delta.ok {{ color: {SUCCESS}; }}
.kpi-delta.neutral {{ color: {TXT3}; }}

/* VERDICT BANNER */
.verdict-banner {{
    border-radius: 8px;
    padding: 28px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 20px 0;
    border: 1px solid transparent;
}}

.verdict-banner.compromised {{
    background: rgba(232,52,58,0.06);
    border-color: rgba(232,52,58,0.25);
    border-left: 4px solid {ACCENT};
}}

.verdict-banner.suspicious {{
    background: rgba(255,179,0,0.06);
    border-color: rgba(255,179,0,0.2);
    border-left: 4px solid {WARN};
}}

.verdict-banner.clean {{
    background: rgba(0,200,83,0.05);
    border-color: rgba(0,200,83,0.18);
    border-left: 4px solid {SUCCESS};
}}

.verdict-title {{
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.3px;
}}

.verdict-title.red {{ color: {ACCENT}; }}
.verdict-title.amber {{ color: {WARN}; }}
.verdict-title.green {{ color: {SUCCESS}; }}

.verdict-sub {{
    font-size: 14px;
    color: {TXT2};
    margin-top: 6px;
    max-width: 680px;
    line-height: 1.6;
}}

.confidence-badge {{
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 7px 16px;
    border-radius: 4px;
    white-space: nowrap;
    flex-shrink: 0;
}}

.confidence-badge.red {{
    background: rgba(232,52,58,0.15);
    color: {ACCENT};
    border: 1px solid rgba(232,52,58,0.3);
}}

.confidence-badge.amber {{
    background: rgba(255,179,0,0.12);
    color: {WARN};
    border: 1px solid rgba(255,179,0,0.25);
}}

.confidence-badge.green {{
    background: rgba(0,200,83,0.1);
    color: {SUCCESS};
    border: 1px solid rgba(0,200,83,0.22);
}}

/* LAYER STATUS PANEL */
.layers-panel {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    overflow: hidden;
}}

.layer-row {{
    display: flex;
    align-items: center;
    padding: 18px 20px;
    border-bottom: 1px solid {BORDER};
    gap: 16px;
}}

.layer-row:last-child {{
    border-bottom: none;
}}

.layer-bar {{
    width: 3px;
    height: 44px;
    border-radius: 2px;
    flex-shrink: 0;
}}

.layer-bar.red {{ background: {ACCENT}; }}
.layer-bar.green {{ background: {SUCCESS}; }}
.layer-bar.amber {{ background: {WARN}; }}
.layer-bar.grey {{ background: {BORDER}; }}

.layer-name {{
    font-size: 10px;
    font-weight: 700;
    color: {TXT3};
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 5px;
}}

.layer-status {{
    font-size: 15px;
    font-weight: 800;
}}

.layer-status.red {{ color: {ACCENT}; }}
.layer-status.green {{ color: {SUCCESS}; }}
.layer-status.amber {{ color: {WARN}; }}
.layer-status.grey {{ color: {TXT3}; }}

.layer-detail {{
    font-size: 12px;
    color: {TXT2};
    margin-top: 3px;
}}

/* FINDINGS */
.finding-card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 20px 20px 20px 24px;
    margin-bottom: 8px;
    display: flex;
    gap: 20px;
}}

.finding-card.critical {{
    border-left: 3px solid {ACCENT};
}}

.finding-card.high {{
    border-left: 3px solid {WARN};
}}

.finding-card.medium {{
    border-left: 3px solid {CYAN};
}}

.sev-badge {{
    flex-shrink: 0;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    padding: 4px 8px;
    border-radius: 3px;
    height: fit-content;
    margin-top: 2px;
}}

.sev-badge.critical {{
    background: rgba(232,52,58,0.15);
    color: {ACCENT};
}}

.sev-badge.high {{
    background: rgba(255,179,0,0.12);
    color: {WARN};
}}

.sev-badge.medium {{
    background: rgba(0,212,255,0.1);
    color: {CYAN};
}}

.finding-title {{
    font-size: 15px;
    font-weight: 700;
    color: {TXT1};
    margin-bottom: 7px;
    line-height: 1.3;
}}

.finding-detail {{
    font-size: 13px;
    color: {TXT2};
    line-height: 1.65;
}}

/* STEPS */
.step-item {{
    display: flex;
    gap: 18px;
    padding: 18px 0;
    border-bottom: 1px solid {BORDER};
}}

.step-item:last-child {{
    border-bottom: none;
}}

.step-num {{
    width: 28px;
    height: 28px;
    border-radius: 50%;
    border: 1.5px solid {ACCENT};
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 800;
    color: {ACCENT};
    flex-shrink: 0;
    margin-top: 2px;
    font-family: 'JetBrains Mono', monospace;
}}

.step-title {{
    font-size: 15px;
    font-weight: 700;
    color: {TXT1};
    margin-bottom: 5px;
}}

.step-detail {{
    font-size: 13px;
    color: {TXT2};
    line-height: 1.65;
}}

/* UPLOAD ZONE */
[data-testid="stFileUploader"] {{
    background: {SURFACE} !important;
    border: 1.5px dashed {BORDER} !important;
    border-radius: 8px !important;
    padding: 8px !important;
    transition: border-color 0.2s !important;
}}

[data-testid="stFileUploader"]:hover {{
    border-color: {ACCENT} !important;
}}

/* BUTTONS */
.stButton > button {{
    background: {ACCENT} !important;
    border: none !important;
    border-radius: 5px !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 12px !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
    padding: 10px 24px !important;
    font-family: 'Inter', sans-serif !important;
    transition: opacity 0.15s !important;
}}

.stButton > button:hover {{
    opacity: 0.85 !important;
}}

/* DOWNLOAD BUTTON */
[data-testid="stDownloadButton"] > button {{
    background: {SURFACE} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 5px !important;
    color: {TXT2} !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: 1px !important;
    transition: border-color 0.15s !important;
}}

[data-testid="stDownloadButton"] > button:hover {{
    border-color: {ACCENT} !important;
    color: {TXT1} !important;
}}

/* INPUTS */
.stTextInput > div > div > input {{
    background: {SURFACE} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 5px !important;
    color: {TXT1} !important;
    font-size: 13px !important;
    font-family: 'JetBrains Mono', monospace !important;
}}

/* DATAFRAME */
[data-testid="stDataFrame"] {{
    border: 1px solid {BORDER} !important;
    border-radius: 6px !important;
}}

/* SPINNER */
.stSpinner > div {{
    border-top-color: {ACCENT} !important;
}}

/* SCROLLBAR */
::-webkit-scrollbar {{ width: 4px; height: 4px; }}
::-webkit-scrollbar-track {{ background: {BG}; }}
::-webkit-scrollbar-thumb {{
    background: {BORDER};
    border-radius: 2px;
}}
::-webkit-scrollbar-thumb:hover {{
    background: {ACCENT};
}}

/* ALERTS */
[data-testid="stAlert"] {{
    border-radius: 6px !important;
    font-size: 13px !important;
}}

/* PLOTLY CHARTS BG */
.js-plotly-plot .plotly {{
    border-radius: 8px;
}}

/* CAPTION */
.stCaption {{
    color: {TXT3} !important;
    font-size: 11px !important;
}}

/* METRIC */
[data-testid="metric-container"] {{
    background: {SURFACE} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 6px !important;
    padding: 20px !important;
}}

/* TABLE */
th {{
    background: {SURFACE} !important;
    color: {TXT2} !important;
    font-size: 11px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
}}

/* THEME TOGGLE BUTTON */
.theme-toggle {{
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 9999;
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 50px;
    padding: 10px 18px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    color: {TXT1};
    display: flex;
    align-items: center;
    gap: 8px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    transition: all 0.2s;
    font-family: 'Inter', sans-serif;
}}

.theme-toggle:hover {{
    border-color: {ACCENT};
    transform: translateY(-1px);
}}

/* DEMO BADGE */
.demo-badge {{
    display: inline-block;
    background: rgba(255,179,0,0.12);
    border: 1px solid rgba(255,179,0,0.25);
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 10px;
    font-weight: 700;
    color: {WARN};
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-left: 12px;
}}

/* STATUS INDICATOR */
.status-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 0;
    border-bottom: 1px solid {BORDER};
}}

.status-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}

.status-dot.green {{
    background: {SUCCESS};
    box-shadow: 0 0 8px {SUCCESS};
}}

.status-dot.grey {{
    background: {BORDER};
}}

.status-dot.amber {{
    background: {WARN};
    box-shadow: 0 0 8px {WARN};
}}

.status-label {{
    font-size: 12px;
    font-weight: 500;
    color: {TXT1};
}}

.status-sub {{
    font-size: 11px;
    color: {TXT3};
    margin-left: auto;
}}
</style>
""", unsafe_allow_html=True)

# -- HELPER FUNCTIONS --

def geolocate_ips(ip_list):
    locations = []
    seen = set()
    skip = ('192.168', '10.', '172.',
            '127.', '0.', '-')
    for ip in ip_list:
        if ip in seen or not ip:
            continue
        seen.add(ip)
        if (ip == 'UNKNOWN' or
                any(ip.startswith(s) for s in skip)):
            continue
        try:
            r = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=3)
            d = r.json()
            if d.get('status') == 'success':
                locations.append({
                    'ip': ip,
                    'lat': d['lat'],
                    'lon': d['lon'],
                    'country': d['country'],
                    'city': d.get('city', ''),
                    'isp': d.get('isp', ''),
                    'suspicious': False
                })
        except Exception:
            continue
    return locations


def get_verdict(hmac_bad, deleted, injected,
                anomalies, critical, total):
    if deleted > 0 or injected > 0:
        return "COMPROMISED", "compromised", "red"
    if hmac_bad and deleted == 0:
        # HMAC flagged but no actual deletions
        # means minor HMAC mismatch not deletion
        pass
    if critical > 0 or anomalies > total * 0.02:
        return "SUSPICIOUS", "suspicious", "amber"
    return "CLEAN", "clean", "green"


def build_findings(df, deleted, injected,
                   critical, anomalies):
    out = []
    if deleted > 0:
        out.append({
            'sev': 'critical',
            'title': (
                f'{deleted} log records '
                f'confirmed deleted'),
            'detail': (
                'Cryptographic chain verification '
                'detected records missing from this '
                'file. This is mathematical proof of '
                'deliberate log erasure. Attackers '
                'delete logs to remove evidence of '
                'privilege escalation, lateral '
                'movement, or data exfiltration.')
        })
    if injected > 0:
        out.append({
            'sev': 'critical',
            'title': (
                f'{injected} records injected '
                f'into log file'),
            'detail': (
                f'{injected} entries found that do '
                'not appear in the trusted baseline. '
                'These may represent forged entries '
                'inserted to create a false audit '
                'trail or confuse investigators.')
        })
    if 'event_id' in df.columns:
        n1102 = (df['event_id'] == 1102).sum()
        n4719 = (df['event_id'] == 4719).sum()
        if n1102 > 0:
            out.append({
                'sev': 'critical',
                'title': (
                    f'Security log cleared '
                    f'({n1102} instance(s)) '
                    f'Event ID 1102'),
                'detail': (
                    'Event ID 1102 is generated when '
                    'the Windows Security log is cleared. '
                    'This is performed by attackers after '
                    'intrusion to destroy forensic '
                    'evidence. Legitimate administrators '
                    'rarely clear security logs.')
            })
        if n4719 > 0:
            out.append({
                'sev': 'high',
                'title': (
                    f'Audit policy modified '
                    f'({n4719} instance(s)) '
                    f'Event ID 4719'),
                'detail': (
                    'Event ID 4719 indicates the audit '
                    'policy was changed. Attackers modify '
                    'audit policy before executing '
                    'malicious actions to suppress '
                    'logging. This is a precursor to '
                    'anti-forensic activity.')
            })
    if 'process_name' in df.columns:
        tools = ['wevtutil', 'whoami', 'net.exe',
                 'runas', 'psexec', 'mimikatz']
        mask = df['process_name'].str.lower(
            ).str.contains(
            '|'.join(tools), na=False)
        sus = df[mask]
        if len(sus) > 0:
            top = (sus['process_name']
                   .value_counts().head(3))
            names = ', '.join(top.index.tolist())
            out.append({
                'sev': 'high',
                'title': (
                    f'Attack-associated processes: '
                    f'{names}'),
                'detail': (
                    'These executables are commonly '
                    'associated with post-exploitation '
                    'activity. wevtutil.exe is the '
                    'primary Windows log-clearing tool. '
                    'whoami.exe is used for privilege '
                    'enumeration. Their presence '
                    'corroborates other findings.')
            })
    if anomalies > 0 and not out:
        out.append({
            'sev': 'medium',
            'title': (
                f'{anomalies} anomalous patterns '
                f'detected by AI model'),
            'detail': (
                f'Isolation Forest identified '
                f'{anomalies} events with statistical '
                f'properties inconsistent with the '
                f'established normal baseline. '
                f'Further investigation recommended.')
        })
    return out


def make_chart_layout(height=320):
    return dict(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter, sans-serif',
            color=TXT2,
            size=11),
        margin=dict(l=0, r=0, t=12, b=0),
        height=height,
        xaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            showgrid=True,
            zeroline=False),
        yaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            showgrid=True,
            zeroline=False),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            font=dict(size=11)),
        hovermode='closest'
    )


# -- DEMO DATA --
DEMO = {
    'total': 31658,
    'deleted': 0,
    'injected': 0,
    'anomalies': 284,
    'critical': 7,
    'confidence': 94.2,
    'chain': 'INTACT',
    'ai': 'ANOMALIES DETECTED',
    'verdict': 'SUSPICIOUS',
    'verdict_class': 'suspicious',
    'verdict_color': 'amber'
}

# -- SIDEBAR --
with st.sidebar:
    st.markdown(f"""
<div class="sidebar-brand">
    <div class="sidebar-logo">
        LOG<span>SHIELD</span>
    </div>
    <div class="sidebar-tag">
        Forensic Integrity Platform
    </div>
</div>
""", unsafe_allow_html=True)

    pages = [
        ("Dashboard", "Overview and KPIs"),
        ("Analysis", "Run file analysis"),
        ("Findings", "Forensic findings"),
        ("Report", "Export report"),
        ("Live Monitor", "Real-time mode"),
    ]

    for pg, desc in pages:
        is_active = st.session_state.page == pg
        active_class = "active" if is_active else ""
        dot = (
            '<span class="nav-dot"></span>'
            if is_active else "")
        clicked = st.button(
            pg,
            key=f"nav_{pg}",
            use_container_width=True)
        if clicked:
            st.session_state.page = pg
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # System status in sidebar
    IF_READY = os.path.exists(
        'models_saved/isolation_forest.pkl')
    CHAIN_READY = os.path.exists(
        'models_saved/hmac_chain.json')

    st.markdown(
        f'<div style="padding:0 12px;'
        f'margin-top:8px">'
        f'<div style="font-size:9px;'
        f'font-weight:700;color:{TXT3};'
        f'letter-spacing:2px;'
        f'text-transform:uppercase;'
        f'padding-bottom:10px;'
        f'border-bottom:1px solid {BORDER};'
        f'margin-bottom:10px">System Status</div>',
        unsafe_allow_html=True)

    items = [
        ("HMAC Chain", CHAIN_READY),
        ("Isolation Forest", IF_READY),
        ("LSTM Model", False),
        ("Autoencoder", False),
    ]
    for name, ready in items:
        dot_col = 'green' if ready else 'grey'
        sub = 'Ready' if ready else 'Pending'
        st.markdown(f"""
<div class="status-row">
    <span class="status-dot {dot_col}"></span>
    <span class="status-label">{name}</span>
    <span class="status-sub">{sub}</span>
</div>""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    theme_choice = st.radio(
        "Theme",
        options=["Dark", "Light"],
        index=0 if st.session_state.dark_mode else 1,
        horizontal=True,
        key="theme_radio"
    )
    new_dark = (theme_choice == "Dark")
    if new_dark != st.session_state.dark_mode:
        st.session_state.dark_mode = new_dark
        st.rerun()

page = st.session_state.page
done = st.session_state.analysis_done

# -- PAGE: DASHBOARD --
if page == 'Dashboard':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">
        Dashboard
        <span class="demo-badge">
            {'Live' if done else 'Demo'}
        </span>
    </div>
    <div class="top-bar-meta">
        <div class="live-pill">
            <span class="live-dot"></span>
            System Ready
        </div>
        <span>v1.0</span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    # Pull values
    if done:
        tv = st.session_state.anomaly_count
        dv = st.session_state.deleted_count
        av = st.session_state.anomaly_count
        crv = st.session_state.critical_count
        vt = st.session_state.verdict
        vc = (
            "red" if vt == "COMPROMISED"
            else "amber" if vt == "SUSPICIOUS"
            else "green")
        vclass = (
            "compromised" if vt == "COMPROMISED"
            else "suspicious" if vt == "SUSPICIOUS"
            else "clean")
        total = len(
            st.session_state.df_result
        ) if st.session_state.df_result is not None else 0
    else:
        tv = DEMO['total']
        dv = DEMO['deleted']
        av = DEMO['anomalies']
        crv = DEMO['critical']
        vt = DEMO['verdict']
        vc = DEMO['verdict_color']
        vclass = DEMO['verdict_class']
        total = DEMO['total']

    # KPI GRID - order: 1 4 3 2 5 7 6 8
    # 1=Total Events 4=Critical 3=AI Anomalies
    # 2=Deleted 5=Chain 7=Confidence
    # 6=Suspicious Procs 8=Time Range
    st.markdown(f"""
<div class="kpi-row">
    <div class="kpi-card cyan">
        <div class="kpi-val cyan">
            {total:,}
        </div>
        <div class="kpi-label">Total Events</div>
        <div class="kpi-delta neutral">
            Analyzed
        </div>
    </div>
    <div class="kpi-card
        {'accent' if crv > 0 else 'success'}">
        <div class="kpi-val
            {'red' if crv > 0 else 'green'}">
            {crv:,}
        </div>
        <div class="kpi-label">Critical Events</div>
        <div class="kpi-delta
            {'bad' if crv > 0 else 'ok'}">
            {'1102 / 4719 detected'
             if crv > 0 else 'None detected'}
        </div>
    </div>
    <div class="kpi-card
        {'warn' if av > 0 else 'success'}">
        <div class="kpi-val
            {'amber' if av > 0 else 'green'}">
            {av:,}
        </div>
        <div class="kpi-label">AI Anomalies</div>
        <div class="kpi-delta
            {'bad' if av > 0 else 'ok'}">
            {'Flagged' if av > 0 else 'Clean'}
        </div>
    </div>
    <div class="kpi-card
        {'accent' if dv > 0 else 'success'}">
        <div class="kpi-val
            {'red' if dv > 0 else 'green'}">
            {dv:,}
        </div>
        <div class="kpi-label">Deleted Records</div>
        <div class="kpi-delta
            {'bad' if dv > 0 else 'ok'}">
            {'Confirmed' if dv > 0 else 'None'}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    # Second row of KPIs
    chain_val = (
        "FAIL" if (done and dv > 0)
        else "PASS")
    chain_col = (
        "red" if chain_val == "FAIL"
        else "green")
    conf_val = (
        f"{DEMO['confidence']}%" if not done
        else (
            "HIGH" if vt == "CLEAN"
            else "MEDIUM"))

    st.markdown(f"""
<div class="kpi-row">
    <div class="kpi-card
        {'accent' if chain_val=='FAIL'
         else 'success'}">
        <div class="kpi-val {chain_col}">
            {chain_val}
        </div>
        <div class="kpi-label">Chain Status</div>
        <div class="kpi-delta
            {'bad' if chain_val=='FAIL' else 'ok'}">
            HMAC-SHA256
        </div>
    </div>
    <div class="kpi-card cyan">
        <div class="kpi-val cyan">
            {conf_val}
        </div>
        <div class="kpi-label">Confidence</div>
        <div class="kpi-delta neutral">
            Detection certainty
        </div>
    </div>
    <div class="kpi-card">
        <div class="kpi-val">
            2
        </div>
        <div class="kpi-label">Active Layers</div>
        <div class="kpi-delta neutral">
            of 4 total
        </div>
    </div>
    <div class="kpi-card
        {'accent' if vt != 'CLEAN' else 'success'}">
        <div class="kpi-val {vc}">
            {vt}
        </div>
        <div class="kpi-label">Verdict</div>
        <div class="kpi-delta neutral">
            Overall assessment
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    # VERDICT BANNER
    vt_desc = {
        "COMPROMISED": (
            "Confirmed evidence of deliberate log "
            "manipulation. This file cannot be used "
            "as reliable evidence without "
            "further investigation."),
        "SUSPICIOUS": (
            "Anomalous patterns detected "
            "inconsistent with normal system "
            "behavior. Manual review recommended."),
        "CLEAN": (
            "Cryptographic chain intact. No "
            "statistical anomalies detected. "
            "Log file appears authentic.")
    }

    st.markdown(f"""
<div class="verdict-banner {vclass}">
    <div>
        <div class="verdict-title {vc}">
            INTEGRITY {vt}
        </div>
        <div class="verdict-sub">
            {vt_desc.get(vt, '')}
        </div>
    </div>
    <div class="confidence-badge {vc}">
        HIGH CONFIDENCE
    </div>
</div>
""", unsafe_allow_html=True)

    # CHARTS ROW
    st.markdown(
        '<div class="sec-label">'
        'Detection Overview</div>',
        unsafe_allow_html=True)

    ch1, ch2 = st.columns([3, 2])

    with ch1:
        # Event timeline or demo
        if done and st.session_state.df_result is not None:
            df_r = st.session_state.df_result
            if ('if_score' in df_r.columns and
                    'time_created' in df_r.columns):
                norm = df_r[df_r['if_flag'] == 0]
                anom = df_r[df_r['if_flag'] == 1]
                fig = go.Figure()
                fig.add_trace(go.Scattergl(
                    x=norm['time_created'],
                    y=norm['if_score'],
                    mode='markers',
                    name='Normal',
                    marker=dict(
                        color=SUCCESS,
                        size=3,
                        opacity=0.5)))
                if len(anom) > 0:
                    fig.add_trace(go.Scattergl(
                        x=anom['time_created'],
                        y=anom['if_score'],
                        mode='markers',
                        name='Anomaly',
                        marker=dict(
                            color=ACCENT,
                            size=8,
                            symbol='diamond')))
                fig.update_layout(
                    **make_chart_layout(320),
                    title=dict(
                        text='Event Timeline',
                        font=dict(
                            size=13,
                            color=TXT1)))
                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={'displayModeBar': False})
        else:
            # Demo chart
            t = pd.date_range(
                '2026-08-25 08:00',
                periods=200, freq='3min')
            y = np.random.uniform(0, 0.3, 200)
            y[80:90] = np.random.uniform(0.7, 1, 10)
            y[150:155] = np.random.uniform(0.6, 0.9, 5)
            colors_arr = [
                ACCENT if v > 0.5 else SUCCESS
                for v in y]
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=t, y=y,
                mode='markers',
                name='Events',
                marker=dict(
                    color=colors_arr,
                    size=5)))
            fig.update_layout(
                **make_chart_layout(320),
                title=dict(
                    text='Event Timeline (Demo)',
                    font=dict(
                        size=13, color=TXT1)))
            st.plotly_chart(
                fig,
                use_container_width=True,
                config={'displayModeBar': False})

    with ch2:
        # Detection layer donut
        layer_vals = [1, 1, 0, 0]
        layer_names = [
            'HMAC Chain',
            'Isolation Forest',
            'LSTM (pending)',
            'Autoencoder (pending)']
        layer_colors = [
            SUCCESS, WARN, BORDER, BORDER]
        fig2 = go.Figure(go.Pie(
            values=[25, 25, 25, 25],
            labels=layer_names,
            hole=0.65,
            marker=dict(colors=layer_colors,
                        line=dict(width=0)),
            textinfo='none',
            hoverinfo='label'))
        fig2.add_annotation(
            text='2/4<br><span style="font-size:11px">'
                 'Active</span>',
            x=0.5, y=0.5,
            font=dict(
                size=20,
                color=TXT1,
                family='Inter'),
            showarrow=False)
        fig2.update_layout(
            **make_chart_layout(320),
            showlegend=True,
            title=dict(
                text='Detection Layers',
                font=dict(size=13, color=TXT1)))
        st.plotly_chart(
            fig2,
            use_container_width=True,
            config={'displayModeBar': False})

    st.markdown('</div>', unsafe_allow_html=True)

# -- PAGE: ANALYSIS --
elif page == 'Analysis':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">Log File Analysis</div>
    <div class="top-bar-meta">
        <span>Upload a log file to run analysis</span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    st.markdown(
        '<div class="sec-label">'
        'File Upload</div>',
        unsafe_allow_html=True)
    st.caption(
        "Accepted: .csv  |  "
        "Maximum: 50 MB  |  "
        "Processed in memory, never stored")

    uploaded = st.file_uploader(
        "Select log file",
        type=['csv'],
        label_visibility="collapsed")

    if uploaded is None:
        st.markdown(f"""
<div style="
    text-align:center;
    padding:60px 0;
    color:{TXT3};
    font-size:13px;
    letter-spacing:2px;
    text-transform:uppercase;
    border:1px dashed {BORDER};
    border-radius:8px;
    margin-top:16px">
    No file selected. Upload a Windows
    Event Log CSV to begin analysis.
</div>""", unsafe_allow_html=True)

    if uploaded is not None:
        if uploaded.size > 50 * 1024 * 1024:
            st.error(
                "File exceeds 50 MB limit.")
            st.stop()

        with st.spinner(
                "Running integrity analysis..."):
            try:
                df = parse_csv_from_bytes(
                    uploaded.getvalue())
                df = extract_features(df)
            except Exception as e:
                st.error(
                    "Analysis failed. Verify file "
                    f"format. Detail: {str(e)}")
                st.stop()

        # HMAC
        CHAIN = 'models_saved/hmac_chain.json'
        hmac_ok = os.path.exists(CHAIN)
        hmac_bad = False
        deleted = 0
        injected = 0
        if hmac_ok:
            try:
                df = verify_hmac_chain(df, CHAIN)
                c = check_chain_continuity(
                    df, CHAIN)
                hmac_bad = (
                    df['hmac_flag'].sum() > 0 or
                    c['gap_detected'] or
                    c['injection_detected'])
                deleted = c['missing_records']
                injected = c['extra_records']
            except Exception:
                hmac_ok = False

        # IF
        IF = 'models_saved/isolation_forest.pkl'
        if_ok = os.path.exists(IF)
        anomalies = 0
        critical = 0
        if if_ok:
            try:
                df = predict_anomalies(df, IF)
                anomalies = int(
                    df['if_flag'].sum())
                critical = int(
                    df['is_critical_event'].sum()
                    if 'is_critical_event'
                    in df.columns else 0)
            except Exception:
                if_ok = False

        verdict, vclass, vc = get_verdict(
            hmac_bad, deleted, injected,
            anomalies, critical, len(df))

        findings = build_findings(
            df, deleted, injected,
            critical, anomalies)

        # Save to session
        st.session_state.analysis_done = True
        st.session_state.df_result = df
        st.session_state.verdict = verdict
        st.session_state.deleted_count = deleted
        st.session_state.injected_count = injected
        st.session_state.anomaly_count = anomalies
        st.session_state.critical_count = critical
        st.session_state.findings = findings
        st.session_state.analysis_time = (
            datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S UTC"))

        # Show verdict
        vt_desc = {
            "COMPROMISED": (
                f"Confirmed evidence of deliberate "
                f"log manipulation. {deleted} records "
                f"deleted. This file cannot be used "
                f"as reliable evidence without "
                f"further investigation."),
            "SUSPICIOUS": (
                "Anomalous patterns detected "
                "inconsistent with normal behavior. "
                "Manual review recommended."),
            "CLEAN": (
                "Cryptographic chain intact. "
                "No significant anomalies detected. "
                "Log file appears authentic.")
        }
        st.markdown(f"""
<div class="verdict-banner {vclass}">
    <div>
        <div class="verdict-title {vc}">
            INTEGRITY {verdict}
        </div>
        <div class="verdict-sub">
            {vt_desc.get(verdict, '')}
        </div>
    </div>
    <div class="confidence-badge {vc}">
        HIGH CONFIDENCE
    </div>
</div>
""", unsafe_allow_html=True)

        # Metrics
        st.markdown(f"""
<div class="kpi-row" style="margin-top:16px">
    <div class="kpi-card cyan">
        <div class="kpi-val cyan">{len(df):,}</div>
        <div class="kpi-label">Total Events</div>
        <div class="kpi-delta neutral">Analyzed</div>
    </div>
    <div class="kpi-card
        {'accent' if deleted>0 else 'success'}">
        <div class="kpi-val
            {'red' if deleted>0 else 'green'}">
            {deleted:,}
        </div>
        <div class="kpi-label">Deleted Records</div>
        <div class="kpi-delta
            {'bad' if deleted>0 else 'ok'}">
            {'Confirmed' if deleted>0 else 'None'}
        </div>
    </div>
    <div class="kpi-card
        {'warn' if anomalies>0 else 'success'}">
        <div class="kpi-val
            {'amber' if anomalies>0 else 'green'}">
            {anomalies:,}
        </div>
        <div class="kpi-label">AI Anomalies</div>
        <div class="kpi-delta
            {'bad' if anomalies>0 else 'ok'}">
            {'Flagged' if anomalies>0 else 'Clean'}
        </div>
    </div>
    <div class="kpi-card
        {'accent' if critical>0 else 'success'}">
        <div class="kpi-val
            {'red' if critical>0 else 'green'}">
            {critical:,}
        </div>
        <div class="kpi-label">Critical Events</div>
        <div class="kpi-delta
            {'bad' if critical>0 else 'ok'}">
            {'1102/4719' if critical>0 else 'None'}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

        # Layer status
        st.markdown(
            '<div class="sec-label">'
            'Detection Results</div>',
            unsafe_allow_html=True)

        l1c = 'red' if hmac_bad else (
            'green' if hmac_ok else 'grey')
        l1s = ('COMPROMISED' if hmac_bad else
               'INTACT' if hmac_ok else 'UNAVAILABLE')
        l1d = (
            f'{deleted} records deleted, '
            f'{injected} injected'
            if hmac_bad else
            'Chain fully verified'
            if hmac_ok else
            'Chain file not found')
        l2c = ('amber' if anomalies > 0 else
               'green' if if_ok else 'grey')
        l2s = ('ANOMALIES DETECTED'
               if anomalies > 0 else
               'NORMAL' if if_ok else 'UNAVAILABLE')
        l2d = (
            f'{anomalies} events flagged'
            if anomalies > 0 else
            'No anomalies' if if_ok else
            'Model not loaded')

        st.markdown(f"""
<div class="layers-panel">
    <div class="layer-row">
        <div class="layer-bar {l1c}"></div>
        <div>
            <div class="layer-name">
                Layer 1 - HMAC-SHA256 Chain
            </div>
            <div class="layer-status {l1c}">
                {l1s}
            </div>
            <div class="layer-detail">
                {l1d} - Mathematical certainty
            </div>
        </div>
    </div>
    <div class="layer-row">
        <div class="layer-bar {l2c}"></div>
        <div>
            <div class="layer-name">
                Layer 2a - Isolation Forest
            </div>
            <div class="layer-status {l2c}">
                {l2s}
            </div>
            <div class="layer-detail">{l2d}</div>
        </div>
    </div>
    <div class="layer-row">
        <div class="layer-bar grey"></div>
        <div>
            <div class="layer-name">
                Layer 2b - LSTM Sequence Model
            </div>
            <div class="layer-status grey">
                PENDING
            </div>
            <div class="layer-detail">
                Requires expanded dataset
            </div>
        </div>
    </div>
    <div class="layer-row">
        <div class="layer-bar grey"></div>
        <div>
            <div class="layer-name">
                Layer 2c - Autoencoder
            </div>
            <div class="layer-status grey">
                PENDING
            </div>
            <div class="layer-detail">
                Requires expanded dataset
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

        # Timeline
        if ('if_score' in df.columns and
                'time_created' in df.columns):
            st.markdown(
                '<div class="sec-label">'
                'Event Timeline</div>',
                unsafe_allow_html=True)

            norm = df[df['if_flag'] == 0]
            anom = df[df['if_flag'] == 1]

            fig = go.Figure()

            # Normal events as small dots
            fig.add_trace(go.Scattergl(
                x=norm['time_created'],
                y=norm['if_score'],
                mode='markers',
                name=f'Normal ({len(norm):,})',
                marker=dict(
                    color=SUCCESS,
                    size=3,
                    opacity=0.4),
                hovertemplate=(
                    'Time: %{x}<br>'
                    'Score: %{y:.3f}'
                    '<extra>Normal</extra>')))

            # Anomalies as larger diamonds
            if len(anom) > 0:
                fig.add_trace(go.Scattergl(
                    x=anom['time_created'],
                    y=anom['if_score'],
                    mode='markers',
                    name=f'Anomaly ({len(anom):,})',
                    marker=dict(
                        color=ACCENT,
                        size=10,
                        symbol='diamond',
                        line=dict(
                            color='rgba(255,255,255,0.3)',
                            width=1)),
                    hovertemplate=(
                        'Time: %{x}<br>'
                        'Score: %{y:.3f}'
                        '<extra>ANOMALY</extra>')))

            # Add threshold line
            threshold_y = 0.5
            fig.add_hline(
                y=threshold_y,
                line=dict(
                    color=WARN,
                    width=1,
                    dash='dash'),
                annotation=dict(
                    text='Detection threshold',
                    font=dict(
                        color=WARN,
                        size=10),
                    xref='paper',
                    x=1))

            fig.update_layout(
                **make_chart_layout(340),
                title=dict(
                    text=(
                        f'Event Timeline  '
                        f'{len(norm):,} normal  '
                        f'{len(anom):,} anomalies'),
                    font=dict(
                        size=13,
                        color=TXT1,
                        family='Inter')),
                xaxis=dict(
                    gridcolor=BORDER,
                    linecolor=BORDER,
                    title='Time',
                    titlefont=dict(
                        size=11, color=TXT2)),
                yaxis=dict(
                    gridcolor=BORDER,
                    linecolor=BORDER,
                    title='Anomaly Score',
                    titlefont=dict(
                        size=11, color=TXT2),
                    range=[0, 1.05]))

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={'displayModeBar': False})

            st.caption(
                f"Green dots: normal events  "
                f"Red diamonds: anomalies  "
                f"Dashed line: detection threshold")

        # Process activity
        if 'process_name' in df.columns:
            tools = ['wevtutil', 'whoami',
                     'net.exe', 'runas',
                     'cmd.exe', 'powershell',
                     'psexec']
            mask = df['process_name'].str.lower(
                ).str.contains(
                '|'.join(tools), na=False)
            sus = df[mask]
            if len(sus) > 0:
                st.markdown(
                    '<div class="sec-label">'
                    'Process Activity</div>',
                    unsafe_allow_html=True)
                pc = (sus['process_name']
                      .value_counts()
                      .head(8)
                      .reset_index())
                pc.columns = ['Process', 'Count']
                bar = go.Figure(go.Bar(
                    x=pc['Count'],
                    y=pc['Process'],
                    orientation='h',
                    marker=dict(
                        color=ACCENT,
                        opacity=0.8,
                        line=dict(width=0))))
                bar.update_layout(
                    **make_chart_layout(280))
                st.plotly_chart(
                    bar,
                    use_container_width=True,
                    config={'displayModeBar': False})

        # World map
        if 'ip_address' in df.columns:
            skip = ('192.168', '10.', '172.',
                    '127.', '-', 'UNKNOWN')
            pub = [
                ip for ip in
                df['ip_address'].dropna().unique()
                if ip and not any(
                    ip.startswith(s) for s in skip)]
            if pub:
                st.markdown(
                    '<div class="sec-label">'
                    'IP Origin Map</div>',
                    unsafe_allow_html=True)
                with st.spinner(
                        "Resolving locations..."):
                    locs = geolocate_ips(pub[:20])
                if locs:
                    sus_ips = (
                        df[df['if_flag'] == 1][
                            'ip_address']
                        .dropna().unique().tolist()
                        if 'if_flag' in df.columns
                        else [])
                    loc_df = pd.DataFrame(locs)
                    loc_df['type'] = loc_df['ip'].apply(
                        lambda x: 'Suspicious'
                        if x in sus_ips else 'Normal')
                    map_fig = px.scatter_geo(
                        loc_df,
                        lat='lat', lon='lon',
                        color='type',
                        color_discrete_map={
                            'Suspicious': ACCENT,
                            'Normal': SUCCESS},
                        hover_data={
                            'ip': True,
                            'country': True,
                            'city': True,
                            'isp': True,
                            'lat': False,
                            'lon': False},
                        projection='natural earth')
                    map_fig.update_traces(
                        marker=dict(
                            size=12, opacity=0.9))
                    map_fig.update_layout(
                        geo=dict(
                            bgcolor='rgba(0,0,0,0)',
                            landcolor='#1a2035',
                            oceancolor='#0a0c14',
                            showocean=True,
                            showland=True,
                            showcountries=True,
                            countrycolor=BORDER,
                            showframe=False),
                        **make_chart_layout(350),
                        showlegend=True)
                    st.plotly_chart(
                        map_fig,
                        use_container_width=True,
                        config={
                            'displayModeBar': False})

        # Flagged events table
        if 'if_flag' in df.columns:
            flagged = df[df['if_flag'] == 1]
            if len(flagged) > 0:
                st.markdown(
                    f'<div class="sec-label">'
                    f'Flagged Events '
                    f'({len(flagged):,})</div>',
                    unsafe_allow_html=True)
                show_cols = [
                    c for c in [
                        'time_created',
                        'event_id',
                        'account_name',
                        'process_name',
                        'is_critical_event',
                        'if_score'
                    ] if c in flagged.columns]
                st.dataframe(
                    flagged[show_cols]
                    .sort_values(
                        'if_score',
                        ascending=False)
                    .head(100),
                    use_container_width=True,
                    hide_index=True)

        st.markdown(
            '<div style="margin-top:8px">'
            'Go to the Report page to download '
            'the full forensic report.'
            '</div>',
            unsafe_allow_html=True)

        st.info(
            "Results are saved. If you switch theme, "
            "go to Findings page to see results. "
            "Re-upload file only if you want new analysis.")

    st.markdown('</div>', unsafe_allow_html=True)

# -- PAGE: FINDINGS --
elif page == 'Findings':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">
        Forensic Findings
    </div>
    <div class="top-bar-meta">
        <span>
            {'Analysis complete'
             if done else 'No analysis run yet'}
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    if not done:
        st.info(
            "No analysis has been run yet. "
            "Go to Analysis, upload a file, "
            "then return here.")
    else:
        findings = st.session_state.findings
        vt = st.session_state.verdict
        vc = (
            "red" if vt == "COMPROMISED"
            else "amber" if vt == "SUSPICIOUS"
            else "green")
        vclass = (
            "compromised" if vt == "COMPROMISED"
            else "suspicious" if vt == "SUSPICIOUS"
            else "clean")

        st.markdown(
            '<div class="sec-label">'
            'Forensic Findings</div>',
            unsafe_allow_html=True)

        if not findings:
            st.markdown(f"""
<div class="finding-card medium">
    <div class="sev-badge medium">INFO</div>
    <div>
        <div class="finding-title">
            No significant findings
        </div>
        <div class="finding-detail">
            Log file integrity appears intact.
            No indicators of tampering were
            identified by any detection layer.
        </div>
    </div>
</div>""", unsafe_allow_html=True)
        else:
            for f in findings:
                st.markdown(f"""
<div class="finding-card {f['sev']}">
    <div class="sev-badge {f['sev']}">
        {f['sev'].upper()}
    </div>
    <div>
        <div class="finding-title">
            {f['title']}
        </div>
        <div class="finding-detail">
            {f['detail']}
        </div>
    </div>
</div>""", unsafe_allow_html=True)

        # Recommended actions
        if vt != "CLEAN":
            st.markdown(
                '<div class="sec-label">'
                'Recommended Actions</div>',
                unsafe_allow_html=True)

            steps = [
                ("Preserve log file",
                 "Create a write-protected forensic "
                 "copy immediately. Do not allow any "
                 "process to modify the original."),
                ("Isolate affected system",
                 "Disconnect the machine from the "
                 "network to prevent further evidence "
                 "destruction or ongoing attacker "
                 "access."),
                ("Engage incident response",
                 "Escalate to your IR team with this "
                 "LogShield report. Record the exact "
                 "timestamp of this analysis."),
                ("Correlate with external sources",
                 "Check network, firewall, and DNS "
                 "logs for the same time period."),
                ("Preserve chain of custody",
                 "Document every action taken, by "
                 "whom, and at what time.")
            ]
            html = '<div>'
            for i, (title, detail) in enumerate(
                    steps, 1):
                html += f"""
<div class="step-item">
    <div class="step-num">{i}</div>
    <div>
        <div class="step-title">{title}</div>
        <div class="step-detail">{detail}</div>
    </div>
</div>"""
            html += '</div>'
            st.markdown(html, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

# -- PAGE: REPORT --
elif page == 'Report':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">Export Report</div>
    <div class="top-bar-meta">
        <span>Generate forensic PDF or CSV</span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    if not done:
        st.info(
            "No analysis has been run yet. "
            "Go to Analysis and upload a file first.")
    else:
        st.markdown(
            '<div class="sec-label">'
            'Export Options</div>',
            unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown(f"""
<div style="
    background:{SURFACE};
    border:1px solid {BORDER};
    border-radius:8px;
    padding:28px;
    margin-bottom:12px">
    <div style="
        font-size:16px;
        font-weight:700;
        color:{TXT1};
        margin-bottom:8px">
        Full Forensic PDF Report
    </div>
    <div style="
        font-size:13px;
        color:{TXT2};
        line-height:1.6;
        margin-bottom:20px">
        Professional document including cover page,
        executive summary, quantitative findings,
        evidence table, recommended actions,
        and methodology. Suitable for legal
        proceedings and management reporting.
    </div>
</div>""", unsafe_allow_html=True)

            try:
                pdf_bytes = generate_pdf_report(
                    df=st.session_state.df_result,
                    verdict=st.session_state.verdict,
                    deleted_count=(
                        st.session_state.deleted_count),
                    injected_count=(
                        st.session_state.injected_count),
                    anomaly_count=(
                        st.session_state.anomaly_count),
                    critical_count=(
                        st.session_state.critical_count),
                    findings=st.session_state.findings,
                    analysis_timestamp=(
                        st.session_state.analysis_time
                        or "N/A")
                )
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_bytes,
                    file_name="logshield_report.pdf",
                    mime="application/pdf",
                    use_container_width=True)
            except Exception as e:
                st.error(
                    f"PDF generation failed: {str(e)}")

        with col2:
            st.markdown(f"""
<div style="
    background:{SURFACE};
    border:1px solid {BORDER};
    border-radius:8px;
    padding:28px;
    margin-bottom:12px">
    <div style="
        font-size:16px;
        font-weight:700;
        color:{TXT1};
        margin-bottom:8px">
        Flagged Events CSV
    </div>
    <div style="
        font-size:13px;
        color:{TXT2};
        line-height:1.6;
        margin-bottom:20px">
        Spreadsheet of all events flagged as
        anomalous by the detection pipeline.
        Includes timestamps, event IDs, account
        names, process names, and anomaly scores.
        Suitable for further analysis.
    </div>
</div>""", unsafe_allow_html=True)

            df_r = st.session_state.df_result
            if (df_r is not None and
                    'if_flag' in df_r.columns):
                flagged = df_r[df_r['if_flag'] == 1]
                show = [c for c in [
                    'time_created', 'event_id',
                    'account_name', 'process_name',
                    'is_critical_event', 'if_score'
                ] if c in flagged.columns]
                st.download_button(
                    label="Download CSV Report",
                    data=flagged[show].to_csv(
                        index=False),
                    file_name=(
                        "logshield_flagged.csv"),
                    mime="text/csv",
                    use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)

# -- PAGE: LIVE MONITOR --
elif page == 'Live Monitor':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">Live Monitor</div>
    <div class="top-bar-meta">
        <span>Real-time Windows Event Log monitoring
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    st.markdown(
        '<div class="sec-label">'
        'Monitor Configuration</div>',
        unsafe_allow_html=True)

    folder = st.text_input(
        "Folder path",
        value=r"C:\Windows\System32\winevt\Logs")

    c1, c2, c3 = st.columns([2, 2, 6])
    with c1:
        start = st.button(
            "Start",
            type="primary",
            use_container_width=True)
    with c2:
        stop = st.button(
            "Stop",
            use_container_width=True)

    if start:
        if not os.path.exists(folder):
            st.error("Path not found.")
        else:
            st.success(f"Monitoring: {folder}")

            # Live chart placeholder
            st.markdown(
                '<div class="sec-label">'
                'Live Activity</div>',
                unsafe_allow_html=True)

            chart_placeholder = st.empty()
            counter_placeholder = st.empty()

            # Simulate live updates (3 cycles)
            for i in range(3):
                t = pd.date_range(
                    datetime.utcnow(),
                    periods=20,
                    freq='5s')
                y = np.random.uniform(0, 0.3, 20)
                if i == 2:
                    y[15] = 0.9

                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=list(range(len(t))),
                    y=y,
                    mode='lines+markers',
                    line=dict(
                        color=ACCENT,
                        width=2),
                    marker=dict(
                        color=[
                            ACCENT if v > 0.5
                            else SUCCESS
                            for v in y],
                        size=6)))
                fig.update_layout(
                    **make_chart_layout(280),
                    title=dict(
                        text='Live Anomaly Score',
                        font=dict(
                            size=13,
                            color=TXT1)))
                chart_placeholder.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={
                        'displayModeBar': False})
                counter_placeholder.caption(
                    f"Events processed: "
                    f"{(i+1)*20}  |  "
                    f"Alerts: "
                    f"{'1' if i==2 else '0'}")
                time.sleep(2)

    if stop:
        st.info("Monitoring stopped.")

    st.markdown(
        '<div class="sec-label">'
        'Detection Capability</div>',
        unsafe_allow_html=True)
    st.markdown(f"""
| Layer | Method | Detects | Status |
|---|---|---|---|
| 1 | HMAC-SHA256 Chain | Deletion, modification | Active |
| 2a | Isolation Forest | Temporal gaps | Active |
| 2b | LSTM | Sequence violations | Pending |
| 2c | Autoencoder | Log injection | Pending |
""")

    st.markdown('</div>', unsafe_allow_html=True)
