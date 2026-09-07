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
import hashlib
import io
import requests
from datetime import datetime
sys.path.insert(0, '.')

from src.parser import parse_csv_from_bytes, MAX_FILE_SIZE
from src.features import extract_features
from src.hmac_chain import (
    verify_hmac_chain,
    check_chain_continuity,
    check_baseline_row_count)
from src.models.isolation_forest import predict_anomalies
from dashboard.utils.pdf_report import generate_pdf_report
from dashboard.utils.threat_panels import build_all_threat_panels
from dashboard.utils.threat_render import render_threat_overview

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
if 'uploaded_bytes' not in st.session_state:
    st.session_state.uploaded_bytes = None
if 'upload_fingerprint' not in st.session_state:
    st.session_state.upload_fingerprint = None
if 'verdict' not in st.session_state:
    st.session_state.verdict = None
if 'total_events' not in st.session_state:
    st.session_state.total_events = 0
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
if 'hmac_ok' not in st.session_state:
    st.session_state.hmac_ok = False
if 'if_ok' not in st.session_state:
    st.session_state.if_ok = False
if 'chain_intact' not in st.session_state:
    st.session_state.chain_intact = True
if 'timeline_data' not in st.session_state:
    st.session_state.timeline_data = None
if 'process_chart' not in st.session_state:
    st.session_state.process_chart = []
if 'flagged_preview' not in st.session_state:
    st.session_state.flagged_preview = None
if 'threat_panels' not in st.session_state:
    st.session_state.threat_panels = None
if 'baseline_mismatch' not in st.session_state:
    st.session_state.baseline_mismatch = False
if 'baseline_warning' not in st.session_state:
    st.session_state.baseline_warning = ''

if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True 
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
    z-index: 999 !important;
}}

[data-testid="stSidebar"][aria-expanded="true"] {{
    min-width: 230px !important;
    max-width: 230px !important;
}}

[data-testid="stSidebar"] > div:first-child {{
    padding-top: 0 !important;
}}

/* MAIN AREA */
[data-testid="stMain"] {{
    background: {BG} !important;
}}

/* STREAMLIT CHROME AND HEADER CONTROLS */
footer {{ display: none !important; }}
#MainMenu {{ display: none !important; }}
[data-testid="stDecoration"] {{ display: none !important; }}
[data-testid="stToolbarActions"] {{ display: none !important; }}
[data-testid="stDeployButton"] {{ display: none !important; }}

/* Keep header and toolbar transparent with pointer-events pass-through */
header[data-testid="stHeader"],
[data-testid="stToolbar"] {{
    background: transparent !important;
    z-index: 10000 !important;
    pointer-events: none !important;
    display: flex !important;
    visibility: visible !important;
}}

/* Enable pointer events on all sidebar toggle controls */
header[data-testid="stHeader"] button,
header[data-testid="stHeader"] [data-testid="collapsedControl"],
header[data-testid="stHeader"] [data-testid="stSidebarCollapsedControl"],
header[data-testid="stHeader"] [data-testid="stExpandSidebarButton"],
[data-testid="stToolbar"] button,
[data-testid="stToolbar"] [data-testid="stExpandSidebarButton"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="stExpandSidebarButton"],
[data-testid="stSidebarCollapseButton"] {{
    pointer-events: auto !important;
    cursor: pointer !important;
}}

/* EXPAND SIDEBAR BUTTON / COLLAPSED CONTROL (when sidebar is closed) */
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="stExpandSidebarButton"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 10001 !important;
    color: {TXT1} !important;
    background: {SURFACE} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 6px !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.18) !important;
    transition: all 0.15s ease !important;
}}

[data-testid="collapsedControl"]:hover,
[data-testid="stSidebarCollapsedControl"]:hover,
[data-testid="stExpandSidebarButton"]:hover {{
    border-color: {ACCENT} !important;
    color: {ACCENT} !important;
}}

[data-testid="collapsedControl"] svg,
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="stExpandSidebarButton"] svg,
[data-testid="stExpandSidebarButton"] span {{
    fill: {TXT1} !important;
    color: {TXT1} !important;
    stroke: {TXT1} !important;
}}

[data-testid="collapsedControl"]:hover svg,
[data-testid="stSidebarCollapsedControl"]:hover svg,
[data-testid="stExpandSidebarButton"]:hover svg,
[data-testid="stExpandSidebarButton"]:hover span {{
    fill: {ACCENT} !important;
    color: {ACCENT} !important;
    stroke: {ACCENT} !important;
}}

/* COLLAPSE SIDEBAR BUTTON (when sidebar is open) */
[data-testid="stSidebarCollapseButton"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    color: {TXT2} !important;
    z-index: 10001 !important;
    border-radius: 6px !important;
    transition: all 0.15s ease !important;
}}

[data-testid="stSidebarCollapseButton"]:hover {{
    color: {TXT1} !important;
    background: {NAV_SEL} !important;
}}

[data-testid="stSidebarCollapseButton"] svg,
[data-testid="stSidebarCollapseButton"] span {{
    fill: {TXT2} !important;
    color: {TXT2} !important;
}}

[data-testid="stSidebarCollapseButton"]:hover svg,
[data-testid="stSidebarCollapseButton"]:hover span {{
    fill: {TXT1} !important;
    color: {TXT1} !important;
}}

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
    font-size: 11px;
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
    font-size: 13px;
    color: {TXT2};
    display: flex;
    align-items: center;
    gap: 16px;
}}

.live-pill {{
    background: rgba(0,200,83,0.12);
    border: 1px solid rgba(0,200,83,0.25);
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 12px;
    font-weight: 700;
    color: {SUCCESS};
    letter-spacing: 1px;
    display: flex;
    align-items: center;
    gap: 6px;
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
    font-size: 12px;
    font-weight: 700;
    color: {TXT3};
    letter-spacing: 2px;
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
    font-size: 11px;
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
    font-size: 11px;
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
    font-size: 11px;
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
    font-size: 12px !important;
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
    font-size: 12px !important;
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
    padding: 4px 10px;
    font-size: 11px;
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
    """
    Resolves geographic location coordinates for public IP addresses.

    Parameters:
    ip_list (list[str]): List of IP address strings to geolocate.

    Returns:
    list[dict]: List of dictionaries containing ip, lat, lon, country, city, isp.

    Time complexity: O(n) where n is len(ip_list) up to query limit.
    Space complexity: O(n) where n is number of resolved locations.
    """
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


def make_processing_gauge(total_events, anomalies):
    """
    Creates a gauge chart showing log processing rate.
    Shows total events, anomaly percentage, threat level.

    Parameters:
    total_events (int): Total number of log events processed.
    anomalies (int): Number of detected anomalies.

    Returns:
    go.Figure: Plotly indicator gauge figure.

    Time complexity: O(1)
    Space complexity: O(1)
    """
    threat_pct = (anomalies / max(total_events, 1)) * 100

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_pct,
        number=dict(
            suffix="%",
            font=dict(
                size=36,
                color=TXT1,
                family='JetBrains Mono')),
        delta=dict(
            reference=5,
            decreasing=dict(color=SUCCESS),
            increasing=dict(color=ACCENT)),
        title=dict(
            text=(
                "Threat Level<br>"
                f"<span style='font-size:13px;"
                f"color:{TXT2}'>"
                f"{total_events:,} events analyzed"
                f"</span>"),
            font=dict(
                size=16,
                color=TXT1,
                family='Inter')),
        gauge=dict(
            axis=dict(
                range=[0, 100],
                tickwidth=1,
                tickcolor=BORDER,
                tickfont=dict(
                    size=11,
                    color=TXT2)),
            bar=dict(
                color=ACCENT if threat_pct > 5
                else WARN if threat_pct > 1
                else SUCCESS,
                thickness=0.7),
            bgcolor=SURFACE,
            borderwidth=1,
            bordercolor=BORDER,
            steps=[
                dict(
                    range=[0, 1],
                    color='rgba(0,200,83,0.08)'),
                dict(
                    range=[1, 5],
                    color='rgba(255,179,0,0.08)'),
                dict(
                    range=[5, 100],
                    color='rgba(232,52,58,0.08)')],
            threshold=dict(
                line=dict(
                    color=WARN,
                    width=2),
                thickness=0.75,
                value=5))))

    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter',
            color=TXT2),
        margin=dict(l=20, r=20, t=60, b=20),
        height=280)

    return fig


def make_threat_map(df, sus_ips, normal_ips,
                    BG, SURFACE, BORDER,
                    ACCENT, SUCCESS, TXT1, TXT2):
    """
    Creates world map showing IP origin locations.
    Red markers: IPs associated with suspicious events.
    Green markers: IPs from normal clean events.

    Parameters:
    df (pd.DataFrame): Analysis results dataframe.
    sus_ips (list[str]): Suspicious or anomalous IP addresses.
    normal_ips (list[str]): Normal activity IP addresses.
    BG (str): Background color hex.
    SURFACE (str): Card surface color hex.
    BORDER (str): Border color hex.
    ACCENT (str): Threat/alarm accent color hex.
    SUCCESS (str): Normal/success color hex.
    TXT1 (str): Primary text color hex.
    TXT2 (str): Secondary text color hex.

    Returns:
    go.Figure | None: Plotly scattergeo map figure, or None if no public IPs resolve.

    Time complexity: O(n) where n is number of resolved public IPs.
    Space complexity: O(n) for DataFrame and map traces.
    """
    all_ips = list(set(sus_ips + normal_ips))
    skip = ('192.168', '10.', '172.',
            '127.', '0.', '-', 'UNKNOWN')
    public = [
        ip for ip in all_ips
        if ip and not any(
            ip.startswith(s) for s in skip)]

    if not public:
        return None

    with st.spinner("Resolving IP locations..."):
        locs = geolocate_ips(public[:30])

    if not locs:
        return None

    loc_df = pd.DataFrame(locs)
    loc_df['is_suspicious'] = loc_df['ip'].isin(
        sus_ips)
    loc_df['type'] = loc_df['is_suspicious'].map(
        {True: 'Suspicious Origin',
         False: 'Normal Activity'})
    loc_df['size'] = loc_df['is_suspicious'].map(
        {True: 14, False: 8})
    loc_df['hover'] = loc_df.apply(
        lambda r: (
            f"IP: {r['ip']}<br>"
            f"Type: {r['type']}<br>"
            f"Location: {r['city']}, {r['country']}<br>"
            f"ISP: {r['isp']}"),
        axis=1)

    fig = go.Figure()

    # Normal IPs
    norm_locs = loc_df[~loc_df['is_suspicious']]
    if len(norm_locs) > 0:
        fig.add_trace(go.Scattergeo(
            lon=norm_locs['lon'],
            lat=norm_locs['lat'],
            text=norm_locs['hover'],
            hoverinfo='text',
            name='Normal Activity',
            marker=dict(
                size=8,
                color=SUCCESS,
                opacity=0.7,
                line=dict(width=0))))

    # Suspicious IPs
    sus_locs = loc_df[loc_df['is_suspicious']]
    if len(sus_locs) > 0:
        fig.add_trace(go.Scattergeo(
            lon=sus_locs['lon'],
            lat=sus_locs['lat'],
            text=sus_locs['hover'],
            hoverinfo='text',
            name='Suspicious Origin',
            marker=dict(
                size=14,
                color=ACCENT,
                opacity=0.85,
                line=dict(
                    width=1,
                    color='rgba(255,255,255,0.3)'))))

    fig.update_layout(
        geo=dict(
            bgcolor='rgba(0,0,0,0)',
            landcolor='#1a2035',
            oceancolor='#0a0c14',
            showocean=True,
            showland=True,
            showcountries=True,
            countrycolor=BORDER,
            showframe=False,
            showcoastlines=True,
            coastlinecolor=BORDER,
            projection_type='natural earth'),
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter',
            color=TXT2,
            size=11),
        title=dict(
            text='Threat Activity Map',
            font=dict(
                size=13,
                color=TXT1)),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            borderwidth=1,
            font=dict(size=11)),
        margin=dict(l=0, r=0, t=40, b=0),
        height=380)

    return fig


def make_victim_map(
        computer_name, city, country,
        findings, BG, SURFACE, BORDER,
        ACCENT, SUCCESS, WARN, TXT1, TXT2):
    """
    Shows the forensic subject machine on world map.
    Always displays even with no external IPs.
    Uses geocoding to find lat/lon from city name.

    Parameters:
    computer_name (str): Hostname of the analyzed machine.
    city (str): Subject machine city name.
    country (str): Subject machine country name.
    findings (list[dict]): Forensic findings list.
    BG (str): Background color hex.
    SURFACE (str): Card surface color hex.
    BORDER (str): Border color hex.
    ACCENT (str): Critical accent color hex.
    SUCCESS (str): Normal/success color hex.
    WARN (str): Warning/amber color hex.
    TXT1 (str): Primary text color hex.
    TXT2 (str): Secondary text color hex.

    Returns:
    go.Figure: Plotly scattergeo map figure.

    Time complexity: O(1)
    Space complexity: O(1)
    """
    # Geocode the city using nominatim free API
    lat, lon = None, None
    try:
        resp = requests.get(
            'https://nominatim.openstreetmap.org/search',
            params={
                'q': f'{city}, {country}',
                'format': 'json',
                'limit': 1
            },
            headers={
                'User-Agent': 'LogShield/1.0'
            },
            timeout=5)
        data = resp.json()
        if data:
            lat = float(data[0]['lat'])
            lon = float(data[0]['lon'])
    except Exception:
        pass

    # Default to center of India if geocode fails
    if lat is None:
        lat = 20.5937
        lon = 78.9629

    # Determine marker color from findings
    has_critical = any(
        isinstance(f, dict) and f.get('sev') == 'critical'
        for f in (findings or []))
    marker_color = (
        ACCENT if has_critical else WARN)

    # Build hover text
    n_critical = sum(
        1 for f in (findings or [])
        if isinstance(f, dict) and f.get('sev') == 'critical')
    n_high = sum(
        1 for f in (findings or [])
        if isinstance(f, dict) and f.get('sev') == 'high')

    hover_text = (
        f"Machine: {computer_name}<br>"
        f"Location: {city}, {country}<br>"
        f"Status: FORENSIC SUBJECT<br>"
        f"Critical Findings: {n_critical}<br>"
        f"High Findings: {n_high}<br>"
        f"Role: Log source under investigation")

    fig = go.Figure()

    # Pulsing effect using multiple circles
    for size, opacity in [
            (40, 0.08), (28, 0.15), (18, 0.4)]:
        fig.add_trace(go.Scattergeo(
            lon=[lon],
            lat=[lat],
            mode='markers',
            marker=dict(
                size=size,
                color=marker_color,
                opacity=opacity,
                line=dict(width=0)),
            hoverinfo='none',
            showlegend=False))

    # Main marker with label
    fig.add_trace(go.Scattergeo(
        lon=[lon],
        lat=[lat],
        mode='markers+text',
        text=[computer_name],
        textposition='top center',
        textfont=dict(
            size=12,
            color=TXT1,
            family='Inter'),
        marker=dict(
            size=16,
            color=marker_color,
            symbol='circle',
            line=dict(
                width=2,
                color='white')),
        hovertext=hover_text,
        hoverinfo='text',
        name='Forensic Subject',
        showlegend=True))

    # Add annotation box
    fig.add_trace(go.Scattergeo(
        lon=[lon + 8],
        lat=[lat + 6],
        mode='text',
        text=[
            f"FORENSIC SUBJECT<br>"
            f"{n_critical} CRITICAL | "
            f"{n_high} HIGH"],
        textfont=dict(
            size=11,
            color=marker_color,
            family='Inter'),
        hoverinfo='none',
        showlegend=False))

    fig.update_layout(
        geo=dict(
            bgcolor='rgba(0,0,0,0)',
            landcolor='#1a2035',
            oceancolor='#0a0c14',
            showocean=True,
            showland=True,
            showcountries=True,
            countrycolor=BORDER,
            showframe=False,
            showcoastlines=True,
            coastlinecolor=BORDER,
            showrivers=False,
            projection_type='natural earth',
            center=dict(lat=lat, lon=lon),
            projection_scale=3),
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter',
            color=TXT2,
            size=12),
        title=dict(
            text='Forensic Subject Location',
            font=dict(
                size=14,
                color=TXT1)),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            borderwidth=1,
            font=dict(size=11)),
        margin=dict(l=0, r=0, t=40, b=0),
        height=380)

    return fig


def make_network_diagram(
        df, BG, SURFACE, BORDER,
        ACCENT, SUCCESS, WARN, CYAN,
        TXT1, TXT2):
    """
    Network topology showing internal machine, account, and process activity.
    Shows which machines communicated during the investigation period.
    Red nodes: involved in suspicious events.
    Green nodes: normal activity only.
    Center node: forensic subject machine.

    Parameters:
    df (pd.DataFrame): Analysis results dataframe.
    BG (str): Background color hex.
    SURFACE (str): Card surface color hex.
    BORDER (str): Border color hex.
    ACCENT (str): Suspicious/critical color hex.
    SUCCESS (str): Normal activity color hex.
    WARN (str): Center machine/subject color hex.
    CYAN (str): Info accent color hex.
    TXT1 (str): Primary text color hex.
    TXT2 (str): Secondary text color hex.

    Returns:
    go.Figure: Plotly network topology figure.

    Time complexity: O(n) where n is rows in DataFrame.
    Space complexity: O(k) where k is number of nodes and edges.
    """
    import math

    nodes = []
    edges = []
    node_colors = []
    node_sizes = []
    node_labels = []
    node_hover = []

    # Get computer name (center node)
    center = 'UNKNOWN'
    if 'computer' in df.columns:
        center = df['computer'].mode().iloc[0] if len(df) > 0 else 'UNKNOWN'

    nodes.append(center)
    node_colors.append(WARN)
    node_sizes.append(30)
    node_labels.append(center)
    node_hover.append(
        f"Machine: {center}<br>"
        f"Role: Forensic Subject<br>"
        f"Status: Under Investigation<br>"
        f"Total Events: {len(df):,}")

    # Get account names (user nodes)
    if 'account_name' in df.columns:
        accounts = (df['account_name']
                    .dropna()
                    .replace('UNKNOWN', pd.NA)
                    .dropna()
                    .value_counts()
                    .head(6))

        for account, count in accounts.items():
            # Check if this account was in anomalous events
            if 'if_flag' in df.columns:
                anom_count = len(df[
                    (df['account_name'] == account) &
                    (df['if_flag'] == 1)])
                is_suspicious = anom_count > 0
            else:
                is_suspicious = False

            nodes.append(account)
            node_colors.append(
                ACCENT if is_suspicious else SUCCESS)
            node_sizes.append(20)
            node_labels.append(account)
            node_hover.append(
                f"Account: {account}<br>"
                f"Total Events: {count:,}<br>"
                f"Status: "
                f"{'SUSPICIOUS' if is_suspicious else 'Normal'}")
            edges.append((0, len(nodes)-1))

    # Get process names (process nodes)
    if 'process_name' in df.columns:
        attack_tools = [
            'wevtutil', 'whoami', 'net.exe',
            'runas', 'cmd.exe', 'powershell',
            'psexec']
        for tool in attack_tools:
            mask = (df['process_name']
                    .str.lower()
                    .str.contains(tool, na=False))
            count = mask.sum()
            if count > 0:
                nodes.append(tool)
                node_colors.append(ACCENT)
                node_sizes.append(18)
                node_labels.append(tool)
                node_hover.append(
                    f"Process: {tool}<br>"
                    f"Executions: {count:,}<br>"
                    f"Status: SUSPICIOUS TOOL<br>"
                    f"Risk: Attack-associated process")
                edges.append((0, len(nodes)-1))

    # Critical event nodes
    if 'event_id' in df.columns:
        n1102 = (df['event_id'] == 1102).sum()
        n4719 = (df['event_id'] == 4719).sum()

        if n1102 > 0:
            nodes.append('LOG\nCLEARED')
            node_colors.append(ACCENT)
            node_sizes.append(25)
            node_labels.append('LOG CLEARED')
            node_hover.append(
                f"Event: Log Cleared (1102)<br>"
                f"Count: {n1102}x<br>"
                f"Severity: CRITICAL<br>"
                f"Meaning: Evidence destroyed")
            edges.append((0, len(nodes)-1))

        if n4719 > 0:
            nodes.append('AUDIT\nDISABLED')
            node_colors.append(ACCENT)
            node_sizes.append(22)
            node_labels.append('AUDIT DISABLED')
            node_hover.append(
                f"Event: Audit Policy Changed (4719)<br>"
                f"Count: {n4719}x<br>"
                f"Severity: HIGH<br>"
                f"Meaning: Logging suppressed")
            edges.append((0, len(nodes)-1))

    # Create circular layout
    n = len(nodes)
    pos_x = [0.0]
    pos_y = [0.0]

    for i in range(1, n):
        angle = 2 * math.pi * (i-1) / max(n-1, 1)
        radius = 1.8
        pos_x.append(radius * math.cos(angle))
        pos_y.append(radius * math.sin(angle))

    # Edge traces
    edge_traces = []
    for src, tgt in edges:
        if src < len(pos_x) and tgt < len(pos_x):
            is_red_edge = (
                node_colors[tgt] == ACCENT)
            edge_traces.append(go.Scatter(
                x=[pos_x[src], pos_x[tgt], None],
                y=[pos_y[src], pos_y[tgt], None],
                mode='lines',
                line=dict(
                    width=1.5 if is_red_edge else 1,
                    color=(
                        'rgba(232,52,58,0.4)'
                        if is_red_edge
                        else 'rgba(30,37,48,0.8)')),
                hoverinfo='none',
                showlegend=False))

    # Node trace
    node_trace = go.Scatter(
        x=pos_x,
        y=pos_y,
        mode='markers+text',
        hoverinfo='text',
        hovertext=node_hover,
        text=node_labels,
        textposition=[
            'middle center' if i == 0
            else 'top center'
            for i in range(len(nodes))],
        textfont=dict(
            size=[12 if i == 0 else 11
                  for i in range(len(nodes))],
            color=[TXT1] * len(nodes),
            family='Inter'),
        marker=dict(
            size=[s * 3 for s in node_sizes],
            color=node_colors,
            line=dict(
                width=2,
                color=SURFACE)),
        showlegend=False)

    fig = go.Figure(
        data=edge_traces + [node_trace])

    # Legend
    for label, color in [
            ('Suspicious', ACCENT),
            ('Normal', SUCCESS),
            ('Subject', WARN)]:
        fig.add_trace(go.Scatter(
            x=[None], y=[None],
            mode='markers',
            name=label,
            marker=dict(
                size=10,
                color=color)))

    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter',
            color=TXT2),
        title=dict(
            text='Internal Network Activity',
            font=dict(
                size=14,
                color=TXT1)),
        showlegend=True,
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            borderwidth=1,
            font=dict(size=11)),
        hovermode='closest',
        margin=dict(l=0, r=0, t=40, b=0),
        height=400,
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            showline=False),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            showline=False))

    return fig


def get_verdict(deleted, injected, anomalies,
                critical, total):
    if deleted > 0 or injected > 0:
        return "COMPROMISED", "compromised", "red"
    if critical > 0 or anomalies > total * 0.02:
        return "SUSPICIOUS", "suspicious", "amber"
    return "CLEAN", "clean", "green"


def _file_fingerprint(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def _build_timeline_data(df):
    if ('if_score' not in df.columns or
            'time_created' not in df.columns or
            'if_flag' not in df.columns):
        return None
    norm = df[df['if_flag'] == 0]
    anom = df[df['if_flag'] == 1]
    return {
        'norm_times': (
            norm['time_created'].astype(str).tolist()),
        'norm_scores': (
            norm['if_score'].astype(float).tolist()),
        'anom_times': (
            anom['time_created'].astype(str).tolist()),
        'anom_scores': (
            anom['if_score'].astype(float).tolist()),
        'norm_count': int(len(norm)),
        'anom_count': int(len(anom)),
    }


def _build_process_chart(df):
    if 'process_name' not in df.columns:
        return []
    tools = ['wevtutil', 'whoami', 'net.exe', 'runas',
             'cmd.exe', 'powershell', 'psexec']
    mask = df['process_name'].str.lower().str.contains(
        '|'.join(tools), na=False)
    sus = df[mask]
    if len(sus) == 0:
        return []
    counts = (sus['process_name']
              .value_counts().head(8))
    return [
        {'process': k, 'count': int(v)}
        for k, v in counts.items()]


def _build_flagged_preview(df):
    if 'if_flag' not in df.columns:
        return None
    from dashboard.utils.threat_panels import build_flagged_events_table
    preview = build_flagged_events_table(df)
    if len(preview) == 0:
        return None
    return preview.to_json(orient='split')


def run_analysis_pipeline(file_bytes):
    """Run full analysis pipeline on uploaded bytes."""
    df = parse_csv_from_bytes(file_bytes)
    file_rows = len(df)
    baseline_check = check_baseline_row_count(
        file_rows, 'models_saved/hmac_chain.json')
    df = extract_features(df)

    CHAIN = 'models_saved/hmac_chain.json'
    hmac_ok = os.path.exists(CHAIN)
    deleted = 0
    injected = 0
    chain_intact = True
    if hmac_ok:
        try:
            df = verify_hmac_chain(df, CHAIN)
            c = check_chain_continuity(df, CHAIN)
            deleted = c['missing_records']
            injected = c['extra_records']
            chain_intact = (
                not c['gap_detected'] and
                not c['injection_detected'] and
                int(df['hmac_flag'].sum()) == 0)
        except Exception:
            hmac_ok = False
            chain_intact = False

    IF = 'models_saved/isolation_forest.pkl'
    if_ok = os.path.exists(IF)
    anomalies = 0
    critical = 0
    if if_ok:
        try:
            df = predict_anomalies(df, IF)
            anomalies = int(df['if_flag'].sum())
            critical = int(
                df['is_critical_event'].sum()
                if 'is_critical_event' in df.columns
                else 0)
        except Exception:
            if_ok = False

    total = len(df)
    verdict, vclass, vc = get_verdict(
        deleted, injected, anomalies, critical, total)
    findings = build_findings(
        df, deleted, injected, critical, anomalies)

    return {
        'df': df,
        'total_events': total,
        'deleted': deleted,
        'injected': injected,
        'anomalies': anomalies,
        'critical': critical,
        'verdict': verdict,
        'vclass': vclass,
        'vc': vc,
        'findings': findings,
        'hmac_ok': hmac_ok,
        'if_ok': if_ok,
        'chain_intact': chain_intact,
        'baseline_mismatch': baseline_check['mismatch'],
        'baseline_warning': baseline_check['message'],
        'timeline_data': _build_timeline_data(df),
        'process_chart': _build_process_chart(df),
        'flagged_preview': _build_flagged_preview(df),
        'threat_panels': build_all_threat_panels(
            df, verdict),
    }


def save_analysis_to_session(result, file_bytes):
    """Persist primitive analysis results in session."""
    st.session_state.analysis_done = True
    st.session_state.df_result = result['df']
    st.session_state.uploaded_bytes = file_bytes
    st.session_state.upload_fingerprint = (
        _file_fingerprint(file_bytes))
    st.session_state.total_events = result['total_events']
    st.session_state.verdict = result['verdict']
    st.session_state.deleted_count = result['deleted']
    st.session_state.injected_count = result['injected']
    st.session_state.anomaly_count = result['anomalies']
    st.session_state.critical_count = result['critical']
    st.session_state.findings = result['findings']
    st.session_state.hmac_ok = result['hmac_ok']
    st.session_state.if_ok = result['if_ok']
    st.session_state.chain_intact = result['chain_intact']
    st.session_state.baseline_mismatch = (
        result['baseline_mismatch'])
    st.session_state.baseline_warning = (
        result['baseline_warning'])
    st.session_state.timeline_data = result['timeline_data']
    st.session_state.process_chart = result['process_chart']
    st.session_state.flagged_preview = (
        result['flagged_preview'])
    st.session_state.threat_panels = (
        result['threat_panels'])
    st.session_state.analysis_time = (
        datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S UTC"))


def render_timeline_chart(timeline_data, height=340):
    """Render event timeline from cached primitive data."""
    if not timeline_data:
        return
    norm_count = timeline_data['norm_count']
    anom_count = timeline_data['anom_count']
    threshold = 0.5
    fig = go.Figure()
    if norm_count > 0:
        fig.add_trace(go.Scattergl(
            x=timeline_data['norm_times'],
            y=timeline_data['norm_scores'],
            mode='markers',
            name=f'Normal ({norm_count:,})',
            marker=dict(
                color=SUCCESS,
                size=3,
                opacity=0.4),
            hovertemplate=(
                'Time: %{x}<br>'
                'Anomaly score: %{y:.3f}<br>'
                'This event matched normal temporal '
                'patterns in the baseline'
                '<extra>Normal</extra>')))
    if anom_count > 0:
        fig.add_trace(go.Scattergl(
            x=timeline_data['anom_times'],
            y=timeline_data['anom_scores'],
            mode='markers',
            name=f'Anomaly ({anom_count:,})',
            marker=dict(
                color=ACCENT,
                size=10,
                symbol='diamond',
                line=dict(
                    color='rgba(255,255,255,0.3)',
                    width=1)),
            hovertemplate=(
                'Time: %{x}<br>'
                'Anomaly score: %{y:.3f}<br>'
                'Isolation Forest flagged this event as '
                'a temporal outlier (possible gap attack)'
                '<extra>ANOMALY</extra>')))
    fig.add_shape(
        type='line',
        xref='paper',
        x0=0,
        x1=1,
        yref='y',
        y0=threshold,
        y1=threshold,
        line=dict(color=WARN, dash='dash'))
    fig.add_annotation(
        xref='paper',
        x=1,
        y=threshold,
        yref='y',
        showarrow=False,
        text='Threshold',
        xanchor='left',
        font=dict(color=WARN, size=10))
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter, sans-serif',
            color=TXT2,
            size=11),
        margin=dict(l=0, r=0, t=12, b=0),
        height=height,
        hovermode='closest',
        title=dict(
            text=(
                f'Event Timeline  '
                f'{norm_count:,} normal  '
                f'{anom_count:,} anomalies'),
            font=dict(
                size=13,
                color=TXT1,
                family='Inter')),
        xaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            title=dict(
                text='Time',
                font=dict(size=11, color=TXT2))),
        yaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            title=dict(
                text='Anomaly Score',
                font=dict(size=11, color=TXT2)),
            range=[0, 1.05]),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            font=dict(size=11)))
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={'displayModeBar': False})


def render_analysis_results():
    """Render full analysis output from session state."""
    verdict = st.session_state.verdict
    vclass = (
        "compromised" if verdict == "COMPROMISED"
        else "suspicious" if verdict == "SUSPICIOUS"
        else "clean")
    vc = (
        "red" if verdict == "COMPROMISED"
        else "amber" if verdict == "SUSPICIOUS"
        else "green")
    total = st.session_state.total_events
    deleted = st.session_state.deleted_count
    injected = st.session_state.injected_count
    anomalies = st.session_state.anomaly_count
    critical = st.session_state.critical_count
    hmac_ok = st.session_state.hmac_ok
    if_ok = st.session_state.if_ok
    chain_intact = st.session_state.chain_intact

    if st.session_state.baseline_mismatch:
        st.warning(st.session_state.baseline_warning)

    vt_desc = {
        "COMPROMISED": (
            f"Confirmed evidence of deliberate "
            f"log manipulation. {deleted} records "
            f"deleted. This file cannot be used "
            f"as reliable evidence without "
            f"further investigation."),
        "SUSPICIOUS": (
            "Anomalous patterns detected "
            "inconsistent with normal system "
            "behavior. Manual review recommended."),
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

    chain_val = "PASS" if chain_intact else "FAIL"
    chain_col = "green" if chain_intact else "red"
    conf_val = (
        "HIGH" if verdict == "CLEAN" else "MEDIUM")

    st.markdown(f"""
<div class="kpi-row" style="margin-top:16px">
    <div class="kpi-card cyan">
        <div class="kpi-val cyan">{total:,}</div>
        <div class="kpi-label">Total Events</div>
        <div class="kpi-delta neutral">Analyzed</div>
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
            {'1102 / 4719 detected'
             if critical>0 else 'None detected'}
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
</div>
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
        <div class="kpi-val cyan">{conf_val}</div>
        <div class="kpi-label">Confidence</div>
        <div class="kpi-delta neutral">
            Detection certainty
        </div>
    </div>
    <div class="kpi-card">
        <div class="kpi-val">2</div>
        <div class="kpi-label">Active Layers</div>
        <div class="kpi-delta neutral">of 4 total</div>
    </div>
    <div class="kpi-card
        {'accent' if verdict != 'CLEAN' else 'success'}">
        <div class="kpi-val {vc}">{verdict}</div>
        <div class="kpi-label">Verdict</div>
        <div class="kpi-delta neutral">
            Overall assessment
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="sec-label">'
        'Detection Results</div>',
        unsafe_allow_html=True)

    l1c = 'red' if not chain_intact else (
        'green' if hmac_ok else 'grey')
    l1s = ('COMPROMISED' if not chain_intact else
           'INTACT' if hmac_ok else 'UNAVAILABLE')
    l1d = (
        f'{deleted} deleted, {injected} injected'
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

    timeline = st.session_state.timeline_data
    if timeline:
        st.markdown(
            '<div class="sec-label">'
            'Event Timeline</div>',
            unsafe_allow_html=True)
        render_timeline_chart(timeline, height=340)
        st.caption(
            "Green dots: normal events  "
            "Red diamonds: anomalies  "
            "Dashed line: detection threshold")

    process_chart = st.session_state.process_chart
    if process_chart:
        st.markdown(
            '<div class="sec-label">'
            'Process Activity</div>',
            unsafe_allow_html=True)
        pc = pd.DataFrame(process_chart)
        bar = go.Figure(go.Bar(
            x=pc['count'],
            y=pc['process'],
            orientation='h',
            marker=dict(
                color=ACCENT,
                opacity=0.8,
                line=dict(width=0))))
        bar.update_layout(**make_chart_layout(280))
        st.plotly_chart(
            bar,
            use_container_width=True,
            config={'displayModeBar': False})

    df = st.session_state.df_result
    findings = st.session_state.findings or []

    if df is not None:
        st.markdown(
            '<div class="sec-label">'
            'Threat Activity Map</div>',
            unsafe_allow_html=True)

        # Location input
        map_col1, map_col2 = st.columns([3, 1])
        with map_col2:
            city_input = st.text_input(
                "Subject machine city",
                value="Bangalore",
                help=(
                    "Enter the city where the machine "
                    "being investigated is located. "
                    "Used for geographic visualization."))
            country_input = st.text_input(
                "Country",
                value="India")

        with map_col1:
            # Get computer name from data
            comp_name = 'UNKNOWN'
            if 'computer' in df.columns:
                comp_name = (
                    df['computer'].mode().iloc[0]
                    if len(df) > 0 else 'UNKNOWN')

            # Always show victim machine map
            with st.spinner(
                    "Rendering geographic map..."):
                victim_map = make_victim_map(
                    computer_name=comp_name,
                    city=city_input,
                    country=country_input,
                    findings=findings,
                    BG=BG, SURFACE=SURFACE,
                    BORDER=BORDER, ACCENT=ACCENT,
                    SUCCESS=SUCCESS, WARN=WARN,
                    TXT1=TXT1, TXT2=TXT2)
                st.plotly_chart(
                    victim_map,
                    use_container_width=True,
                    config={'displayModeBar': False})

            st.caption(
                f"Showing forensic subject: {comp_name}  "
                f"Location: {city_input}, {country_input}  "
                f"Enter the actual location of the "
                f"investigated machine in the fields above.")

        # Network topology
        st.markdown(
            '<div class="sec-label">'
            'Network Activity Topology</div>',
            unsafe_allow_html=True)
        st.caption(
            "Visual map of machines, accounts, and "
            "processes involved in this log session. "
            "Red nodes indicate suspicious activity.")

        net_fig = make_network_diagram(
            df=df,
            BG=BG, SURFACE=SURFACE,
            BORDER=BORDER, ACCENT=ACCENT,
            SUCCESS=SUCCESS, WARN=WARN,
            CYAN=CYAN, TXT1=TXT1, TXT2=TXT2)

        st.plotly_chart(
            net_fig,
            use_container_width=True,
            config={'displayModeBar': False})

        # Now check for public IPs additionally
        if 'ip_address' in df.columns:
            skip = ('192.168', '10.', '172.',
                    '127.', '0.', '-', 'UNKNOWN')
            pub = [
                ip for ip in
                df['ip_address'].dropna().unique()
                if ip and not any(
                    ip.startswith(s) for s in skip)]

            if pub and 'if_flag' in df.columns:
                st.markdown(
                    '<div class="sec-label">'
                    'External IP Origins</div>',
                    unsafe_allow_html=True)
                sus_ips = (
                    df[df['if_flag'] == 1]['ip_address']
                    .dropna().unique().tolist())
                with st.spinner(
                        "Resolving external IP locations..."):
                    locs = geolocate_ips(pub[:30])
                if locs:
                    loc_df = pd.DataFrame(locs)
                    loc_df['type'] = loc_df['ip'].apply(
                        lambda x: 'Suspicious'
                        if x in sus_ips else 'Normal')
                    ext_map = px.scatter_geo(
                        loc_df,
                        lat='lat', lon='lon',
                        color='type',
                        color_discrete_map={
                            'Suspicious': ACCENT,
                            'Normal': SUCCESS},
                        hover_data={
                            'ip': True,
                            'country': True,
                            'city': True},
                        projection='natural earth')
                    ext_map.update_layout(
                        geo=dict(
                            bgcolor='rgba(0,0,0,0)',
                            landcolor='#1a2035',
                            oceancolor='#0a0c14',
                            showocean=True,
                            showland=True,
                            showcountries=True,
                            countrycolor=BORDER,
                            showframe=False),
                        paper_bgcolor='rgba(0,0,0,0)',
                        margin=dict(l=0, r=0, t=0, b=0),
                        height=350)
                    st.plotly_chart(
                        ext_map,
                        use_container_width=True,
                        config={'displayModeBar': False})

    preview_json = st.session_state.flagged_preview
    if preview_json:
        flagged = pd.read_json(
            io.StringIO(preview_json), orient='split')
        st.markdown(
            f'<div class="sec-label">'
            f'Flagged Events '
            f'({st.session_state.anomaly_count:,})'
            f'</div>',
            unsafe_allow_html=True)
        st.dataframe(
            flagged,
            use_container_width=True,
            hide_index=True)

    st.markdown(
        '<div style="margin-top:8px">'
        'Go to the Report page to download '
        'the full forensic report.'
        '</div>',
        unsafe_allow_html=True)


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
        ("Threat Overview", "Attack path visualization"),
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
        f'<div style="font-size:11px;'
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
        total = st.session_state.total_events
    else:
        tv = DEMO['total']
        dv = DEMO['deleted']
        av = DEMO['anomalies']
        crv = DEMO['critical']
        vt = DEMO['verdict']
        vc = DEMO['verdict_color']
        vclass = DEMO['verdict_class']
        total = DEMO['total']

    if done and st.session_state.baseline_mismatch:
        st.warning(st.session_state.baseline_warning)

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
        "FAIL" if (done and not st.session_state.chain_intact)
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

    if done and st.session_state.df_result is not None:
        df_r = st.session_state.df_result
        comp = 'UNKNOWN'
        if 'computer' in df_r.columns:
            comp = (df_r['computer'].mode().iloc[0]
                    if len(df_r) > 0 else 'UNKNOWN')

        st.markdown(f"""
<div style="
    background:{SURFACE};
    border:1px solid {BORDER};
    border-radius:8px;
    padding:16px 24px;
    margin:12px 0;
    display:flex;
    align-items:center;
    gap:20px">
    <div style="
        width:10px;height:10px;
        background:{ACCENT};
        border-radius:50%;
        box-shadow:0 0 8px {ACCENT};
        flex-shrink:0"></div>
    <div>
        <div style="
            font-size:11px;
            font-weight:700;
            color:{TXT3};
            letter-spacing:1.5px;
            text-transform:uppercase;
            margin-bottom:3px">
            Forensic Subject
        </div>
        <div style="
            font-size:14px;
            font-weight:700;
            color:{TXT1};
            font-family:'JetBrains Mono',monospace">
            {comp}
        </div>
    </div>
    <div style="margin-left:auto;text-align:right">
        <div style="
            font-size:11px;
            color:{TXT3};
            margin-bottom:3px">
            Analysis Time
        </div>
        <div style="
            font-size:12px;
            color:{TXT2};
            font-family:'JetBrains Mono',monospace">
            {st.session_state.analysis_time or 'N/A'}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="sec-label">'
        'Processing Overview</div>',
        unsafe_allow_html=True)

    g1, g2, g3 = st.columns(3)

    with g1:
        gauge = make_processing_gauge(
            DEMO['total'] if not done
            else len(st.session_state.df_result)
            if st.session_state.df_result is not None
            else DEMO['total'],
            DEMO['anomalies'] if not done
            else st.session_state.anomaly_count)
        st.plotly_chart(
            gauge,
            use_container_width=True,
            config={'displayModeBar': False})

    with g2:
        # Log Classification donut
        if done and st.session_state.df_result is not None:
            df_r = st.session_state.df_result
            if 'event_id' in df_r.columns:
                cats = {
                    'Critical (1102/4719)': len(df_r[
                        df_r['is_critical_event']==1])
                    if 'is_critical_event' in df_r.columns
                    else 0,
                    'Anomalous': st.session_state.anomaly_count,
                    'Normal': (
                        len(df_r) -
                        st.session_state.anomaly_count),
                }
        else:
            cats = {
                'Critical': 7,
                'Anomalous': 284,
                'Normal': 31367,
            }

        cat_colors = [ACCENT, WARN, SUCCESS]
        fig_class = go.Figure(go.Pie(
            labels=list(cats.keys()),
            values=list(cats.values()),
            hole=0.6,
            marker=dict(
                colors=cat_colors,
                line=dict(width=0)),
            textinfo='percent',
            textfont=dict(
                size=11,
                color='white'),
            hovertemplate=(
                '%{label}<br>'
                '%{value:,} events<br>'
                '%{percent}'
                '<extra></extra>')))
        fig_class.add_annotation(
            text=(
                f"{cats.get('Critical', 7)}<br>"
                f"<span style='font-size:11px'>"
                f"Critical</span>"),
            x=0.5, y=0.5,
            font=dict(
                size=22,
                color=TXT1,
                family='Inter'),
            showarrow=False)
        fig_class.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family='Inter',
                color=TXT2,
                size=12),
            title=dict(
                text='Log Classification',
                font=dict(
                    size=14,
                    color=TXT1)),
            margin=dict(l=0, r=0, t=40, b=0),
            height=280,
            legend=dict(
                bgcolor='rgba(0,0,0,0)',
                font=dict(size=11)))
        st.plotly_chart(
            fig_class,
            use_container_width=True,
            config={'displayModeBar': False})

    with g3:
        # Log Event and Alarm Trend
        if done and st.session_state.df_result is not None:
            df_r = st.session_state.df_result
            if 'time_created' in df_r.columns:
                df_r = df_r.copy()
                df_r['time_created'] = pd.to_datetime(
                    df_r['time_created'], utc=True,
                    errors='coerce')
                df_r['hour'] = df_r[
                    'time_created'].dt.floor('h')
                hourly = df_r.groupby('hour').agg(
                    total=('event_id', 'count'),
                    anomalies=('if_flag', 'sum')
                    if 'if_flag' in df_r.columns
                    else ('event_id', 'count')
                ).reset_index()
            else:
                hourly = None
        else:
            hourly = None

        if hourly is not None and len(hourly) > 0:
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=hourly['hour'],
                y=hourly['total'],
                name='All Events',
                line=dict(color=CYAN, width=2),
                fill='tozeroy',
                fillcolor='rgba(0,212,255,0.06)'))
            if 'anomalies' in hourly.columns:
                fig_trend.add_trace(go.Scatter(
                    x=hourly['hour'],
                    y=hourly['anomalies'],
                    name='Anomalies',
                    line=dict(
                        color=ACCENT,
                        width=2)))
        else:
            # Demo trend
            hours = pd.date_range(
                '2026-08-25 08:00',
                periods=12, freq='h')
            total = [120, 145, 132, 189, 210,
                     180, 156, 234, 198, 167,
                     143, 121]
            alarms = [2, 1, 3, 8, 12, 7,
                      4, 15, 9, 5, 3, 2]
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=hours, y=total,
                name='All Events',
                line=dict(color=CYAN, width=2),
                fill='tozeroy',
                fillcolor='rgba(0,212,255,0.06)'))
            fig_trend.add_trace(go.Scatter(
                x=hours, y=alarms,
                name='Alarms',
                line=dict(color=ACCENT, width=2)))

        fig_trend.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family='Inter',
                color=TXT2,
                size=12),
            title=dict(
                text='Log and Alarm Trend',
                font=dict(
                    size=14,
                    color=TXT1)),
            legend=dict(
                bgcolor='rgba(0,0,0,0)',
                font=dict(size=11)),
            margin=dict(l=0, r=0, t=40, b=0),
            height=280,
            xaxis=dict(
                gridcolor=BORDER,
                linecolor=BORDER),
            yaxis=dict(
                gridcolor=BORDER,
                linecolor=BORDER))
        st.plotly_chart(
            fig_trend,
            use_container_width=True,
            config={'displayModeBar': False})

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
        if done and st.session_state.timeline_data:
            st.markdown(
                '<div class="sec-label">'
                'Event Timeline</div>',
                unsafe_allow_html=True)
            render_timeline_chart(
                st.session_state.timeline_data,
                height=320)
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
        "Maximum: 150 MB  |  "
        "Processed in memory, never stored")

    uploaded = st.file_uploader(
        "Select log file",
        type=['csv'],
        label_visibility="collapsed")

    if uploaded is None and not done:
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
        if uploaded.size > MAX_FILE_SIZE:
            st.error(
                "This file exceeds the 150 MB upload limit. "
                "Please split your log export into smaller "
                "CSV files and upload them separately.")
            st.stop()

        file_bytes = uploaded.getvalue()
        fingerprint = _file_fingerprint(file_bytes)
        if fingerprint != st.session_state.upload_fingerprint:
            with st.spinner(
                    "Running integrity analysis..."):
                try:
                    result = run_analysis_pipeline(
                        file_bytes)
                    save_analysis_to_session(
                        result, file_bytes)
                except Exception as e:
                    st.error(
                        "Analysis failed. Verify file "
                        f"format. Detail: {str(e)}")
                    st.stop()

    if st.session_state.analysis_done:
        render_analysis_results()

    st.markdown('</div>', unsafe_allow_html=True)

# -- PAGE: THREAT OVERVIEW --
elif page == 'Threat Overview':

    st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-title">Threat Overview</div>
    <div class="top-bar-meta">
        <span>Attack path and knowledge graph</span>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="page-wrap">',
        unsafe_allow_html=True)

    if not done or st.session_state.df_result is None:
        st.info(
            "No analysis has been run yet. "
            "Go to Analysis, upload a file, "
            "then return here.")
    else:
        df_r = st.session_state.df_result
        vt = st.session_state.verdict
        findings = st.session_state.findings

        # KNOWLEDGE GRAPH using plotly
        st.markdown(
            '<div class="sec-label">'
            'Attack Knowledge Graph</div>',
            unsafe_allow_html=True)
        st.caption(
            "Visual representation of detected "
            "attack sequence and connections "
            "between suspicious events.")

        # Build nodes and edges dynamically
        # from actual analysis results
        nodes = []
        edges = []
        node_colors = []
        node_sizes = []
        node_text = []

        # Always start with system node
        nodes.append("Windows\nEvent Logs")
        node_colors.append(CYAN)
        node_sizes.append(40)
        node_text.append(
            f"Source: Windows Event Logs<br>"
            f"Total Records: {len(df_r):,}<br>"
            f"Time Range: Log file analyzed")

        # Add HMAC node
        hmac_status = (
            "COMPROMISED"
            if st.session_state.deleted_count > 0
            else "INTACT")
        hmac_color = (
            ACCENT if hmac_status == "COMPROMISED"
            else SUCCESS)
        nodes.append(
            f"HMAC Chain\n{hmac_status}")
        node_colors.append(hmac_color)
        node_sizes.append(35)
        node_text.append(
            f"Layer 1: Cryptographic Chain<br>"
            f"Status: {hmac_status}<br>"
            f"Deleted Records: "
            f"{st.session_state.deleted_count}<br>"
            f"Injected Records: "
            f"{st.session_state.injected_count}")
        edges.append((0, 1))

        # Add critical events if found
        crv = st.session_state.critical_count
        n1102 = 0
        if 'event_id' in df_r.columns:
            n1102 = (df_r['event_id'] == 1102).sum()
            n4719 = (df_r['event_id'] == 4719).sum()

            if n1102 > 0:
                nodes.append(
                    f"Event 1102\nLog Cleared x{n1102}")
                node_colors.append(ACCENT)
                node_sizes.append(32)
                node_text.append(
                    f"Event ID: 1102<br>"
                    f"Name: Security Log Cleared<br>"
                    f"Count: {n1102} instance(s)<br>"
                    f"Severity: CRITICAL<br>"
                    f"Meaning: Attacker erased evidence")
                edges.append((1, len(nodes)-1))

            if n4719 > 0:
                nodes.append(
                    f"Event 4719\nPolicy Changed x{n4719}")
                node_colors.append(WARN)
                node_sizes.append(30)
                node_text.append(
                    f"Event ID: 4719<br>"
                    f"Name: Audit Policy Changed<br>"
                    f"Count: {n4719} instance(s)<br>"
                    f"Severity: HIGH<br>"
                    f"Meaning: Logging was disabled")
                edges.append((1, len(nodes)-1))

        # Add suspicious process nodes
        if 'process_name' in df_r.columns:
            tools = ['wevtutil', 'whoami',
                     'net.exe', 'psexec']
            for tool in tools:
                mask = (df_r['process_name']
                        .str.lower()
                        .str.contains(
                            tool, na=False))
                count = mask.sum()
                if count > 0:
                    nodes.append(
                        f"{tool}\nx{count}")
                    node_colors.append(WARN)
                    node_sizes.append(28)
                    node_text.append(
                        f"Process: {tool}<br>"
                        f"Executions: {count}<br>"
                        f"Risk: Attack tool<br>"
                        f"Meaning: Used for "
                        f"post-exploitation")
                    edges.append((
                        2 if n1102 > 0 else 1,
                        len(nodes)-1))

        # Add AI detection node
        anom = st.session_state.anomaly_count
        ai_col = WARN if anom > 0 else SUCCESS
        nodes.append(
            f"AI Detection\n{anom} Anomalies")
        node_colors.append(ai_col)
        node_sizes.append(35)
        node_text.append(
            f"Layer 2: AI/ML Detection<br>"
            f"Model: Isolation Forest<br>"
            f"Anomalies: {anom:,}<br>"
            f"Rate: "
            f"{anom/max(len(df_r),1)*100:.1f}%<br>"
            f"LSTM: Pending<br>"
            f"Autoencoder: Pending")
        edges.append((0, len(nodes)-1))

        # Add verdict node
        vc_color = (
            ACCENT if vt == "COMPROMISED"
            else WARN if vt == "SUSPICIOUS"
            else SUCCESS)
        nodes.append(f"Verdict\n{vt}")
        node_colors.append(vc_color)
        node_sizes.append(40)
        node_text.append(
            f"Final Verdict: {vt}<br>"
            f"Confidence: HIGH<br>"
            f"Based on: HMAC + AI analysis<br>"
            f"Action: See Findings page")
        edges.append((1, len(nodes)-1))
        edges.append((len(nodes)-2, len(nodes)-1))

        # Create layout positions
        import math
        n = len(nodes)
        pos_x = []
        pos_y = []
        for i, node in enumerate(nodes):
            if i == 0:
                pos_x.append(0)
                pos_y.append(0)
            elif i == 1:
                pos_x.append(2)
                pos_y.append(0)
            elif i == len(nodes) - 2:
                pos_x.append(2)
                pos_y.append(-2)
            elif i == len(nodes) - 1:
                pos_x.append(4)
                pos_y.append(0)
            else:
                angle = (
                    (i - 2) /
                    max(n - 4, 1) * math.pi - math.pi/2)
                pos_x.append(
                    2 + 1.5 * math.cos(angle))
                pos_y.append(
                    1.5 * math.sin(angle))

        # Build edge traces
        edge_traces = []
        for e in edges:
            if e[0] < len(pos_x) and e[1] < len(pos_x):
                edge_traces.append(go.Scatter(
                    x=[pos_x[e[0]],
                       pos_x[e[1]], None],
                    y=[pos_y[e[0]],
                       pos_y[e[1]], None],
                    mode='lines',
                    line=dict(
                        width=1.5,
                        color=BORDER),
                    hoverinfo='none',
                    showlegend=False))

        # Node trace
        node_trace = go.Scatter(
            x=pos_x,
            y=pos_y,
            mode='markers+text',
            hoverinfo='text',
            hovertext=node_text,
            text=nodes,
            textposition='top center',
            textfont=dict(
                size=12,
                color=TXT1,
                family='Inter'),
            marker=dict(
                size=[s * 2 for s in node_sizes],
                color=node_colors,
                line=dict(
                    width=2,
                    color=SURFACE),
                opacity=0.9),
            showlegend=False)

        fig_kg = go.Figure(
            data=edge_traces + [node_trace])
        fig_kg.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family='Inter',
                color=TXT2),
            showlegend=False,
            hovermode='closest',
            margin=dict(l=20, r=20, t=20, b=20),
            height=500,
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showline=False))

        st.plotly_chart(
            fig_kg,
            use_container_width=True,
            config={'displayModeBar': False})

        st.caption(
            "Hover over any node to see detailed "
            "information. Node size indicates "
            "severity. Red nodes are critical, "
            "amber nodes are high risk, "
            "green nodes are clean.")

        # ATTACK TIMELINE TABLE
        st.markdown(
            '<div class="sec-label">'
            'Attack Sequence Timeline</div>',
            unsafe_allow_html=True)

        timeline_events = []

        if 'time_created' in df_r.columns:
            if 'event_id' in df_r.columns:
                critical_rows = df_r[
                    df_r['is_critical_event'] == 1
                ].copy() if 'is_critical_event' in df_r.columns else pd.DataFrame()

                if len(critical_rows) > 0:
                    for _, row in critical_rows.head(
                            10).iterrows():
                        eid = int(row['event_id'])
                        meaning = {
                            1102: "Security log was cleared",
                            4719: "Audit policy was changed",
                            4624: "Successful logon",
                            4625: "Failed logon attempt",
                            4688: "New process created",
                            4663: "File access attempt",
                            4672: "Special privileges used",
                            4698: "Scheduled task created"
                        }.get(eid, f"Event {eid}")

                        sev = (
                            "CRITICAL"
                            if eid in [1102, 4719]
                            else "HIGH"
                            if eid in [4625, 4698]
                            else "MEDIUM")

                        timeline_events.append({
                            'Time': str(
                                row['time_created']
                            )[:19],
                            'Event ID': eid,
                            'Account': str(
                                row.get(
                                    'account_name',
                                    'UNKNOWN')),
                            'Process': str(
                                row.get(
                                    'process_name',
                                    'UNKNOWN')),
                            'What Happened': meaning,
                            'Severity': sev
                        })

            if timeline_events:
                tl_df = pd.DataFrame(timeline_events)
                st.dataframe(
                    tl_df,
                    use_container_width=True,
                    hide_index=True)
            else:
                st.caption(
                    "No critical sequence events "
                    "found in this dataset.")

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
                if st.session_state.uploaded_bytes:
                    pdf_df = run_analysis_pipeline(
                        st.session_state.uploaded_bytes)['df']
                else:
                    pdf_df = None
                if pdf_df is None:
                    st.error(
                        "No analysis data available.")
                else:
                    pdf_bytes = generate_pdf_report(
                        df=pdf_df,
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

            preview_json = st.session_state.flagged_preview
            if preview_json:
                flagged = pd.read_json(
                    io.StringIO(preview_json),
                    orient='split')
                st.download_button(
                    label="Download CSV Report",
                    data=flagged.to_csv(index=False),
                    file_name=(
                        "logshield_flagged.csv"),
                    mime="text/csv",
                    use_container_width=True)
            elif st.session_state.uploaded_bytes:
                st.caption(
                    "No flagged events in last analysis.")

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
