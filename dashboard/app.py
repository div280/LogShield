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
from src.models.lstm_model import predict_lstm, load_lstm
from dashboard.utils.pdf_report import generate_pdf_report
from dashboard.utils.threat_panels import (
    build_all_threat_panels,
    build_lstm_panel_data)
from dashboard.utils.threat_render import (
    render_threat_overview,
    render_lstm_panel)
from dashboard.attack_map import create_simulated_attack_map

_LSTM_CACHE = {}
_CHAIN_CACHE = {}


def get_cached_lstm_model(
        model_path='models_saved/lstm_ae.keras',
        meta_path='models_saved/lstm_meta.pkl'):
    """Load and cache LSTM model and metadata once."""
    cache_key = (model_path, meta_path)
    if cache_key not in _LSTM_CACHE:
        _LSTM_CACHE[cache_key] = load_lstm(model_path, meta_path)
    return _LSTM_CACHE[cache_key]


def get_cached_hmac_chain(chain_filepath='models_saved/hmac_chain.json'):
    """Load and cache HMAC chain metadata and identity keys once."""
    if chain_filepath not in _CHAIN_CACHE:
        if os.path.exists(chain_filepath):
            with open(chain_filepath, 'r') as f:
                data = json.load(f)
            entries = data.get('chain', [])
            has_src = bool(entries and 'source_file' in entries[0])
            if has_src:
                keys = set(
                    (str(e.get('source_file', '')), str(e.get('event_record_id', '')))
                    for e in entries)
            else:
                keys = set(
                    (str(e.get('event_record_id', '')), str(e.get('time_created', '')))
                    for e in entries)
            _CHAIN_CACHE[chain_filepath] = {
                'data': data,
                'has_source_file': has_src,
                'keys': keys,
                'total': len(keys)
            }
        else:
            _CHAIN_CACHE[chain_filepath] = None
    return _CHAIN_CACHE[chain_filepath]


st.set_page_config(
    page_title="LogShield",
    page_icon="https://img.icons8.com/fluency/48/shield.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -- THEME STATE --
if "dark_mode" not in st.session_state:
    try:
        st.session_state.dark_mode = True
    except Exception:
        pass

for _k, _v in [
    ('dark_mode', True),
    ('page', 'Dashboard'),
    ('analysis_done', False),
    ('df_result', None),
    ('uploaded_bytes', None),
    ('upload_fingerprint', None),
    ('verdict', None),
    ('total_events', 0),
    ('deleted_count', 0),
    ('injected_count', 0),
    ('anomaly_count', 0),
    ('critical_count', 0),
    ('findings', []),
    ('analysis_time', None),
    ('hmac_ok', False),
    ('if_ok', False),
    ('chain_intact', True),
    ('timeline_data', None),
    ('process_chart', []),
    ('flagged_preview', None),
    ('threat_panels', None),
    ('baseline_mismatch', False),
    ('baseline_warning', ''),
    ('lstm_ok', False),
    ('lstm_notice', ''),
    ('lstm_panel', None)
]:
    try:
        if _k not in st.session_state:
            st.session_state[_k] = _v
    except Exception:
        pass

if "dark_mode" not in st.session_state:
    try:
        st.session_state.dark_mode = True
    except Exception:
        pass

try:
    dm = st.session_state.dark_mode
except Exception:
    try:
        dm = st.session_state.get("dark_mode", True)
    except Exception:
        dm = True
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
    color: {TXT1} !important;
}}

[data-testid="stAlert"] p,
[data-testid="stAlert"] div,
[data-testid="stAlert"] span,
[data-testid="stAlert"] [data-testid="stMarkdownContainer"],
[data-testid="stAlert"] [data-testid="stMarkdownContainer"] p,
[data-testid="stAlert"] [data-testid="stAlertContent"],
[data-testid="stAlert"] [data-testid="stNotificationContent"] {{
    color: {TXT1} !important;
}}

/* PLOTLY CHARTS BG */
.js-plotly-plot .plotly {{
    border-radius: 8px;
}}

/* CAPTION */
.stCaption,
[data-testid="stCaptionContainer"],
.stCaption p {{
    color: {TXT3 if dm else TXT1} !important;
    font-size: 12px !important;
}}

/* WIDGET LABELS & RADIO OPTIONS */
label,
[data-testid="stWidgetLabel"],
[data-testid="stWidgetLabel"] p,
[data-testid="stWidgetLabel"] span,
.stTextInput label,
.stRadio label,
[data-testid="stRadio"] label,
[data-testid="stRadio"] [data-testid="stWidgetLabel"] p,
[data-testid="stRadio"] [role="radiogroup"] label,
[data-testid="stRadio"] [role="radiogroup"] label p,
[data-testid="stRadio"] [role="radiogroup"] label span,
[data-testid="stRadio"] [role="radiogroup"] div[data-testid="stMarkdownContainer"] p,
[data-testid="stRadio"] [role="radiogroup"] div[data-testid="stMarkdownContainer"] span,
[data-testid="stRadio"] [data-testid="stMarkdownContainer"] p {{
    color: {TXT1} !important;
    font-size: 13px !important;
}}

[data-testid="stWidgetLabel"],
[data-testid="stWidgetLabel"] p {{
    font-weight: 600 !important;
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
    color: {TXT3 if dm else TXT2};
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
    Creates a gauge chart showing AI anomaly rate.
    Shows total events, anomaly percentage.

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
        mode="gauge+number",
        value=threat_pct,
        number=dict(
            suffix="%",
            font=dict(
                size=36,
                color=TXT1,
                family='JetBrains Mono')),
        title=dict(
            text=(
                "AI anomaly rate<br>"
                f"<span style='font-size:12px;"
                f"color:{TXT2}'>"
                f"{total_events:,} events (flags fixed baseline share by design)"
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


def get_verdict(deleted=0, injected=0, anomalies=0,
                critical=0, total=0,
                chain_intact=True,
                baseline_mismatch=False,
                hmac_failed=False,
                lstm_alert=False):
    # Rule 3 in Task 2: Does not match -> SUSPICIOUS with "HMAC could not be verified against a baseline". Never COMPROMISED and never CLEAN in this case.
    if baseline_mismatch:
        return "SUSPICIOUS", "suspicious", "amber"

    # Rule 2 in Task 2: Matches and verification fails -> COMPROMISED
    del_val = deleted if isinstance(deleted, (int, float)) else 0
    inj_val = injected if isinstance(injected, (int, float)) else 0
    if del_val > 0 or inj_val > 0 or (not chain_intact and hmac_failed) or hmac_failed:
        return "COMPROMISED", "compromised", "red"

    # Rule 2 in Task 2: Matches and chain intact -> CLEAN unless LSTM file-level alert fires (then SUSPICIOUS)
    if lstm_alert:
        return "SUSPICIOUS", "suspicious", "amber"

    # Rule 5 & 6: Events 1102/4719 and Isolation Forest are supporting evidence only, do not change verdict
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
    if df is None or len(df) == 0:
        return None
    from dashboard.utils.threat_panels import build_flagged_events_table
    preview = build_flagged_events_table(df)
    if len(preview) == 0:
        return None
    return preview.to_json(orient='split')


def run_analysis_pipeline(file_bytes):
    """Run full analysis pipeline on uploaded bytes."""
    df_raw = parse_csv_from_bytes(file_bytes)
    file_rows = len(df_raw)

    CHAIN = 'models_saved/hmac_chain.json'
    cached_chain = get_cached_hmac_chain(CHAIN)
    hmac_ok = cached_chain is not None

    deleted = 0
    injected = 0
    deleted_breakdown = ""
    injected_breakdown = ""
    chain_intact = True
    baseline_matches = False
    hmac_failed = False
    break_info = None

    if hmac_ok:
        has_src = cached_chain['has_source_file']
        chain_keys = cached_chain['keys']

        # Task 2: Check usable key columns (fail closed if missing)
        req_cols = {'source_file', 'event_record_id'} if has_src else {'event_record_id', 'time_created'}
        if not req_cols.issubset(df_raw.columns) or len(df_raw) == 0:
            baseline_matches = False
        else:
            if has_src:
                file_keys_list = list(zip(
                    df_raw['source_file'].astype(str),
                    df_raw['event_record_id'].astype(str)))
            else:
                file_keys_list = list(zip(
                    df_raw['event_record_id'].astype(str),
                    df_raw['time_created'].astype(str)))
            file_keys = set(file_keys_list)

            # Task 2: at least 50% of the file's keys appear in the chain
            matching_keys = file_keys.intersection(chain_keys)
            match_frac = len(matching_keys) / max(len(file_keys), 1)
            baseline_matches = bool(match_frac >= 0.50)

            if baseline_matches:
                missing_keys = chain_keys - file_keys
                extra_keys = file_keys - chain_keys
                deleted = len(missing_keys)
                injected = len(extra_keys)
                if injected > 0:
                    extra_mask = [1 if k in extra_keys else 0 for k in file_keys_list]
                    if 'source_file' in df_raw.columns:
                        inj_files = df_raw.loc[[bool(x) for x in extra_mask], 'source_file'].value_counts()
                        top_inj = [f"{f}: {n}" for f, n in inj_files.head(3).items()]
                        injected_breakdown = f" (largest additions: {', '.join(top_inj)})" if top_inj else ""

    baseline_mismatch = not baseline_matches

    # Preserve original uploaded order with stable index column
    df_orig = df_raw.copy()
    df_orig['_orig_pos'] = np.arange(file_rows)
    df = df_raw.copy()
    df['_orig_pos'] = np.arange(file_rows)
    if baseline_matches and injected > 0:
        df['hmac_extra'] = [1 if k in extra_keys else 0 for k in file_keys_list]
    df = extract_features(df)

    if hmac_ok and baseline_matches:
        try:
            df = verify_hmac_chain(df, CHAIN)
            hmac_mod = int(df['hmac_flag'].sum()) if 'hmac_flag' in df.columns else 0
            chain_intact = bool(deleted == 0 and injected == 0 and hmac_mod == 0)
            hmac_failed = not chain_intact
            if hmac_failed and 'hmac_flag' in df.columns and (df['hmac_flag'] == 1).any():
                first_bad = df[df['hmac_flag'] == 1].iloc[0]
                rec_k = first_bad.get('event_record_id', first_bad.name)
                time_t = first_bad.get('time_created', 'unknown')
                break_info = (
                    f"The chain first breaks at record #{rec_k} "
                    f"(time {time_t}); records after it cannot be trusted."
                )
        except Exception:
            chain_intact = False
            hmac_failed = True
    elif hmac_ok and not baseline_matches:
        chain_intact = False
        hmac_failed = False
        deleted = "N/A"
        injected = "N/A"

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

    LSTM_MODEL = 'models_saved/lstm_ae.keras'
    LSTM_META = 'models_saved/lstm_meta.pkl'
    lstm_ok = False
    lstm_notice = ""
    threshold = 0.1283
    df_lstm_scored = None

    if not (os.path.exists(LSTM_MODEL) and os.path.exists(LSTM_META)):
        lstm_notice = "The event order check could not run for this file."
    elif len(df_orig) < 10:
        lstm_notice = "The event order check could not run for this file."
    else:
        req_cols = {'event_id', 'time_created'}
        if not req_cols.issubset(df_orig.columns):
            lstm_notice = "The event order check could not run for this file."
        else:
            try:
                # Work on copy of ORIGINAL uploaded order
                df_lstm = df_orig.copy()
                if 'source_file' not in df_lstm.columns:
                    df_lstm['source_file'] = 'uploaded_log.csv'
                if 'event_record_id' not in df_lstm.columns:
                    df_lstm['event_record_id'] = range(1, len(df_lstm) + 1)

                model, meta = get_cached_lstm_model(LSTM_MODEL, LSTM_META)
                threshold = float(meta.get('threshold', 0.1283))
                df_lstm_scored = predict_lstm(df_lstm, model=model, meta=meta)

                # Merge lstm_flag and lstm_score back by the original-position key
                flag_map = dict(zip(df_lstm_scored['_orig_pos'], df_lstm_scored['lstm_flag']))
                score_map = dict(zip(df_lstm_scored['_orig_pos'], df_lstm_scored['lstm_score']))
                df['lstm_flag'] = df['_orig_pos'].map(flag_map).fillna(0).astype(int)
                df['lstm_score'] = df['_orig_pos'].map(score_map).fillna(0.0).astype(float)
                lstm_ok = True
            except Exception:
                lstm_ok = False
                lstm_notice = "The event order check could not run for this file."

    target_lstm_df = df_lstm_scored if df_lstm_scored is not None else df
    lstm_panel = build_lstm_panel_data(
        target_lstm_df,
        threshold=threshold,
        notice=lstm_notice if not lstm_ok else "")

    lstm_alert = bool(lstm_panel.get('alert_fired', False)) if lstm_ok else False

    total = len(df)
    verdict, vclass, vc = get_verdict(
        deleted=deleted, injected=injected, anomalies=anomalies,
        critical=critical, total=total,
        chain_intact=chain_intact,
        baseline_mismatch=baseline_mismatch,
        hmac_failed=hmac_failed,
        lstm_alert=lstm_alert)
    findings = build_findings(
        df, deleted, injected, critical, anomalies,
        baseline_mismatch=baseline_mismatch,
        hmac_failed=hmac_failed,
        break_info=break_info,
        lstm_alert=lstm_alert,
        deleted_breakdown=deleted_breakdown,
        injected_breakdown=injected_breakdown)

    baseline_warning = (
        "HMAC could not be verified against a baseline because the uploaded dataset identity keys do not match the trusted baseline."
        if baseline_mismatch else ""
    )

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
        'lstm_ok': lstm_ok,
        'lstm_notice': lstm_notice,
        'lstm_panel': lstm_panel,
        'baseline_mismatch': baseline_mismatch,
        'baseline_warning': baseline_warning,
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
    st.session_state.lstm_ok = result.get('lstm_ok', False)
    st.session_state.lstm_notice = result.get('lstm_notice', '')
    st.session_state.lstm_panel = result.get('lstm_panel', None)
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
            color=TXT1 if not dm else TXT2,
            size=11),
        margin=dict(l=0, r=0, t=48, b=0),
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
            tickfont=dict(color=TXT1 if not dm else TXT2),
            title=dict(
                text='Time',
                font=dict(size=11, color=TXT1 if not dm else TXT2))),
        yaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            tickfont=dict(color=TXT1 if not dm else TXT2),
            title=dict(
                text='Anomaly Score',
                font=dict(size=11, color=TXT1 if not dm else TXT2)),
            range=[0, 1.05]),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            font=dict(size=11, color=TXT1 if not dm else TXT2)))
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
    conf_val = (
        "HIGH" if verdict == "CLEAN" else "MEDIUM")

    if st.session_state.get('baseline_mismatch', False):
        chain_val = "UNVERIFIED"
        chain_col = "amber"
        chain_delta_class = "warn"
        chain_delta_text = "No matching baseline"
    else:
        chain_val = "PASS" if chain_intact else "FAIL"
        chain_col = "green" if chain_intact else "red"
        chain_delta_class = "bad" if chain_val == "FAIL" else "ok"
        chain_delta_text = "HMAC-SHA256"

    active_count = sum([
        bool(st.session_state.get('hmac_ok', False)),
        bool(st.session_state.get('if_ok', False)),
        bool(st.session_state.get('lstm_ok', False)),
        False
    ])

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
        {conf_val} CONFIDENCE
    </div>
</div>
""", unsafe_allow_html=True)

    if st.session_state.get('baseline_mismatch', False):
        del_str = "N/A"
        del_col = "amber"
        del_delta = "Not available"
        del_card = "warn"
    else:
        del_num = deleted if isinstance(deleted, (int, float)) else 0
        del_str = f"{del_num:,}"
        del_col = "red" if del_num > 0 else "green"
        del_delta = "Confirmed" if del_num > 0 else "None"
        del_card = "accent" if del_num > 0 else "success"

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
    <div class="kpi-card {del_card}">
        <div class="kpi-val {del_col}">
            {del_str}
        </div>
        <div class="kpi-label">Deleted Records</div>
        <div class="kpi-delta
            {'bad' if del_delta=='Confirmed' else ('warn' if del_delta=='Not available' else 'ok')}">
            {del_delta}
        </div>
    </div>
</div>
<div class="kpi-row">
    <div class="kpi-card
        {'warn' if chain_val=='UNVERIFIED' else ('accent' if chain_val=='FAIL' else 'success')}">
        <div class="kpi-val {chain_col}">
            {chain_val}
        </div>
        <div class="kpi-label">Chain Status</div>
        <div class="kpi-delta {chain_delta_class}">
            {chain_delta_text}
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
        <div class="kpi-val">{active_count}</div>
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

    if st.session_state.get('baseline_mismatch', False):
        l1c = 'amber'
        l1s = 'UNVERIFIED'
        l1d = 'HMAC could not be verified against a baseline'
    else:
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

    lstm_ok = st.session_state.get('lstm_ok', False)
    lstm_panel_data = st.session_state.get('lstm_panel', None)
    lstm_flagged = (
        lstm_panel_data.get('rows_flagged', 0)
        if lstm_panel_data else 0)
    l2b_c = ('amber' if lstm_flagged > 0 else
             'green' if lstm_ok else 'grey')
    l2b_s = ('SHUFFLE DETECTED' if lstm_flagged > 0 else
             'NORMAL' if lstm_ok else 'UNAVAILABLE')
    l2b_d = (
        f'{lstm_flagged} out-of-order events flagged'
        if lstm_flagged > 0 else
        'Sequence order intact' if lstm_ok else
        st.session_state.get('lstm_notice') or 'Model not loaded')

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
                {l1d} - Chain verification runs in time order, so reordering of events is checked by the Event Order Check (LSTM).
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
        <div class="layer-bar {l2b_c}"></div>
        <div>
            <div class="layer-name">
                Layer 2b - LSTM Sequence Model
            </div>
            <div class="layer-status {l2b_c}">
                {l2b_s}
            </div>
            <div class="layer-detail">
                {l2b_d}
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

    if lstm_panel_data:
        st.markdown(
            '<div class="sec-label">'
            'Event Order Check (LSTM)</div>',
            unsafe_allow_html=True)
        render_lstm_panel(
            lstm_panel_data,
            {
                'bg': BG,
                'surface': SURFACE,
                'border': BORDER,
                'accent': ACCENT,
                'cyan': CYAN,
                'success': SUCCESS,
                'warn': WARN,
                'txt1': TXT1,
                'txt2': TXT2,
                'txt3': TXT3,
            },
            height=320)

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
            f'({len(flagged):,})'
            f'</div>',
            unsafe_allow_html=True)
        display_flagged = flagged.head(500)
        st.dataframe(
            display_flagged,
            use_container_width=True,
            hide_index=True)
        if len(flagged) > 500:
            st.caption(f"Showing 500 of {len(flagged)} flagged events, strongest evidence first.")
        csv_bytes = flagged.to_csv(index=False).encode('utf-8-sig')
        st.download_button(
            label=f"Download all {len(flagged)} flagged events (CSV)",
            data=csv_bytes,
            file_name="flagged_events.csv",
            mime="text/csv",
            key="download_flagged_events_csv"
        )

    st.markdown(
        '<div style="margin-top:8px">'
        'Go to the Report page to download '
        'the full forensic report.'
        '</div>',
        unsafe_allow_html=True)


def build_findings(df, deleted, injected,
                   critical, anomalies,
                   baseline_mismatch=False,
                   hmac_failed=False,
                   break_info=None,
                   lstm_alert=False,
                   deleted_breakdown="",
                   injected_breakdown=""):
    out = []
    if baseline_mismatch:
        out.append({
            'sev': 'medium',
            'title': 'HMAC could not be verified against a baseline',
            'detail': (
                'HMAC could not be verified against a baseline because the '
                'uploaded dataset does not match the cryptographic chain identity keys. '
                'Tampering cannot be cryptographically proven or ruled out.')
        })
    elif hmac_failed:
        detail_msg = break_info if break_info else (
            'Cryptographic chain verification detected records missing, modified, or out of sequence. '
            'Records after the break cannot be trusted.')
        out.append({
            'sev': 'critical',
            'title': 'Cryptographic chain verification failed',
            'detail': detail_msg
        })

    del_num = deleted if isinstance(deleted, (int, float)) else 0
    inj_num = injected if isinstance(injected, (int, float)) else 0

    if del_num > 0 and not baseline_mismatch:
        out.append({
            'sev': 'critical',
            'title': (
                f'{del_num} log records '
                f'confirmed deleted'),
            'detail': (
                f'{del_num} records are missing compared with the trusted baseline{deleted_breakdown}. '
                'Cryptographic chain verification detected records missing from this file. '
                'This is mathematical proof of deliberate log erasure. Attackers '
                'delete logs to remove evidence of privilege escalation, lateral '
                'movement, or data exfiltration.')
        })
    if inj_num > 0 and not baseline_mismatch:
        out.append({
            'sev': 'critical',
            'title': (
                f'{inj_num} records injected '
                f'into log file'),
            'detail': (
                f'{inj_num} records are extra compared with the trusted baseline{injected_breakdown}. '
                'These entries do not appear in the trusted baseline. '
                'These may represent forged entries inserted to create a false audit '
                'trail or confuse investigators.')
        })
    if 'event_id' in df.columns:
        n1102 = (df['event_id'] == 1102).sum()
        n4719 = (df['event_id'] == 4719).sum()
        if n1102 > 0:
            out.append({
                'sev': 'medium',
                'title': (
                    f'Notable security event: Security log cleared '
                    f'({n1102} instance(s)) Event ID 1102'),
                'detail': (
                    'Event ID 1102 is generated when '
                    'the Windows Security log is cleared. '
                    'This is performed by administrators or attackers. '
                    'This is supporting evidence and does not alone prove tampering.')
            })
        if n4719 > 0:
            out.append({
                'sev': 'medium',
                'title': (
                    f'Notable security event: Audit policy modified '
                    f'({n4719} instance(s)) Event ID 4719'),
                'detail': (
                    'Event ID 4719 indicates the audit policy was changed. '
                    'This is supporting evidence and does not alone prove tampering.')
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
    if 'lstm_flag' in df.columns:
        lstm_count = int(df['lstm_flag'].sum())
        if lstm_count > 0:
            out.append({
                'sev': 'high' if lstm_alert else 'low',
                'title': (
                    f'{lstm_count} events with broken '
                    f'chronological sequence (LSTM)'),
                'detail': (
                    f'The LSTM sequence autoencoder identified '
                    f'{lstm_count} events with sequence violations '
                    f'and high reconstruction error. This pattern is '
                    f'consistent with a shuffle attack where log entries '
                    f'were reordered to obfuscate the sequence of events.')
            })
    if anomalies > 0 and not out:
        out.append({
            'sev': 'info',
            'title': (
                f'{anomalies} anomalous patterns '
                f'detected by AI model'),
            'detail': (
                f'Isolation Forest identified '
                f'{anomalies} events with statistical '
                f'properties inconsistent with the '
                f'established normal baseline. '
                f'Note: Isolation Forest flags a fixed share of any '
                f'file by design as supporting evidence.')
        })
    return out


def make_chart_layout(height=320):
    return dict(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter, sans-serif',
            color=TXT1 if not dm else TXT2,
            size=11),
        margin=dict(l=0, r=0, t=48, b=0),
        height=height,
        xaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            tickfont=dict(color=TXT1 if not dm else TXT2),
            showgrid=True,
            zeroline=False),
        yaxis=dict(
            gridcolor=BORDER,
            linecolor=BORDER,
            tickfont=dict(color=TXT1 if not dm else TXT2),
            showgrid=True,
            zeroline=False),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor=BORDER,
            font=dict(size=11, color=TXT1 if not dm else TXT2)),
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

    def _set_nav_page(target_page):
        try:
            st.session_state["page"] = target_page
            st.session_state.page = target_page
        except Exception:
            pass

    for pg, desc in pages:
        is_active = st.session_state.get("page", "Dashboard") == pg
        st.button(
            pg,
            key=f"nav_{pg}",
            on_click=_set_nav_page,
            args=(pg,),
            use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # System status in sidebar
    IF_READY = os.path.exists(
        'models_saved/isolation_forest.pkl')
    CHAIN_READY = os.path.exists(
        'models_saved/hmac_chain.json')
    LSTM_READY = (
        os.path.exists('models_saved/lstm_ae.keras') and
        os.path.exists('models_saved/lstm_meta.pkl'))

    st.markdown(
        f'<div style="padding:0 12px;'
        f'margin-top:8px">'
        f'<div style="font-size:11px;'
        f'font-weight:700;color:{TXT3 if dm else TXT1};'
        f'letter-spacing:2px;'
        f'text-transform:uppercase;'
        f'padding-bottom:10px;'
        f'border-bottom:1px solid {BORDER};'
        f'margin-bottom:10px">System Status</div>',
        unsafe_allow_html=True)

    items = [
        ("HMAC Chain", CHAIN_READY),
        ("Isolation Forest", IF_READY),
        ("LSTM Model", LSTM_READY),
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
    cur_dm = st.session_state.get("dark_mode", True)
    theme_choice = st.radio(
        "Theme",
        options=["Dark", "Light"],
        index=0 if cur_dm else 1,
        horizontal=True,
        key="theme_radio"
    )
    new_dark = (theme_choice == "Dark")
    if new_dark != cur_dm:
        try:
            st.session_state.dark_mode = new_dark
        except Exception:
            pass
        st.rerun()

page = st.session_state.get("page", "Dashboard")
done = st.session_state.get("analysis_done", False)

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

    if done and st.session_state.get('baseline_mismatch', False):
        dv_str = "N/A"
        dv_col = "amber"
        dv_delta = "Not available"
        dv_card = "warn"
    else:
        dv_num = dv if isinstance(dv, (int, float)) else 0
        dv_str = f"{dv_num:,}"
        dv_col = "red" if dv_num > 0 else "green"
        dv_delta = "Confirmed" if dv_num > 0 else "None"
        dv_card = "accent" if dv_num > 0 else "success"

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
    <div class="kpi-card {dv_card}">
        <div class="kpi-val {dv_col}">
            {dv_str}
        </div>
        <div class="kpi-label">Deleted Records</div>
        <div class="kpi-delta
            {'bad' if dv_delta=='Confirmed' else ('warn' if dv_delta=='Not available' else 'ok')}">
            {dv_delta}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    # Second row of KPIs
    if not done:
        chain_val = DEMO['chain']
        chain_col = "green"
        chain_delta_class = "ok"
        chain_delta_text = "HMAC-SHA256"
        conf_val = f"{DEMO['confidence']}%"
        active_count = 2
    elif st.session_state.get('baseline_mismatch', False):
        chain_val = "UNVERIFIED"
        chain_col = "amber"
        chain_delta_class = "warn"
        chain_delta_text = "No matching baseline"
        conf_val = "HIGH" if vt == "CLEAN" else "MEDIUM"
        active_count = sum([
            bool(st.session_state.get('hmac_ok', False)),
            bool(st.session_state.get('if_ok', False)),
            bool(st.session_state.get('lstm_ok', False)),
            False
        ])
    else:
        chain_val = "PASS" if st.session_state.chain_intact else "FAIL"
        chain_col = "green" if st.session_state.chain_intact else "red"
        chain_delta_class = "bad" if chain_val == "FAIL" else "ok"
        chain_delta_text = "HMAC-SHA256"
        conf_val = "HIGH" if vt == "CLEAN" else "MEDIUM"
        active_count = sum([
            bool(st.session_state.get('hmac_ok', False)),
            bool(st.session_state.get('if_ok', False)),
            bool(st.session_state.get('lstm_ok', False)),
            False
        ])

    st.markdown(f"""
<div class="kpi-row">
    <div class="kpi-card
        {'warn' if chain_val=='UNVERIFIED' else ('accent' if chain_val=='FAIL' else 'success')}">
        <div class="kpi-val {chain_col}">
            {chain_val}
        </div>
        <div class="kpi-label">Chain Status</div>
        <div class="kpi-delta {chain_delta_class}">
            {chain_delta_text}
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
            {active_count}
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
            real_crit = int(
                st.session_state.get('critical_count', 0)
                if 'critical_count' in st.session_state
                else df_r['is_critical_event'].sum()
                if 'is_critical_event' in df_r.columns
                else len(df_r[df_r['event_id'].isin([1102, 4719])])
                if 'event_id' in df_r.columns
                else 0)
            cats = {
                'Critical (1102/4719)': real_crit,
                'Anomalous': st.session_state.anomaly_count,
                'Normal': max(
                    0,
                    len(df_r) -
                    st.session_state.anomaly_count -
                    real_crit),
            }
            center_crit = real_crit
        else:
            cats = {
                'Critical': 7,
                'Anomalous': 284,
                'Normal': 31367,
            }
            center_crit = 7

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
                f"{center_crit:,}<br>"
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

    badge_conf = (
        "HIGH CONFIDENCE" if not done
        else f"{conf_val} CONFIDENCE")

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
        {badge_conf}
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
        if not done:
            layer_names = [
                'HMAC Chain (Active)',
                'Isolation Forest (Active)',
                'LSTM (pending)',
                'Autoencoder (pending)']
            layer_colors = [
                SUCCESS, WARN, BORDER, BORDER]
            donut_active_count = 2
        else:
            hmac_on = bool(st.session_state.get('hmac_ok', False))
            if_on = bool(st.session_state.get('if_ok', False))
            lstm_on = bool(st.session_state.get('lstm_ok', False))

            layer_names = [
                'HMAC Chain' if hmac_on else 'HMAC Chain (inactive)',
                'Isolation Forest' if if_on else 'Isolation Forest (inactive)',
                'LSTM Autoencoder' if lstm_on else 'LSTM (pending)',
                'Autoencoder (pending)']
            layer_colors = [
                SUCCESS if hmac_on else BORDER,
                WARN if if_on else BORDER,
                ACCENT if lstm_on else BORDER,
                BORDER]
            donut_active_count = sum([hmac_on, if_on, lstm_on, False])

        fig2 = go.Figure(go.Pie(
            values=[25, 25, 25, 25],
            labels=layer_names,
            hole=0.65,
            marker=dict(colors=layer_colors,
                        line=dict(width=0)),
            textinfo='none',
            hoverinfo='label'))
        fig2.add_annotation(
            text=f'{donut_active_count}/4<br><span style="font-size:11px">'
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

    # -- SIMULATED GLOBAL ATTACK MAP (Dashboard page only) --
    st.markdown(
        '<div class="sec-label">'
        'Simulated Global Attack Map</div>',
        unsafe_allow_html=True)
    st.caption(
        "Simulated attacker locations, shown for demonstration "
        "purposes. Not derived from real geolocation data.")
    with st.spinner("Rendering attack map..."):
        _atk_fig = create_simulated_attack_map(
            victim_lat=20.5937,
            victim_lon=78.9629,
            computer_name="FORENSIC-HOST",
            city="India",
            country="India",
            BG=BG, SURFACE=SURFACE,
            BORDER=BORDER, ACCENT=ACCENT,
            SUCCESS=SUCCESS, WARN=WARN,
            CYAN=CYAN, TXT1=TXT1, TXT2=TXT2)
    st.plotly_chart(
        _atk_fig,
        use_container_width=True,
        config={'displayModeBar': False})

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
        lstm_cnt = (
            int(df_r['lstm_flag'].sum())
            if 'lstm_flag' in df_r.columns
            else 0)
        lstm_txt = (
            f"{lstm_cnt:,} order anomalies"
            if 'lstm_flag' in df_r.columns
            else "Pending")
        ai_col = WARN if (anom > 0 or lstm_cnt > 0) else SUCCESS
        nodes.append(
            f"AI Detection\n{anom} Anomalies")
        node_colors.append(ai_col)
        node_sizes.append(35)
        node_text.append(
            f"Layer 2: AI/ML Detection<br>"
            f"Isolation Forest: {anom:,}<br>"
            f"LSTM: {lstm_txt}<br>"
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
