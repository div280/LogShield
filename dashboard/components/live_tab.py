"""LogShield dashboard live monitoring component.

Provides real-time event log streaming, cryptographic HMAC chaining,
sliding sequence checks, live telemetry charts, and live attack injection triggers.
"""
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import streamlit as st

from live_tail.watcher import LogWatcher
from live_tail.live_pipeline import LivePipelineEngine


def _format_local_time(tc_val: Any) -> str:
    """Convert UTC or ISO timestamp to user's local host timezone (HH:MM:SS)."""
    if not tc_val:
        return ""
    s = str(tc_val).strip()
    try:
        ts = pd.to_datetime(s)
        if ts.tz is None:
            ts = ts.tz_localize('UTC')
        py_dt = ts.to_pydatetime().astimezone()
        return py_dt.strftime("%H:%M:%S")
    except Exception:
        return s.split('T')[-1][:8] if 'T' in s else s[-8:]


def _resolve_model_path(rel_path: str) -> str:
    """Resolve model path considering root and LogShield subfolder execution."""
    candidates = [
        rel_path,
        os.path.join("LogShield", rel_path),
        os.path.join(os.path.dirname(__file__), "..", "..", rel_path)
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return rel_path


def _get_live_watcher(mode: str = "auto", channel: str = "Security") -> LogWatcher:
    """Retrieve or initialize singleton LogWatcher in session state.

    Parameters:
        mode (str): 'auto', 'windows', or 'simulation'.
        channel (str): Windows event channel name.

    Returns:
        LogWatcher: Singleton watcher instance.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    if "live_watcher" not in st.session_state or st.session_state.live_watcher is None:
        st.session_state.live_watcher = LogWatcher(
            channel=channel,
            mode=mode,
            poll_interval=0.8
        )
    return st.session_state.live_watcher


def _get_live_engine() -> LivePipelineEngine:
    """Retrieve or initialize singleton LivePipelineEngine in session state.

    Returns:
        LivePipelineEngine: Singleton pipeline engine instance.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    if "live_engine" not in st.session_state or st.session_state.live_engine is None:
        st.session_state.live_engine = LivePipelineEngine(
            if_model_path=_resolve_model_path("models_saved/isolation_forest.pkl"),
            lstm_meta_path=_resolve_model_path("models_saved/lstm_meta.pkl"),
            max_history=50
        )
    return st.session_state.live_engine


def render_live_tab() -> None:
    """Render the Live Monitor interface tab.

    Connects to live monitoring events queue, displays real-time log ingestion
    stream, reports security events, and renders live Plotly anomaly charts.

    Returns:
        None

    Time Complexity: O(N) where N is recent events count (N <= 50).
    Space Complexity: O(N) for chart rendering.
    """
    # Color tokens matching dashboard SIEM theme
    dm = st.session_state.get("dark_mode", True)
    BG = "#0A0C10" if dm else "#FFFFFF"
    SURFACE = "#0F1319" if dm else "#F8F9FA"
    BORDER = "#1E2530" if dm else "#E2E8F0"
    ACCENT = "#E8343A"
    CYAN = "#00D4FF"
    SUCCESS = "#00C853"
    WARN = "#FFB300"
    TXT1 = "#E2E8F0" if dm else "#0F172A"
    TXT2 = "#8892B0" if dm else "#64748B"

    # State flags
    if "live_monitoring_active" not in st.session_state:
        st.session_state.live_monitoring_active = False

    engine = _get_live_engine()

    # Top Bar Header
    is_active = st.session_state.live_monitoring_active
    status_pill = (
        f'<div class="live-pill" style="display:inline-flex; align-items:center; gap:6px; background:rgba(0,200,83,0.15); border:1px solid #00C853; border-radius:12px; padding:3px 10px; font-size:11px; font-weight:600; color:#00C853;">'
        f'<span style="height:7px; width:7px; background:#00C853; border-radius:50%; display:inline-block; animation:pulse 1.5s infinite;"></span> STREAMING ACTIVE</div>'
        if is_active else
        f'<div class="live-pill" style="display:inline-flex; align-items:center; gap:6px; background:rgba(136,146,176,0.15); border:1px solid #8892B0; border-radius:12px; padding:3px 10px; font-size:11px; font-weight:600; color:#8892B0;">'
        f'<span style="height:7px; width:7px; background:#8892B0; border-radius:50%; display:inline-block;"></span> STANDBY</div>'
    )

    st.markdown(f"""
<div class="top-bar" style="display:flex; justify-content:space-between; align-items:center; padding:12px 0 20px 0; border-bottom:1px solid {BORDER}; margin-bottom:20px;">
    <div>
        <div style="font-size:24px; font-weight:700; color:{TXT1}; letter-spacing:-0.5px;">Live Monitor</div>
        <div style="font-size:12px; color:{TXT2}; margin-top:2px;">Real-Time Windows Security Event Ingestion & Dual-Layer Tamper Detection</div>
    </div>
    <div>{status_pill}</div>
</div>
""", unsafe_allow_html=True)

    st.markdown('<div class="page-wrap">', unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Control Panel
    # -------------------------------------------------------------------------
    st.markdown(f'<div style="font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:{CYAN}; margin-bottom:8px;">Stream Controls</div>', unsafe_allow_html=True)

    c_cfg1, c_cfg2, c_act1, c_act2, c_act3 = st.columns([2.5, 2.0, 1.5, 1.5, 1.5])
    with c_cfg1:
        mode_choice = st.selectbox(
            "Ingestion Mode",
            ["Auto (Detect OS / Safe Emulation)", "Live Windows Event Log", "Live Simulation Stream (Demo)"],
            index=0,
            disabled=is_active
        )
    with c_cfg2:
        channel_choice = st.selectbox(
            "Event Channel",
            ["Security", "System", "Application"],
            index=0,
            disabled=is_active
        )

    mode_map = {
        "Auto (Detect OS / Safe Emulation)": "auto",
        "Live Windows Event Log": "windows",
        "Live Simulation Stream (Demo)": "simulation"
    }
    selected_mode = mode_map[mode_choice]

    with c_act1:
        st.write("")
        st.write("")
        if not is_active:
            if st.button("▶ Start Stream", type="primary", use_container_width=True):
                watcher = _get_live_watcher(mode=selected_mode, channel=channel_choice)
                watcher.mode = selected_mode
                watcher.channel = channel_choice
                watcher.start()
                st.session_state.live_monitoring_active = True
                st.rerun()
        else:
            if st.button("⏹ Stop Stream", use_container_width=True):
                watcher = _get_live_watcher()
                watcher.stop()
                st.session_state.live_monitoring_active = False
                st.rerun()

    with c_act2:
        st.write("")
        st.write("")
        if st.button("🔄 Reset Feed", use_container_width=True):
            engine.reset_state()
            watcher = _get_live_watcher()
            while not watcher.event_queue.empty():
                try:
                    watcher.event_queue.get_nowait()
                except Exception:
                    break
            st.rerun()

    with c_act3:
        st.write("")
        st.write("")
        auto_refresh = st.checkbox("Auto-Refresh", value=True, help="Automatically stream incoming events every 1 second")

    # Live CMD Admin Bridge Status Indicator
    st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:6px; padding:8px 14px; margin-top:10px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
    <span style="font-size:11px; color:{CYAN}; font-weight:600;">💻 Live CMD Admin Bridge: Connected</span>
    <span style="font-size:11px; color:{TXT2};">Run <code>admin_console.bat</code> or <code>python admin_cmd.py &lt;command&gt;</code> in CMD Admin to stream live user/process actions directly into this feed.</span>
</div>
""", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Teacher Demo / Viva Section: One-Click Attack Triggers
    # -------------------------------------------------------------------------
    st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:12px 16px; margin:14px 0 20px 0;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <span style="font-size:12px; font-weight:700; color:{TXT1};">⚡ Live Attack Injection (Teacher Review & Viva Demo)</span>
        <span style="font-size:11px; color:{TXT2};">Simulate real-time anti-forensic tampering to verify immediate sub-500ms detection</span>
    </div>
</div>
""", unsafe_allow_html=True)

    c_atk1, c_atk2, c_atk3, c_atk4 = st.columns(4)
    watcher = _get_live_watcher()

    with c_atk1:
        if st.button("🚨 Clear Audit Log (1102)", use_container_width=True, help="Simulate an attacker executing 'wevtutil cl Security'"):
            watcher.inject_attack("clear")
            st.toast("Injected Event 1102: The audit log was cleared!", icon="🚨")

    with c_atk2:
        if st.button("⚠️ Gap Attack (Delete Logs)", use_container_width=True, help="Simulate selective record deletion causing a sequence gap"):
            watcher.inject_attack("gap")
            st.toast("Injected Gap Attack: 50 missing records skipped!", icon="⚠️")

    with c_atk3:
        if st.button("⚡ Inject Mimikatz Binary", use_container_width=True, help="Simulate malicious process execution"):
            watcher.inject_attack("injection")
            st.toast("Injected Suspicious Process: mimikatz.exe invoked!", icon="⚡")

    with c_atk4:
        if st.button("🔀 Shuffle Sequence Attack", use_container_width=True, help="Simulate out-of-order sequence timestamp manipulation"):
            watcher.inject_attack("shuffle")
            st.toast("Injected Shuffle Attack: Out-of-order record ID!", icon="🔀")

    # -------------------------------------------------------------------------
    # Ingestion & Pipeline Execution
    # -------------------------------------------------------------------------
    if is_active:
        new_events = watcher.get_all_events(max_count=20)
        for ev in new_events:
            engine.process_event(ev)

    kpis = engine.get_kpis()
    w_status = watcher.get_status()

    # Telemetry Warning / Permission banner
    if is_active and w_status.get('last_error'):
        st.markdown(f"""
<div style="background:rgba(255,179,0,0.15); border:1px solid #FFB300; border-radius:8px; padding:12px 16px; margin:10px 0; display:flex; align-items:center; gap:12px;">
    <div style="font-size:20px;">⚠️</div>
    <div>
        <div style="color:#FFB300; font-weight:700; font-size:12px; text-transform:uppercase;">Stream Telemetry Notice</div>
        <div style="color:{TXT1}; font-size:12px;">{w_status['last_error']}</div>
    </div>
</div>
""", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Live KPI Cards Grid
    # -------------------------------------------------------------------------
    st.markdown(f'<div style="font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:{CYAN}; margin:16px 0 8px 0;">Live Forensic Telemetry</div>', unsafe_allow_html=True)

    kp1, kp2, kp3, kp4, kp5 = st.columns(5)
    with kp1:
        st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:14px; text-align:center;">
    <div style="font-size:11px; color:{TXT2}; text-transform:uppercase; font-weight:600;">Events Ingested</div>
    <div style="font-size:26px; font-weight:800; color:{TXT1}; margin:4px 0;">{kpis['total_processed']}</div>
    <div style="font-size:10px; color:{CYAN};">{w_status['active_mode'].capitalize()} stream</div>
</div>
""", unsafe_allow_html=True)

    with kp2:
        int_score = kpis['average_integrity_score']
        score_color = SUCCESS if int_score >= 85 else WARN if int_score >= 50 else ACCENT
        st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:14px; text-align:center;">
    <div style="font-size:11px; color:{TXT2}; text-transform:uppercase; font-weight:600;">Integrity Score</div>
    <div style="font-size:26px; font-weight:800; color:{score_color}; margin:4px 0;">{int_score}%</div>
    <div style="font-size:10px; color:{TXT2};">Mathematical Chain</div>
</div>
""", unsafe_allow_html=True)

    with kp3:
        clean_c = kpis['clean_count']
        st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:14px; text-align:center;">
    <div style="font-size:11px; color:{TXT2}; text-transform:uppercase; font-weight:600;">Verified Clean</div>
    <div style="font-size:26px; font-weight:800; color:{SUCCESS}; margin:4px 0;">{clean_c}</div>
    <div style="font-size:10px; color:{SUCCESS};">Zero anomalies</div>
</div>
""", unsafe_allow_html=True)

    with kp4:
        comp_c = kpis['compromised_count']
        comp_color = ACCENT if comp_c > 0 else TXT2
        st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:14px; text-align:center;">
    <div style="font-size:11px; color:{TXT2}; text-transform:uppercase; font-weight:600;">Compromised</div>
    <div style="font-size:26px; font-weight:800; color:{comp_color}; margin:4px 0;">{comp_c}</div>
    <div style="font-size:10px; color:{ACCENT if comp_c > 0 else TXT2};">Critical Attacks</div>
</div>
""", unsafe_allow_html=True)

    with kp5:
        st.markdown(f"""
<div style="background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; padding:14px; text-align:center;">
    <div style="font-size:11px; color:{TXT2}; text-transform:uppercase; font-weight:600;">Active HMAC Chain</div>
    <div style="font-size:14px; font-family:monospace; font-weight:700; color:{CYAN}; margin:10px 0;">{kpis['running_hmac_prefix']}</div>
    <div style="font-size:10px; color:{TXT2};">SHA-256 Forward Bound</div>
</div>
""", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Critical Alert Notification Banner
    # -------------------------------------------------------------------------
    if kpis['compromised_count'] > 0:
        latest_alerts = [a['alert'] for a in list(engine.recent_alerts)[-3:] if 'CRITICAL' in a['alert'] or 'GAP' in a['alert']]
        alert_msg = latest_alerts[-1] if latest_alerts else "Anti-forensic log tampering detected!"
        st.markdown(f"""
<div style="background:rgba(232,52,58,0.15); border:1px solid {ACCENT}; border-radius:8px; padding:12px 16px; margin:16px 0; display:flex; align-items:center; gap:12px;">
    <div style="font-size:22px;">🚨</div>
    <div>
        <div style="color:{ACCENT}; font-weight:700; font-size:13px;">ACTIVE TAMPER ALERT TRIGGERED</div>
        <div style="color:{TXT1}; font-size:12px;">{alert_msg}</div>
    </div>
</div>
""", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Real-Time Visualizations (Anomaly Chart & Event Feed)
    # -------------------------------------------------------------------------
    ch_col, tab_col = st.columns([5, 5])

    recent_list = list(engine.recent_events)

    with ch_col:
        st.markdown(f'<div style="font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:{CYAN}; margin-bottom:8px;">Live Anomaly Score Timeline</div>', unsafe_allow_html=True)
        if len(recent_list) > 0:
            x_vals = list(range(1, len(recent_list) + 1))
            y_scores = [ev.get('anomaly_score', 0.0) for ev in recent_list]
            colors = [
                ACCENT if ev.get('verdict') == 'COMPROMISED'
                else WARN if ev.get('verdict') == 'SUSPICIOUS'
                else SUCCESS
                for ev in recent_list
            ]

            fig = go.Figure()
            # Anomaly threshold line
            fig.add_hline(y=0.5, line_dash="dash", line_color=WARN, opacity=0.7, annotation_text="Anomaly Threshold (0.5)")

            fig.add_trace(go.Scatter(
                x=x_vals,
                y=y_scores,
                mode='lines+markers',
                line=dict(color=CYAN, width=2),
                marker=dict(color=colors, size=8, line=dict(color=BORDER, width=1)),
                name='Anomaly Score',
                hovertemplate="Record #%{text}<br>Anomaly Score: %{y:.3f}<extra></extra>",
                text=[ev.get('event_record_id') for ev in recent_list]
            ))

            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color=TXT2, size=11),
                margin=dict(l=30, r=20, t=20, b=30),
                height=260,
                xaxis=dict(title="Recent Events Window", gridcolor=BORDER, zeroline=False),
                yaxis=dict(title="Score (0-1)", range=[-0.05, 1.05], gridcolor=BORDER, zeroline=False),
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
        else:
            st.markdown(f'<div style="height:260px; display:flex; align-items:center; justify-content:center; background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; color:{TXT2}; font-size:13px;">Waiting for stream to start... Click "Start Stream" above.</div>', unsafe_allow_html=True)

    with tab_col:
        st.markdown(f'<div style="font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:{CYAN}; margin-bottom:8px;">Live Stream Feed (Most Recent)</div>', unsafe_allow_html=True)
        if len(recent_list) > 0:
            feed_data = []
            for ev in reversed(recent_list[-12:]):
                time_str = _format_local_time(ev.get('time_created', ''))
                feed_data.append({
                    "Time": time_str,
                    "Record #": ev.get('event_record_id'),
                    "Event ID": ev.get('event_id'),
                    "Account": ev.get('account_name', 'SYSTEM'),
                    "Process": ev.get('process_name'),
                    "Verdict": ev.get('verdict'),
                    "Notes": ev.get('alerts')[0] if ev.get('alerts') else "Sequence Verified"
                })
            df_feed = pd.DataFrame(feed_data)
            st.dataframe(
                df_feed,
                use_container_width=True,
                height=260,
                hide_index=True
            )
        else:
            st.markdown(f'<div style="height:260px; display:flex; align-items:center; justify-content:center; background:{SURFACE}; border:1px solid {BORDER}; border-radius:8px; color:{TXT2}; font-size:13px;">No events ingested yet.</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # Auto-refresh loop when stream is active
    if is_active and auto_refresh:
        time.sleep(1.0)
        st.rerun()
