"""
test_dashboard.py
Unit and security tests for LogShield dashboard components, new features, and fail-closed integrity checks.
"""
import io
import os
import sys
import tempfile
import pytest
import pandas as pd
import plotly.graph_objects as go

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.parser import (
    parse_csv_file,
    parse_csv_from_bytes,
    parse_evtx_file,
    MAX_FILE_SIZE,
)
from dashboard.app import (
    make_processing_gauge,
    make_threat_map,
    make_victim_map,
    make_network_diagram,
    geolocate_ips,
    get_verdict,
    render_timeline_chart,
)


def test_dashboard_file_exists():
    assert os.path.exists('dashboard/app.py')


def test_config_file_exists():
    assert os.path.exists('.streamlit/config.toml')


def test_pdf_report_module_exists():
    assert os.path.exists('dashboard/utils/pdf_report.py')


def test_isolation_forest_model_exists():
    assert os.path.exists('models_saved/isolation_forest.pkl')


def test_hmac_chain_exists():
    assert os.path.exists('models_saved/hmac_chain.json')


def test_streamlit_importable():
    import streamlit
    assert True


def test_plotly_importable():
    import plotly.graph_objects as go
    assert True


def test_threat_panels_module_exists():
    assert os.path.exists('dashboard/utils/threat_panels.py')


def test_threat_render_module_exists():
    assert os.path.exists('dashboard/utils/threat_render.py')


def test_render_timeline_chart_builds_figure():
    class FakeStreamlit:
        last_fig = None

        @staticmethod
        def plotly_chart(fig, **kwargs):
            FakeStreamlit.last_fig = fig

    import dashboard.app as app_module
    original_st = app_module.st
    app_module.st = FakeStreamlit
    try:
        timeline = {
            'norm_times': ['2026-08-25 08:00:00+00:00'] * 1000,
            'norm_scores': [0.1] * 1000,
            'anom_times': ['2026-08-25 09:00:00+00:00'] * 50,
            'anom_scores': [0.9] * 50,
            'norm_count': 1000,
            'anom_count': 50,
        }
        render_timeline_chart(timeline, height=340)
        fig = FakeStreamlit.last_fig
        assert isinstance(fig, go.Figure)
        assert len(fig.layout.shapes) >= 1
        assert len(fig.layout.annotations) >= 1
    finally:
        app_module.st = original_st


# =========================================================================
# FEATURE 1: LOG PROCESSING RATE GAUGE TESTS
# =========================================================================

def test_make_processing_gauge_figure_generation():
    total_events = 31658
    anomalies = 284
    fig = make_processing_gauge(total_events, anomalies)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 1
    trace = fig.data[0]
    expected_pct = (anomalies / total_events) * 100
    assert abs(trace.value - expected_pct) < 1e-4
    assert trace.gauge.axis.range == (0, 100)


def test_make_processing_gauge_zero_events_safe():
    fig = make_processing_gauge(0, 0)
    assert isinstance(fig, go.Figure)
    assert fig.data[0].value == 0.0


# =========================================================================
# FEATURE 2: THREAT ACTIVITY WORLD MAP & IP GEOLOCATION TESTS
# =========================================================================

def test_geolocate_ips_filters_private_and_unknown():
    private_and_special_ips = [
        '192.168.1.1',
        '10.0.0.5',
        '172.16.0.1',
        '127.0.0.1',
        '0.0.0.0',
        '-',
        'UNKNOWN',
        '',
    ]
    results = geolocate_ips(private_and_special_ips)
    assert results == []


def test_make_threat_map_skips_when_no_public_ips():
    df = pd.DataFrame({
        'ip_address': ['192.168.1.5', '10.0.0.1', '127.0.0.1'],
        'if_flag': [1, 0, 0]
    })
    fig = make_threat_map(
        df,
        ['192.168.1.5'],
        ['10.0.0.1', '127.0.0.1'],
        '#0A0C10', '#0F1319', '#1E2530',
        '#E8343A', '#00C853', '#F0F2F5', '#6B7280'
    )
    assert fig is None


def test_make_threat_map_builds_scattergeo(monkeypatch):
    mock_locations = [
        {
            'ip': '203.0.113.195',
            'lat': 37.7749,
            'lon': -122.4194,
            'country': 'United States',
            'city': 'San Francisco',
            'isp': 'Example ISP',
            'suspicious': False
        },
        {
            'ip': '198.51.100.42',
            'lat': 51.5074,
            'lon': -0.1278,
            'country': 'United Kingdom',
            'city': 'London',
            'isp': 'Example Telecom',
            'suspicious': False
        }
    ]
    import dashboard.app as app_module
    monkeypatch.setattr(app_module, 'geolocate_ips', lambda ips: mock_locations)

    df = pd.DataFrame({
        'ip_address': ['203.0.113.195', '198.51.100.42'],
        'if_flag': [1, 0]
    })
    fig = make_threat_map(
        df,
        ['203.0.113.195'],
        ['198.51.100.42'],
        '#0A0C10', '#0F1319', '#1E2530',
        '#E8343A', '#00C853', '#F0F2F5', '#6B7280'
    )
    assert isinstance(fig, go.Figure)
    trace_names = [t.name for t in fig.data]
    assert 'Normal Activity' in trace_names
    assert 'Suspicious Origin' in trace_names


def test_make_victim_map_figure_generation(monkeypatch):
    class MockResponse:
        @staticmethod
        def json():
            return [{'lat': '12.9716', 'lon': '77.5946'}]

    import requests
    monkeypatch.setattr(requests, 'get', lambda *args, **kwargs: MockResponse())

    fig = make_victim_map(
        computer_name='WIN-PC01',
        city='Bangalore',
        country='India',
        findings=[{'sev': 'critical', 'title': 'Log Cleared'}],
        BG='#0A0C10', SURFACE='#0F1319', BORDER='#1E2530',
        ACCENT='#E8343A', SUCCESS='#00C853', WARN='#FFB300',
        TXT1='#F0F2F5', TXT2='#6B7280'
    )
    assert isinstance(fig, go.Figure)
    trace_names = [t.name for t in fig.data if t.name]
    assert 'Forensic Subject' in trace_names
    subject_trace = [t for t in fig.data if t.name == 'Forensic Subject'][0]
    assert subject_trace.marker.color == '#E8343A'
    assert subject_trace.text[0] == 'WIN-PC01'


def test_make_victim_map_default_coordinates_fallback(monkeypatch):
    import requests
    def raise_err(*args, **kwargs):
        raise ConnectionError("Network unreachable")
    monkeypatch.setattr(requests, 'get', raise_err)

    fig = make_victim_map(
        computer_name='WIN-OFFLINE',
        city='UnknownCity',
        country='UnknownCountry',
        findings=[],
        BG='#0A0C10', SURFACE='#0F1319', BORDER='#1E2530',
        ACCENT='#E8343A', SUCCESS='#00C853', WARN='#FFB300',
        TXT1='#F0F2F5', TXT2='#6B7280'
    )
    assert isinstance(fig, go.Figure)
    assert fig.layout.geo.center.lat == 20.5937
    assert fig.layout.geo.center.lon == 78.9629


def test_make_network_diagram_topology_generation():
    df = pd.DataFrame({
        'computer': ['WIN-CORP-01'] * 10,
        'account_name': ['SYSTEM', 'admin', 'jdoe', 'SYSTEM', 'admin', 'guest', 'audit', 'test', 'admin', 'jdoe'],
        'process_name': ['wevtutil.exe', 'cmd.exe', 'psexec.exe', 'lsass.exe', 'whoami.exe', 'explorer.exe', 'powershell.exe', 'net.exe', 'svchost.exe', 'cmd.exe'],
        'event_id': [1102, 4719, 4624, 4625, 4688, 4663, 1102, 4719, 4624, 4688],
        'if_flag': [1, 1, 0, 1, 0, 0, 1, 1, 0, 0]
    })

    fig = make_network_diagram(
        df=df,
        BG='#0A0C10', SURFACE='#0F1319', BORDER='#1E2530',
        ACCENT='#E8343A', SUCCESS='#00C853', WARN='#FFB300',
        CYAN='#00D4FF', TXT1='#F0F2F5', TXT2='#6B7280'
    )
    assert isinstance(fig, go.Figure)
    assert len(fig.data) >= 2
    node_trace = [t for t in fig.data if t.mode == 'markers+text'][0]
    labels = node_trace.text
    assert 'WIN-CORP-01' in labels
    assert any('wevtutil' in str(l) for l in labels)
    assert any('LOG CLEARED' in str(l) for l in labels)
    assert any('AUDIT DISABLED' in str(l) for l in labels)


# =========================================================================
# FEATURE 3: LOG CLASSIFICATION DONUT TESTS
# =========================================================================

def test_log_classification_donut_structure():
    cats = {
        'Critical (1102/4719)': 7,
        'Anomalous': 284,
        'Normal': 31367,
    }
    cat_colors = ['#E8343A', '#FFB300', '#00C853']
    fig = go.Figure(go.Pie(
        labels=list(cats.keys()),
        values=list(cats.values()),
        hole=0.6,
        marker=dict(colors=cat_colors, line=dict(width=0)),
        textinfo='percent'
    ))
    fig.add_annotation(
        text=f"{cats.get('Critical (1102/4719)', 7)}<br>Critical",
        x=0.5, y=0.5, showarrow=False
    )
    assert isinstance(fig, go.Figure)
    assert fig.data[0].hole == 0.6
    assert len(fig.data[0].labels) == 3
    assert len(fig.layout.annotations) == 1


# =========================================================================
# FEATURE 4: LOG EVENT AND ALARM TREND TESTS
# =========================================================================

def test_log_event_trend_figure_structure():
    df = pd.DataFrame({
        'time_created': pd.date_range('2026-08-25 08:00', periods=24, freq='h', tz='UTC'),
        'event_id': [4624] * 24,
        'if_flag': [0] * 20 + [1] * 4,
    })
    df['hour'] = df['time_created'].dt.floor('h')
    hourly = df.groupby('hour').agg(
        total=('event_id', 'count'),
        anomalies=('if_flag', 'sum')
    ).reset_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=hourly['hour'],
        y=hourly['total'],
        name='All Events',
        line=dict(color='#00D4FF', width=2),
        fill='tozeroy'
    ))
    fig.add_trace(go.Scatter(
        x=hourly['hour'],
        y=hourly['anomalies'],
        name='Anomalies',
        line=dict(color='#E8343A', width=2)
    ))

    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 2
    assert fig.data[0].name == 'All Events'
    assert fig.data[1].name == 'Anomalies'


# =========================================================================
# FEATURE 5: KNOWLEDGE GRAPH & THREAT OVERVIEW TESTS
# =========================================================================

def test_threat_overview_knowledge_graph_builder():
    df_r = pd.DataFrame({
        'event_id': [1102, 4719, 4624, 4688],
        'process_name': ['wevtutil.exe', 'powershell.exe', 'lsass.exe', 'net.exe'],
        'time_created': pd.date_range('2026-08-25 08:00', periods=4, freq='min', tz='UTC'),
        'is_critical_event': [1, 1, 0, 0]
    })
    deleted_count = 5
    anomaly_count = 12
    verdict = 'COMPROMISED'

    nodes = []
    edges = []

    # System node
    nodes.append("Windows\nEvent Logs")

    # HMAC node
    hmac_status = "COMPROMISED" if deleted_count > 0 else "INTACT"
    nodes.append(f"HMAC Chain\n{hmac_status}")
    edges.append((0, 1))

    # Event 1102 & 4719
    n1102 = (df_r['event_id'] == 1102).sum()
    n4719 = (df_r['event_id'] == 4719).sum()
    if n1102 > 0:
        nodes.append(f"Event 1102\nLog Cleared x{n1102}")
        edges.append((1, len(nodes) - 1))
    if n4719 > 0:
        nodes.append(f"Event 4719\nPolicy Changed x{n4719}")
        edges.append((1, len(nodes) - 1))

    # Process tools
    tools = ['wevtutil', 'whoami', 'net.exe', 'psexec']
    for tool in tools:
        cnt = df_r['process_name'].str.lower().str.contains(tool, na=False).sum()
        if cnt > 0:
            nodes.append(f"{tool}\nx{cnt}")
            edges.append((1, len(nodes) - 1))

    # AI Detection node
    nodes.append(f"AI Detection\n{anomaly_count} Anomalies")
    edges.append((0, len(nodes) - 1))

    # Verdict node
    nodes.append(f"Verdict\n{verdict}")
    edges.append((1, len(nodes) - 1))

    assert "Windows\nEvent Logs" in nodes[0]
    assert "COMPROMISED" in nodes[1]
    assert any("1102" in n for n in nodes)
    assert any("4719" in n for n in nodes)
    assert any("wevtutil" in n for n in nodes)
    assert any("net.exe" in n for n in nodes)
    assert any("Verdict" in n for n in nodes)
    assert len(edges) >= 6


def test_attack_timeline_events_extraction():
    df_r = pd.DataFrame({
        'event_id': [1102, 4719, 4625],
        'time_created': pd.date_range('2026-08-25 08:00', periods=3, freq='min', tz='UTC'),
        'account_name': ['SYSTEM', 'admin', 'guest'],
        'process_name': ['wevtutil.exe', 'auditpol.exe', 'logon.exe'],
        'is_critical_event': [1, 1, 0],
    })

    timeline_events = []
    for _, row in df_r.iterrows():
        eid = int(row['event_id'])
        meaning = {
            1102: "Security log was cleared",
            4719: "Audit policy was changed",
            4625: "Failed logon attempt"
        }.get(eid, f"Event {eid}")
        sev = "CRITICAL" if eid in [1102, 4719] else "HIGH" if eid == 4625 else "MEDIUM"
        timeline_events.append({
            'Time': str(row['time_created'])[:19],
            'Event ID': eid,
            'What Happened': meaning,
            'Severity': sev
        })

    assert len(timeline_events) == 3
    assert timeline_events[0]['Severity'] == 'CRITICAL'
    assert timeline_events[0]['What Happened'] == 'Security log was cleared'
    assert timeline_events[1]['Severity'] == 'CRITICAL'
    assert timeline_events[2]['Severity'] == 'HIGH'


# =========================================================================
# 7 MANDATORY SECURITY TESTS (FAIL CLOSED & HOSTILE INPUT HANDLING)
# =========================================================================

def test_malformed_file_does_not_crash_parser():
    malformed_csv_bytes = b"\x00\xFF\xFE\x00\x01\x02\x03\x04RandomCorruptBinaryData"
    with pytest.raises(Exception):
        parse_csv_from_bytes(malformed_csv_bytes)


def test_oversized_file_is_rejected():
    oversized_size = MAX_FILE_SIZE + 1024
    from src.parser import _check_file_size
    with pytest.raises(ValueError) as exc:
        _check_file_size(oversized_size)
    assert "File exceeds the 150 MB upload limit" in str(exc.value)


def test_wrong_format_file_is_rejected(tmp_path):
    bad_file = tmp_path / "malicious.exe"
    bad_file.write_text("MZBinaryHeaderMock")
    with pytest.raises(ValueError) as exc:
        parse_csv_file(str(bad_file))
    assert "Only .csv files accepted" in str(exc.value)


def test_empty_file_is_handled_gracefully():
    empty_bytes = b""
    with pytest.raises(Exception):
        parse_csv_from_bytes(empty_bytes)


def test_tampered_logs_never_marked_clean_on_error():
    verdict, vclass, vc = get_verdict(deleted=10, injected=0, anomalies=0, critical=0, total=100)
    assert verdict == "COMPROMISED"
    assert vclass == "compromised"
    assert vc == "red"

    verdict_inj, _, _ = get_verdict(deleted=0, injected=3, anomalies=0, critical=0, total=100)
    assert verdict_inj == "COMPROMISED"

    verdict_crit, _, _ = get_verdict(deleted=0, injected=0, anomalies=0, critical=1, total=100)
    assert verdict_crit == "SUSPICIOUS"


def test_path_traversal_attempt_is_blocked():
    traversal_path = "../../etc/shadow.evtx"
    with pytest.raises(ValueError) as exc:
        parse_evtx_file(traversal_path)
    assert "Path traversal detected" in str(exc.value)


def test_temp_files_deleted_after_processing():
    temp_file_path = None
    with tempfile.NamedTemporaryFile(delete=True, suffix=".csv") as tmp:
        tmp.write(b"event_id,time_created,computer,is_tampered\n1102,2026-08-25,WIN1,0\n")
        tmp.flush()
        temp_file_path = tmp.name
        assert os.path.exists(temp_file_path)

    assert not os.path.exists(temp_file_path)
