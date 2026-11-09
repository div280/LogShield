"""
test_live_pipeline.py -- Unit and security tests for LogShield real-time live detection pipeline.
Tests dual-layer rule enforcement, HMAC forward chaining, gap detection, and model fusion.
"""
try:
    import pytest
except ImportError:
    pytest = None

from live_tail.live_pipeline import LivePipelineEngine


def test_live_pipeline_clean_event():
    """Verify clean sequential events receive CLEAN verdict and high integrity score."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    ev1 = {
        'event_record_id': 1001,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:00+00:00',
        'process_name': 'lsass.exe'
    }
    res = engine.process_event(ev1)
    assert res['verdict'] == 'CLEAN'
    assert res['integrity_score'] == 100.0
    assert len(res['alerts']) == 0
    assert 'hmac_hash' in res['event']


def test_live_pipeline_event_1102_critical_override():
    """Verify Event 1102 (Log Cleared) triggers COMPROMISED verdict immediately."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    ev = {
        'event_record_id': 1002,
        'event_id': 1102,
        'time_created': '2026-08-25T10:00:05+00:00',
        'process_name': 'wevtutil.exe'
    }
    res = engine.process_event(ev)
    assert res['verdict'] == 'COMPROMISED'
    assert res['integrity_score'] == 0.0
    assert any("Audit log was cleared" in a for a in res['alerts'])


def test_live_pipeline_gap_attack_detection():
    """Verify jump in event record IDs triggers Gap Attack detection."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    # Initial event
    engine.process_event({
        'event_record_id': 500,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:00+00:00',
        'process_name': 'svchost.exe'
    })

    # Gap attack: jump to 550 (50 missing records)
    res_gap = engine.process_event({
        'event_record_id': 550,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:02+00:00',
        'process_name': 'svchost.exe'
    })
    assert res_gap['verdict'] == 'COMPROMISED'
    assert any("GAP ATTACK DETECTED" in a for a in res_gap['alerts'])


def test_live_pipeline_shuffle_attack_detection():
    """Verify out-of-order record ID triggers Shuffle Attack detection."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    engine.process_event({
        'event_record_id': 700,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:00+00:00',
        'process_name': 'svchost.exe'
    })

    # Shuffled record arrives: record ID 680 arrived after 700
    res_shuf = engine.process_event({
        'event_record_id': 680,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:01+00:00',
        'process_name': 'svchost.exe'
    })
    assert res_shuf['verdict'] == 'SUSPICIOUS'
    assert any("SHUFFLE ATTACK DETECTED" in a for a in res_shuf['alerts'])


def test_live_pipeline_suspicious_process_detection():
    """Verify mimikatz or unauthorized tooling triggers threat alert."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    res = engine.process_event({
        'event_record_id': 800,
        'event_id': 4688,
        'time_created': '2026-08-25T10:00:00+00:00',
        'process_name': 'mimikatz.exe'
    })
    assert res['verdict'] == 'SUSPICIOUS'
    assert any("Suspicious binary execution" in a for a in res['alerts'])


def test_live_pipeline_kpi_aggregation():
    """Verify KPI counters aggregate correctly."""
    engine = LivePipelineEngine(if_model_path="LogShield/models_saved/isolation_forest.pkl")
    engine.reset_state()

    # 1 clean, 1 compromised
    engine.process_event({
        'event_record_id': 900,
        'event_id': 4624,
        'time_created': '2026-08-25T10:00:00+00:00',
        'process_name': 'svchost.exe'
    })
    engine.process_event({
        'event_record_id': 901,
        'event_id': 1102,
        'time_created': '2026-08-25T10:00:01+00:00',
        'process_name': 'wevtutil.exe'
    })

    kpis = engine.get_kpis()
    assert kpis['total_processed'] == 2
    assert kpis['clean_count'] == 1
    assert kpis['compromised_count'] == 1
    assert kpis['average_integrity_score'] == 50.0

