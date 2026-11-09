"""
test_live_watcher.py -- Unit and security tests for LogWatcher real-time ingestion.
Verifies fail-closed behavior, queue buffering, sanitization, and attack injection.
"""
try:
    import pytest
except ImportError:
    pytest = None
import time
from datetime import datetime, timezone
from live_tail.watcher import LogWatcher, sanitize_text


def test_sanitize_text_strips_tags_and_truncates():
    """Verify script tags and HTML injection are neutralized."""
    malicious = "<script>alert('pwned')</script>" + "A" * 500
    cleaned = sanitize_text(malicious, max_len=50)
    assert "<script>" not in cleaned
    assert "&lt;script&gt;" in cleaned
    assert len(cleaned) <= 50


def test_sanitize_text_handles_none_and_numbers():
    """Verify None and non-string types fail safely."""
    assert sanitize_text(None) == 'UNKNOWN'
    assert sanitize_text(12345) == '12345'


def test_watcher_initialization_defaults():
    """Verify LogWatcher starts with clean initialized state."""
    watcher = LogWatcher(channel='Security', mode='simulation', poll_interval=0.2)
    status = watcher.get_status()
    assert status['running'] is False
    assert status['configured_mode'] == 'simulation'
    assert status['channel'] == 'Security'
    assert status['events_emitted'] == 0


def test_watcher_simulation_stream():
    """Verify simulated background thread generates valid events into queue."""
    watcher = LogWatcher(channel='Security', mode='simulation', poll_interval=0.2)
    watcher.start()
    assert watcher.is_running() is True

    # Wait for at least 2 events to be generated
    time.sleep(0.6)
    watcher.stop()
    assert watcher.is_running() is False

    events = watcher.get_all_events(max_count=10)
    assert len(events) >= 1
    ev = events[0]
    assert 'event_record_id' in ev
    assert 'event_id' in ev
    assert 'time_created' in ev
    assert ev['is_tampered'] == 0


def test_watcher_inject_attack_clear():
    """Verify inject_attack('clear') generates critical Event 1102."""
    watcher = LogWatcher(mode='simulation')
    attack_ev = watcher.inject_attack('clear')
    assert attack_ev['event_id'] == 1102
    assert attack_ev['is_tampered'] == 1
    assert attack_ev['tamper_type'] == 'audit_cleared'

    queued = watcher.get_next_event(timeout=0.1)
    assert queued is not None
    assert queued['event_id'] == 1102


def test_watcher_inject_attack_gap_and_injection():
    """Verify inject_attack handles 'gap' and 'injection' attacks."""
    watcher = LogWatcher(mode='simulation')
    gap_ev = watcher.inject_attack('gap')
    assert gap_ev['tamper_type'] == 'gap'
    assert gap_ev['is_tampered'] == 1

    inj_ev = watcher.inject_attack('injection')
    assert inj_ev['tamper_type'] == 'injection'
    assert inj_ev['process_name'] == 'mimikatz.exe'
    assert inj_ev['is_tampered'] == 1


def test_watcher_malformed_event_fails_closed():
    """Verify malformed incoming dictionary fields are sanitized and typed."""
    watcher = LogWatcher(mode='simulation')
    malformed = {
        'event_id': 'NOT_A_NUMBER',
        'event_record_id': None,
        'time_created': None,
        'account_name': '<admin>',
        'is_tampered': 'true'
    }
    success = watcher.inject_event(malformed)
    assert success is True
    ev = watcher.get_next_event(timeout=0.1)
    assert ev is not None
    assert ev['event_id'] == 0
    assert ev['event_record_id'] == 0
    assert '&lt;admin&gt;' in ev['account_name']
