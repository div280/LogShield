try:
    import pytest
except ImportError:
    pytest = None
import pandas as pd
import numpy as np
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))
from src.features import extract_features

SAMPLE_DATA = pd.DataFrame({
    'event_id': [4624, 4625, 4688, 1102, 4663],
    'time_created': pd.to_datetime([
        '2026-08-25 08:00:00+00:00',
        '2026-08-25 08:00:02+00:00',
        '2026-08-25 08:00:05+00:00',
        '2026-08-25 08:00:10+00:00',
        '2026-08-25 08:00:15+00:00'
    ]),
    'computer': ['WIN-TEST'] * 5,
    'account_name': ['user1'] * 5,
    'process_name': ['lsass.exe', 'lsass.exe',
                     'cmd.exe', 'wevtutil.exe', None],
    'is_tampered': [0, 0, 0, 1, 0]
})

def test_extract_features_adds_all_8_columns():
    result = extract_features(SAMPLE_DATA.copy())
    expected = ['delta_t', 'event_frequency',
                'hour_of_day', 'is_business_hours',
                'event_id_encoded', 'is_critical_event',
                'log_burst', 'process_is_suspicious']
    for col in expected:
        assert col in result.columns, f"Missing: {col}"

def test_delta_t_first_row_is_zero():
    result = extract_features(SAMPLE_DATA.copy())
    assert result['delta_t'].iloc[0] == 0.0

def test_delta_t_is_non_negative():
    result = extract_features(SAMPLE_DATA.copy())
    assert (result['delta_t'] >= 0).all()

def test_is_critical_event_flags_1102():
    result = extract_features(SAMPLE_DATA.copy())
    critical_rows = result[result['event_id'] == 1102]
    assert len(critical_rows) > 0
    assert critical_rows['is_critical_event'].iloc[0] == 1

def test_is_critical_event_does_not_flag_normal():
    result = extract_features(SAMPLE_DATA.copy())
    normal_rows = result[result['event_id'] == 4624]
    assert normal_rows['is_critical_event'].iloc[0] == 0

def test_process_is_suspicious_detects_wevtutil():
    result = extract_features(SAMPLE_DATA.copy())
    wev_rows = result[
        result['process_name'] == 'wevtutil.exe']
    assert wev_rows['process_is_suspicious'].iloc[0] == 1

def test_is_business_hours_binary():
    result = extract_features(SAMPLE_DATA.copy())
    assert result['is_business_hours'].isin([0,1]).all()

def test_event_id_encoded_known_values():
    result = extract_features(SAMPLE_DATA.copy())
    row_1102 = result[result['event_id'] == 1102]
    assert row_1102['event_id_encoded'].iloc[0] == 1
    row_4624 = result[result['event_id'] == 4624]
    assert row_4624['event_id_encoded'].iloc[0] == 3

def test_null_process_handled_gracefully():
    result = extract_features(SAMPLE_DATA.copy())
    assert result['process_is_suspicious'].isnull().sum() == 0


def test_streaming_feature_extractor_adds_all_columns():
    from src.features import StreamingFeatureExtractor
    extractor = StreamingFeatureExtractor()
    sample_ev = {
        'event_id': 4624,
        'time_created': '2026-08-25T08:00:00+00:00',
        'process_name': 'lsass.exe'
    }
    enriched = extractor.extract_single(sample_ev)
    expected = ['delta_t', 'event_frequency', 'hour_of_day', 'is_business_hours',
                'event_id_encoded', 'is_critical_event', 'log_burst', 'process_is_suspicious']
    for col in expected:
        assert col in enriched, f"Missing streaming feature: {col}"
    assert enriched['delta_t'] == 0.0
    assert enriched['event_frequency'] == 1
    assert enriched['event_id_encoded'] == 3


def test_streaming_delta_t_and_frequency_tracking():
    from src.features import StreamingFeatureExtractor
    extractor = StreamingFeatureExtractor(window_seconds=60.0)
    ev1 = {'event_id': 4624, 'time_created': '2026-08-25T08:00:00+00:00', 'process_name': 'lsass.exe'}
    ev2 = {'event_id': 4625, 'time_created': '2026-08-25T08:00:05+00:00', 'process_name': 'lsass.exe'}
    res1 = extractor.extract_single(ev1)
    res2 = extractor.extract_single(ev2)
    assert res1['delta_t'] == 0.0
    assert res2['delta_t'] == 5.0
    assert res2['event_frequency'] == 2


def test_streaming_critical_and_suspicious_flags():
    from src.features import StreamingFeatureExtractor
    extractor = StreamingFeatureExtractor()
    ev = {'event_id': 1102, 'time_created': '2026-08-25T08:00:00+00:00', 'process_name': 'wevtutil.exe'}
    res = extractor.extract_single(ev)
    assert res['is_critical_event'] == 1
    assert res['process_is_suspicious'] == 1

