import pytest
import pandas as pd
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))
from src.hmac_chain import (
    build_hmac_chain,
    verify_hmac_chain,
    check_chain_continuity,
    check_baseline_row_count,
    get_chain_record_count,
    _compute_record_hmac,
    _record_to_content_string)
from src.features import extract_features

SAMPLE_DATA = pd.DataFrame({
    'event_record_id': [1, 2, 3, 4, 5],
    'event_id': [4624, 4625, 4688, 1102, 4663],
    'time_created': pd.to_datetime([
        '2026-08-25 08:00:00+00:00',
        '2026-08-25 08:00:02+00:00',
        '2026-08-25 08:00:05+00:00',
        '2026-08-25 08:00:10+00:00',
        '2026-08-25 08:00:15+00:00'
    ]),
    'computer': ['WIN-TEST'] * 5,
    'channel': ['Security'] * 5,
    'is_tampered': [0, 0, 0, 1, 0]
})

def test_build_chain_creates_file(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    result = build_hmac_chain(
        SAMPLE_DATA.copy(), chain_path)
    assert os.path.exists(chain_path)
    assert result['total_records'] == 5

def test_build_chain_returns_correct_count(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    result = build_hmac_chain(
        SAMPLE_DATA.copy(), chain_path)
    assert result['total_records'] == len(SAMPLE_DATA)

def test_verify_clean_data_passes(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    result = verify_hmac_chain(
        SAMPLE_DATA.copy(), chain_path)
    assert 'hmac_flag' in result.columns
    assert 'hmac_verified' in result.columns

def test_verify_detects_modified_record(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    tampered = SAMPLE_DATA.copy()
    tampered.loc[0, 'event_id'] = 9999
    result = verify_hmac_chain(tampered, chain_path)
    assert result['hmac_flag'].sum() > 0

def test_continuity_detects_deleted_record(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    deleted = SAMPLE_DATA.drop(index=2).copy()
    result = check_chain_continuity(
        deleted, chain_path)
    assert result['gap_detected'] == True
    assert result['missing_records'] > 0

def test_continuity_detects_injected_record(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    injected = SAMPLE_DATA.copy()
    new_row = SAMPLE_DATA.iloc[0].copy()
    new_row['event_record_id'] = 999
    injected = pd.concat(
        [injected, new_row.to_frame().T],
        ignore_index=True)
    result = check_chain_continuity(
        injected, chain_path)
    assert result['injection_detected'] == True

def test_hmac_is_deterministic():
    key = b'test_key'
    h1 = _compute_record_hmac('content', 'prev', key)
    h2 = _compute_record_hmac('content', 'prev', key)
    assert h1 == h2

def test_hmac_changes_with_content():
    key = b'test_key'
    h1 = _compute_record_hmac('content_a', 'prev', key)
    h2 = _compute_record_hmac('content_b', 'prev', key)
    assert h1 != h2


def test_baseline_mismatch_detects_large_row_gap(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    result = check_baseline_row_count(100, chain_path)
    assert result['mismatch'] is True
    assert 'baseline' in result['message'].lower()


def test_baseline_match_on_same_row_count(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    build_hmac_chain(SAMPLE_DATA.copy(), chain_path)
    result = check_baseline_row_count(len(SAMPLE_DATA), chain_path)
    assert result['mismatch'] is False


def test_chain_count_matches_after_feature_extraction(tmp_path):
    chain_path = str(tmp_path / "test_chain.json")
    featured = extract_features(SAMPLE_DATA.copy())
    build_hmac_chain(featured, chain_path)
    verified = verify_hmac_chain(
        extract_features(SAMPLE_DATA.copy()), chain_path)
    assert int(verified['hmac_flag'].sum()) == 0
    assert get_chain_record_count(chain_path) == len(SAMPLE_DATA)
