import pytest
import pandas as pd
import numpy as np
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))
from src.tamper import (gap_attack, shuffle_attack,
                         injection_attack,
                         generate_labeled_dataset)

SAMPLE_DATA = pd.DataFrame({
    'event_id': list(range(4600, 4700)),
    'time_created': pd.date_range(
        '2026-08-25 08:00:00+00:00',
        periods=100, freq='2s'),
    'computer': ['WIN-TEST'] * 100,
    'account_name': ['user1'] * 100,
    'process_name': ['lsass.exe'] * 100,
    'event_data': [''] * 100,
    'source_file': ['Security.evtx'] * 100,
    'event_record_id': list(range(1, 101)),
    'provider': ['Microsoft'] * 100,
    'channel': ['Security'] * 100,
    'level': [0] * 100,
    'task': [0] * 100,
    'raw_xml_length': [500] * 100,
    'is_tampered': [0] * 100,
    'delta_t': [2.0] * 100,
    'event_frequency': [1] * 100,
    'hour_of_day': [8] * 100,
    'is_business_hours': [1] * 100,
    'event_id_encoded': [0] * 100,
    'is_critical_event': [0] * 100,
    'log_burst': [0] * 100,
    'process_is_suspicious': [0] * 100
})

def test_gap_attack_reduces_rows():
    result = gap_attack(SAMPLE_DATA.copy(),
                        gap_size=5, num_gaps=1,
                        random_seed=42)
    assert len(result) < len(SAMPLE_DATA)

def test_gap_attack_creates_tampered_labels():
    result = gap_attack(SAMPLE_DATA.copy(),
                        gap_size=5, num_gaps=1,
                        random_seed=42)
    assert result['is_tampered'].sum() > 0

def test_gap_attack_adds_tamper_type_column():
    result = gap_attack(SAMPLE_DATA.copy(),
                        gap_size=5, num_gaps=1,
                        random_seed=42)
    assert 'tamper_type' in result.columns

def test_shuffle_attack_same_row_count():
    result = shuffle_attack(SAMPLE_DATA.copy(),
                            window=20, num_windows=1,
                            random_seed=42)
    assert len(result) == len(SAMPLE_DATA)

def test_shuffle_attack_creates_tampered_labels():
    result = shuffle_attack(SAMPLE_DATA.copy(),
                            window=20, num_windows=1,
                            random_seed=42)
    assert result['is_tampered'].sum() > 0

def test_injection_attack_increases_rows():
    result = injection_attack(SAMPLE_DATA.copy(),
                              num_injections=10,
                              random_seed=42)
    assert len(result) > len(SAMPLE_DATA)

def test_injection_attack_creates_tampered_labels():
    result = injection_attack(SAMPLE_DATA.copy(),
                              num_injections=10,
                              random_seed=42)
    injected = result[result['tamper_type']=='injection']
    assert len(injected) == 10

def test_all_tampered_rows_have_tamper_type():
    df = gap_attack(SAMPLE_DATA.copy(),
                    gap_size=5, num_gaps=1)
    df = shuffle_attack(df, window=20, num_windows=1)
    df = injection_attack(df, num_injections=5)
    tampered = df[df['is_tampered']==1]
    assert tampered['tamper_type'].isnull().sum() == 0

def test_reproducibility_same_seed():
    r1 = gap_attack(SAMPLE_DATA.copy(), random_seed=42)
    r2 = gap_attack(SAMPLE_DATA.copy(), random_seed=42)
    assert len(r1) == len(r2)

def test_generate_labeled_dataset_saves_file(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "output.csv"
    SAMPLE_DATA.to_csv(input_path, index=False)
    result = generate_labeled_dataset(
        str(input_path), str(output_path))
    assert os.path.exists(str(output_path))
    assert len(result) > 0
