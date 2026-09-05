import pytest
import pandas as pd
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))
from src.parser import parse_csv_file, parse_csv_from_bytes, validate_dataframe
import tempfile

SAMPLE_DATA = pd.DataFrame({
    'source_file': ['Security.evtx'] * 5,
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
    'provider': ['Microsoft-Windows-Security'] * 5,
    'channel': ['Security'] * 5,
    'level': [0] * 5,
    'task': [0] * 5,
    'account_name': ['testuser', None, 'testuser',
                     'SYSTEM', 'testuser'],
    'process_name': ['lsass.exe', 'lsass.exe',
                     'cmd.exe', 'wevtutil.exe', None],
    'event_data': [''] * 5,
    'raw_xml_length': [500] * 5,
    'is_tampered': [0, 0, 0, 1, 0]
})

def test_validate_dataframe_passes_on_valid_data():
    assert validate_dataframe(SAMPLE_DATA) == True

def test_validate_dataframe_fails_on_missing_columns():
    bad_df = SAMPLE_DATA.drop(columns=['event_id'])
    with pytest.raises(ValueError):
        validate_dataframe(bad_df)

def test_parse_csv_returns_dataframe(tmp_path):
    csv_path = tmp_path / "test.csv"
    SAMPLE_DATA.to_csv(csv_path, index=False)
    result = parse_csv_file(str(csv_path))
    assert isinstance(result, pd.DataFrame)

def test_parse_csv_has_required_columns(tmp_path):
    csv_path = tmp_path / "test.csv"
    SAMPLE_DATA.to_csv(csv_path, index=False)
    result = parse_csv_file(str(csv_path))
    for col in ['event_id','time_created',
                'computer','is_tampered']:
        assert col in result.columns

def test_null_account_name_filled(tmp_path):
    csv_path = tmp_path / "test.csv"
    SAMPLE_DATA.to_csv(csv_path, index=False)
    result = parse_csv_file(str(csv_path))
    assert result['account_name'].isnull().sum() == 0

def test_null_process_name_filled(tmp_path):
    csv_path = tmp_path / "test.csv"
    SAMPLE_DATA.to_csv(csv_path, index=False)
    result = parse_csv_file(str(csv_path))
    assert result['process_name'].isnull().sum() == 0

def test_wrong_format_rejected(tmp_path):
    bad_file = tmp_path / "test.exe"
    bad_file.write_bytes(b'fake binary')
    with pytest.raises(ValueError):
        parse_csv_file(str(bad_file))

def test_path_traversal_blocked(tmp_path):
    malicious_path = "../../../etc/passwd"
    with pytest.raises((ValueError, FileNotFoundError,
                        OSError)):
        parse_csv_file(malicious_path)

def test_parse_csv_from_bytes():
    csv_bytes = SAMPLE_DATA.to_csv(index=False).encode('utf-8')
    result = parse_csv_from_bytes(csv_bytes)
    assert isinstance(result, pd.DataFrame)
    assert len(result) == 5
    for col in ['event_id', 'time_created', 'computer', 'is_tampered']:
        assert col in result.columns
    assert result['account_name'].isnull().sum() == 0
    assert result['process_name'].isnull().sum() == 0

