"""Integration test: parse full clean CSV via bytes pipeline."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.parser import parse_csv_from_bytes, MAX_FILE_SIZE
from src.features import extract_features
from src.hmac_chain import verify_hmac_chain, check_chain_continuity
from src.models.isolation_forest import predict_anomalies

CLEAN_CSV = (
    r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
    r'\logshield_master_clean.csv')


def test_full_clean_csv_upload_pipeline():
    if not os.path.exists(CLEAN_CSV):
        import pytest
        pytest.skip('Clean CSV not available on this machine')
    size = os.path.getsize(CLEAN_CSV)
    assert size <= MAX_FILE_SIZE
    with open(CLEAN_CSV, 'rb') as handle:
        data = handle.read()
    df = parse_csv_from_bytes(data)
    assert len(df) > 190000
    df = extract_features(df)
    df = predict_anomalies(
        df, 'models_saved/isolation_forest.pkl')
    assert 'if_flag' in df.columns


def test_master_clean_hmac_baseline_pass():
    """Uploading the master baseline must show intact HMAC chain."""
    if not os.path.exists(CLEAN_CSV):
        import pytest
        pytest.skip('Clean CSV not available on this machine')
    with open(CLEAN_CSV, 'rb') as handle:
        data = handle.read()
    df = parse_csv_from_bytes(data)
    df = extract_features(df)
    verified = verify_hmac_chain(
        df, 'models_saved/hmac_chain.json')
    continuity = check_chain_continuity(
        df, 'models_saved/hmac_chain.json')
    assert int(verified['hmac_flag'].sum()) == 0
    assert continuity['missing_records'] == 0
    assert continuity['extra_records'] == 0
    assert continuity['gap_detected'] is False
    assert continuity['injection_detected'] is False


def test_master_clean_isolation_forest_count():
    """IF anomaly count must remain stable after chain rebuild."""
    if not os.path.exists(CLEAN_CSV):
        import pytest
        pytest.skip('Clean CSV not available on this machine')
    with open(CLEAN_CSV, 'rb') as handle:
        data = handle.read()
    df = parse_csv_from_bytes(data)
    df = extract_features(df)
    df = predict_anomalies(
        df, 'models_saved/isolation_forest.pkl')
    anomalies = int(df['if_flag'].sum())
    assert 11000 <= anomalies <= 13000


if __name__ == '__main__':
    t0 = time.time()
    test_full_clean_csv_upload_pipeline()
    test_master_clean_hmac_baseline_pass()
    print('UPLOAD PIPELINE TEST: PASS')
    print(f'Elapsed: {time.time()-t0:.1f}s')
