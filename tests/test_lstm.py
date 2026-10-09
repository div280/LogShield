"""
test_lstm.py -- Unit tests for LogShield LSTM Autoencoder sequence model.
Fast unit tests with synthetic and sampled event sequences.
"""
import os
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta

from src.models.lstm_model import (
    build_features,
    make_windows,
    build_model,
    load_lstm,
    predict_lstm,
    WINDOW_SIZE,
    CONT_FEATURES
)


def _create_synthetic_clean_df(n_rows: int = 50, source_file: str = "test_clean.evtx") -> pd.DataFrame:
    """Helper to generate ordered clean log DataFrame."""
    base_time = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(n_rows):
        records.append({
            'source_file': source_file,
            'event_record_id': 1000 + i,
            'event_id': 4624 if i % 2 == 0 else 4688,
            'time_created': (base_time + timedelta(seconds=i * 2)).isoformat(),
            'attack_type': 'normal',
            'is_tampered': 0
        })
    return pd.DataFrame(records)


def test_feature_builder_keeps_order_and_handles_negative_dt():
    """Verify build_features maintains file order and handles negative dt."""
    # Synthetic DataFrame with an intentional timestamp inversion (shuffle)
    base_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    df = pd.DataFrame([
        {'source_file': 'f1.evtx', 'event_record_id': 1, 'event_id': 4624, 'time_created': base_time.isoformat()},
        {'source_file': 'f1.evtx', 'event_record_id': 2, 'event_id': 4688, 'time_created': (base_time + timedelta(seconds=10)).isoformat()},
        # Negative dt (time went backwards by 5 seconds):
        {'source_file': 'f1.evtx', 'event_record_id': 3, 'event_id': 4625, 'time_created': (base_time + timedelta(seconds=5)).isoformat()},
        # New file boundary:
        {'source_file': 'f2.evtx', 'event_record_id': 10, 'event_id': 4624, 'time_created': base_time.isoformat()}
    ])

    df_feat, id_map = build_features(df)

    assert len(df_feat) == 4
    # First row of each file has dt=0
    assert df_feat['f_dt'].iloc[0] == 0.0
    assert df_feat['f_rid'].iloc[0] == 0.0
    # Second row has positive dt
    assert df_feat['f_dt'].iloc[1] > 0.0
    # Third row has negative dt
    assert df_feat['f_dt'].iloc[2] < 0.0
    # Fourth row is new file -> dt reset to 0
    assert df_feat['f_dt'].iloc[3] == 0.0


def test_windows_never_cross_source_file_boundaries():
    """Ensure sliding windows are confined within individual source_files."""
    df1 = _create_synthetic_clean_df(n_rows=15, source_file="file_a.evtx")
    df2 = _create_synthetic_clean_df(n_rows=12, source_file="file_b.evtx")
    df = pd.concat([df1, df2], ignore_index=True)

    df_feat, _ = build_features(df)
    X_cont, X_eid, y_win, meta = make_windows(df_feat, W=10)

    # df1 has 15 rows -> 6 windows (15 - 10 + 1)
    # df2 has 12 rows -> 3 windows (12 - 10 + 1)
    # Total windows = 9
    assert len(X_cont) == 9
    assert len(meta) == 9

    file_a_meta = [m for m in meta if m[0] == "file_a.evtx"]
    file_b_meta = [m for m in meta if m[0] == "file_b.evtx"]
    assert len(file_a_meta) == 6
    assert len(file_b_meta) == 3


def test_windows_with_critical_events_are_skipped():
    """Verify windows containing critical_event rows are excluded."""
    df = _create_synthetic_clean_df(n_rows=20, source_file="crit_test.evtx")
    # Mark row index 5 as critical event
    df.loc[5, 'attack_type'] = 'critical_event'
    df.loc[5, 'event_id'] = 1102

    df_feat, _ = build_features(df)
    X_cont, X_eid, y_win, meta = make_windows(df_feat, W=10)

    # 20 rows would normally yield 11 windows (0..10 to 10..20)
    # Windows covering index 5: starts at 0, 1, 2, 3, 4, 5 (6 windows contain row 5)
    # Valid remaining windows: 11 - 6 = 5 windows
    assert len(X_cont) == 5
    for src, start_idx, end_idx in meta:
        assert not (start_idx <= 5 < end_idx), "Window contains critical event!"


def test_model_builds_and_predicts_correct_shapes():
    """Verify Keras model construction and forward pass output shapes."""
    n_ids = 50
    W = 10
    model = build_model(n_ids=n_ids, W=W, cont_dim=3)

    batch_size = 4
    dummy_eid = np.random.randint(0, n_ids, size=(batch_size, W), dtype=np.int32)
    dummy_cont = np.random.randn(batch_size, W, 3).astype(np.float32)

    output = model([dummy_eid, dummy_cont], training=False)
    assert output.shape == (batch_size, W, 3)


def test_load_lstm_raises_clean_error_when_files_missing():
    """Verify load_lstm fails closed with clean RuntimeError on missing files."""
    with pytest.raises(RuntimeError) as exc_info:
        load_lstm('models_saved/non_existent_model.keras', 'models_saved/non_existent_meta.pkl')
    assert "LogShield LSTM model unavailable" in str(exc_info.value)


def test_predict_lstm_returns_flags_and_handles_short_file():
    """Verify predict_lstm works and handles files with < 10 rows safely."""
    # Construct a small mock model and meta
    n_ids = 20
    model = build_model(n_ids=n_ids, W=10, cont_dim=3)
    meta = {
        'id_map': {4624: 1, 4688: 2},
        'threshold': 0.5,
        'window_size': 10,
        'continuous_features': CONT_FEATURES
    }

    # 1. Short file (< 10 rows)
    short_df = _create_synthetic_clean_df(n_rows=5, source_file="short.evtx")
    result_short = predict_lstm(short_df, model=model, meta=meta)
    assert 'lstm_flag' in result_short.columns
    assert 'lstm_score' in result_short.columns
    assert (result_short['lstm_flag'] == 0).all()
    assert (result_short['lstm_score'] == 0.0).all()

    # 2. Normal file (>= 10 rows)
    normal_df = _create_synthetic_clean_df(n_rows=25, source_file="normal.evtx")
    result_normal = predict_lstm(normal_df, model=model, meta=meta)
    assert 'lstm_flag' in result_normal.columns
    assert 'lstm_score' in result_normal.columns
    assert len(result_normal) == 25
    assert not result_normal['lstm_score'].isna().any()


def test_clean_sample_vs_shuffled_sample_detection():
    """Verify clean sequence has low reconstruction error vs shuffled sequence."""
    base_time = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(40):
        records.append({
            'source_file': 'ordered.evtx',
            'event_record_id': 100 + i,
            'event_id': 4624,
            'time_created': (base_time + timedelta(seconds=i * 5)).isoformat(),
            'attack_type': 'normal',
            'is_tampered': 0
        })
    df_clean = pd.DataFrame(records)

    # Shuffled version
    df_shuf = df_clean.copy()
    df_shuf['source_file'] = 'shuffled.evtx'
    # Invert rows 10 to 25
    shuf_indices = list(range(10, 25))
    df_shuf.loc[shuf_indices, 'time_created'] = df_shuf.loc[shuf_indices, 'time_created'].values[::-1]
    df_shuf.loc[shuf_indices, 'event_record_id'] = df_shuf.loc[shuf_indices, 'event_record_id'].values[::-1]

    df_clean_feat, id_map = build_features(df_clean)
    df_shuf_feat, _ = build_features(df_shuf, id_map=id_map)

    X_c_clean, X_e_clean, _, _ = make_windows(df_clean_feat, W=10)
    X_c_shuf, X_e_shuf, _, _ = make_windows(df_shuf_feat, W=10)

    # Build model and train quickly on clean sequence
    model = build_model(n_ids=len(id_map), W=10, cont_dim=3)
    model.fit([X_e_clean, X_c_clean], X_c_clean, epochs=10, batch_size=16, verbose=0)

    pred_clean = model.predict([X_e_clean, X_c_clean], verbose=0)
    pred_shuf = model.predict([X_e_shuf, X_c_shuf], verbose=0)

    mse_clean = np.mean((pred_clean - X_c_clean)**2, axis=(1, 2))
    mse_shuf = np.mean((pred_shuf - X_c_shuf)**2, axis=(1, 2))

    # Mean error of shuffled windows containing the anomaly should be significantly higher
    assert np.max(mse_shuf) > np.mean(mse_clean)
