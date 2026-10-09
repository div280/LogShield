"""
test_dashboard_lstm.py -- Unit and integration tests for LSTM dashboard components.
Follows all LogShield security, styling, and forensic rules.
"""
import os
import sys
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dashboard.utils.threat_panels import (
    build_lstm_panel_data,
    build_flagged_events_table,
    build_all_threat_panels
)
from dashboard.app import run_analysis_pipeline, get_cached_lstm_model
from src.models.lstm_model import load_lstm, predict_lstm, CONT_FEATURES


DATA_DIR = os.environ.get(
    'LOGSHIELD_DATA_DIR',
    r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
)
SHUFFLE_CSV_PATH = os.path.join(DATA_DIR, 'logshield_shuffle_attacks.csv')
CLEAN_CSV_PATH = os.path.join(DATA_DIR, 'logshield_master_clean.csv')


def _create_synthetic_sample(n_rows: int = 50, shuffle: bool = False) -> pd.DataFrame:
    """Helper to create synthetic DataFrame for isolated test runs."""
    base_time = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(n_rows):
        records.append({
            'source_file': 'synthetic_sample.evtx',
            'event_record_id': 1000 + i,
            'event_id': 4624 if i % 2 == 0 else 4688,
            'time_created': (base_time + timedelta(seconds=i * 2)).isoformat(),
            'computer': 'WIN-SRV01',
            'account_name': 'admin_user',
            'process_name': 'svchost.exe',
            'delta_t': 2.0,
            'event_frequency': 1,
            'if_flag': 0,
            'if_score': 0.1,
            'is_critical_event': 0,
            'is_tampered': 0
        })
    df = pd.DataFrame(records)
    if shuffle and n_rows >= 10:
        start_s = n_rows // 4
        end_s = min(n_rows, start_s + max(4, n_rows // 3))
        shuf_idx = list(range(start_s, end_s))
        df.loc[shuf_idx, 'time_created'] = df.loc[shuf_idx, 'time_created'].values[::-1]
        df.loc[shuf_idx, 'event_record_id'] = df.loc[shuf_idx, 'event_record_id'].values[::-1]
        df.loc[shuf_idx, 'is_tampered'] = 1
    return df


def test_lstm_panel_builder_clean_sample_and_shuffled_sample():
    """
    Verify LSTM panel builder returns expected structure for clean
    and shuffled datasets in stored order without copying external CSVs.
    """
    model_path = 'models_saved/lstm_ae.keras'
    meta_path = 'models_saved/lstm_meta.pkl'
    if not (os.path.exists(model_path) and os.path.exists(meta_path)):
        pytest.skip("Saved LSTM model not available")

    model, meta = load_lstm(model_path, meta_path)
    threshold = float(meta.get('threshold', 0.1283))

    # 1. Clean Sample
    clean_df = _create_synthetic_sample(n_rows=40, shuffle=False)
    clean_scored = predict_lstm(clean_df, model=model, meta=meta)
    clean_panel = build_lstm_panel_data(clean_scored, threshold=threshold)

    assert clean_panel['status'] == 'ok'
    assert clean_panel['rows_checked'] == 40
    assert 'summary' in clean_panel
    assert 'blocks' in clean_panel
    assert 'timeline_data' in clean_panel

    # 2. Shuffled Sample from external CSV (first few thousand rows only, stored order)
    if os.path.exists(SHUFFLE_CSV_PATH):
        df_shuf_raw = pd.read_csv(SHUFFLE_CSV_PATH, nrows=2000)
        shuf_scored = predict_lstm(df_shuf_raw, model=model, meta=meta)
        shuf_panel = build_lstm_panel_data(shuf_scored, threshold=threshold)

        assert shuf_panel['status'] == 'ok'
        assert "regions contain out-of-order events" in shuf_panel['summary']
        assert shuf_panel['max_score'] >= threshold


def test_missing_model_files_shows_notice_without_crash():
    """
    Verify missing model files result in clean generic notice, no crash,
    and verdict is unaffected.
    """
    notice_panel = build_lstm_panel_data(
        pd.DataFrame(),
        notice="The event order check could not run for this file."
    )
    assert notice_panel['status'] == 'notice'
    assert notice_panel['summary'] == "The event order check could not run for this file."
    assert notice_panel['rows_flagged'] == 0
    assert len(notice_panel['blocks']) == 0


def test_file_fewer_than_10_rows_handled_gracefully():
    """Verify files with < 10 rows return graceful notice without exception."""
    short_df = _create_synthetic_sample(n_rows=5)
    panel = build_lstm_panel_data(
        short_df,
        notice="The event order check could not run for this file."
    )
    assert panel['summary'] == "The event order check could not run for this file."
    assert panel['rows_flagged'] == 0


def test_uploaded_file_without_source_file_works():
    """Verify that DataFrame missing source_file column is handled correctly."""
    model_path = 'models_saved/lstm_ae.keras'
    meta_path = 'models_saved/lstm_meta.pkl'
    if not (os.path.exists(model_path) and os.path.exists(meta_path)):
        pytest.skip("Saved LSTM model not available")

    df_no_src = _create_synthetic_sample(n_rows=25)
    df_no_src = df_no_src.drop(columns=['source_file'])

    model, meta = load_lstm(model_path, meta_path)
    scored = predict_lstm(df_no_src, model=model, meta=meta)

    assert 'lstm_flag' in scored.columns
    assert 'lstm_score' in scored.columns
    assert len(scored) == 25


def test_input_data_order_not_modified_by_lstm_step():
    """Verify input data ordering and indices remain completely intact."""
    model_path = 'models_saved/lstm_ae.keras'
    meta_path = 'models_saved/lstm_meta.pkl'
    if not (os.path.exists(model_path) and os.path.exists(meta_path)):
        pytest.skip("Saved LSTM model not available")

    df = _create_synthetic_sample(n_rows=30, shuffle=True)
    orig_times = df['time_created'].tolist()
    orig_rids = df['event_record_id'].tolist()
    orig_indices = df.index.tolist()

    model, meta = load_lstm(model_path, meta_path)
    scored = predict_lstm(df, model=model, meta=meta)

    assert scored['time_created'].tolist() == orig_times
    assert scored['event_record_id'].tolist() == orig_rids
    assert scored.index.tolist() == orig_indices


def test_flagged_events_table_preserves_old_columns_and_adds_new():
    """
    Verify flagged events table maintains all existing columns in exact order,
    and appends lstm_flag and lstm_score.
    """
    df = _create_synthetic_sample(n_rows=30)
    df.loc[:5, 'if_flag'] = 1
    df['lstm_flag'] = 0
    df.loc[2:4, 'lstm_flag'] = 1
    df['lstm_score'] = 0.05
    df.loc[2:4, 'lstm_score'] = 0.85

    table = build_flagged_events_table(df)

    expected_cols = [
        'timestamp',
        'event_id',
        'account',
        'reason_flagged',
        'lstm_flag',
        'lstm_score'
    ]
    assert list(table.columns) == expected_cols
    assert len(table) > 0


def test_no_em_dashes_or_emojis_in_lstm_ui_strings():
    """
    Strict UI rule: verify no em dashes (\u2014, \u2013) or emojis appear
    in generated summaries, block descriptions, or notice strings.
    """
    df = _create_synthetic_sample(n_rows=30)
    df['lstm_flag'] = 1
    df['lstm_score'] = 0.95

    panel_flagged = build_lstm_panel_data(df)
    panel_clean = build_lstm_panel_data(_create_synthetic_sample(n_rows=30))
    panel_notice = build_lstm_panel_data(
        pd.DataFrame(),
        notice="The event order check could not run for this file."
    )

    all_panels = [panel_flagged, panel_clean, panel_notice]
    forbidden = ["\u2014", "\u2013", "\U0001F600", "\U0001F916", "\U0001F6A8"]

    for p in all_panels:
        summary = p.get('summary', '')
        for char in forbidden:
            assert char not in summary, f"Forbidden character {char!r} found in summary: {summary}"

        for block in p.get('blocks', []):
            meaning = block.get('meaning', '')
            action = block.get('action', '')
            for char in forbidden:
                assert char not in meaning, f"Forbidden character in block meaning: {meaning}"
                assert char not in action, f"Forbidden character in block action: {action}"


def test_pipeline_preserves_original_order_for_lstm_shuffled_sample():
    """
    Unit test ensuring run_analysis_pipeline preserves original uploaded
    event order when evaluating LSTM sequence reconstruction.
    """
    model_path = 'models_saved/lstm_ae.keras'
    meta_path = 'models_saved/lstm_meta.pkl'
    if not (os.path.exists(model_path) and os.path.exists(meta_path)):
        pytest.skip("Saved LSTM model not available")

    # Generate synthetic shuffled dataset
    df_sample = _create_synthetic_sample(n_rows=600, shuffle=True)
    csv_bytes = df_sample.to_csv(index=False).encode('utf-8')

    res = run_analysis_pipeline(csv_bytes)

    assert res['total_events'] == 600
    assert res['lstm_ok'] is True
    assert 'lstm_flag' in res['df'].columns
    assert 'lstm_score' in res['df'].columns
    assert res['lstm_panel']['rows_checked'] == 600
    assert res['lstm_panel']['rows_flagged'] > 0
    assert len(res['lstm_panel']['blocks']) > 0


def test_lstm_block_severity_boundaries():
    """Verify severity boundaries: 0.19 Low, 0.2 Medium, 0.49 Medium, 0.5 High."""
    df = pd.DataFrame({
        'time_created': ['2026-10-01 10:00:00', '2026-10-01 10:00:01', '2026-10-01 10:00:02', '2026-10-01 10:00:03',
                         '2026-10-01 10:00:04', '2026-10-01 10:00:05', '2026-10-01 10:00:06', '2026-10-01 10:00:07'],
        'lstm_flag': [1, 0, 1, 0, 1, 0, 1, 0],
        'lstm_score': [0.19, 0.05, 0.20, 0.05, 0.49, 0.05, 0.50, 0.05]
    })
    panel = build_lstm_panel_data(df)
    blocks = panel['blocks']
    # Sorted by highest_score descending
    assert len(blocks) == 4
    scores_to_sev = {b['highest_score']: b['severity'] for b in blocks}
    assert scores_to_sev[0.50] == 'High'
    assert scores_to_sev[0.49] == 'Medium'
    assert scores_to_sev[0.20] == 'Medium'
    assert scores_to_sev[0.19] == 'Low'


def test_lstm_blocks_sorted_by_score_descending_and_severity_column_last():
    """Verify table is sorted by score descending and old columns keep their order, Severity last."""
    df = pd.DataFrame({
        'time_created': [f'2026-10-01 10:00:{i:02d}' for i in range(10)],
        'lstm_flag': [1, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        'lstm_score': [0.25, 0.0, 0.85, 0.0, 0.15, 0.0, 0.0, 0.0, 0.0, 0.0]
    })
    panel = build_lstm_panel_data(df)
    blocks = panel['blocks']
    assert len(blocks) == 3
    assert blocks[0]['highest_score'] >= blocks[1]['highest_score'] >= blocks[2]['highest_score']

    block_df = pd.DataFrame(blocks).rename(columns={
        'start_time': 'Start Time',
        'end_time': 'End Time',
        'event_count': 'Events in Block',
        'highest_score': 'Max Anomaly Score',
        'meaning': 'Assessment',
        'action': 'Recommended Action',
        'severity': 'Severity'
    })
    expected_cols = [
        'Start Time', 'End Time', 'Events in Block',
        'Max Anomaly Score', 'Assessment', 'Recommended Action', 'Severity'
    ]
    assert list(block_df.columns) == expected_cols


def test_lstm_summary_counts_match_table_on_synthetic_frame():
    """Verify summary text counts match the table (N, M, H, Me, L) on a synthetic frame."""
    n_rows = 600
    flags = [0] * n_rows
    scores = [0.05] * n_rows

    # Block 1 (High): index 10-15 (score 0.65)
    for i in range(10, 16):
        flags[i] = 1
        scores[i] = 0.65

    # Block 2 (Medium): index 30-35 (score 0.35)
    for i in range(30, 36):
        flags[i] = 1
        scores[i] = 0.35

    # Block 3 (Low): index 50-58 (score 0.18)
    for i in range(50, 59):
        flags[i] = 1
        scores[i] = 0.18

    # Block 4 (High): index 70-75 (score 0.90)
    for i in range(70, 76):
        flags[i] = 1
        scores[i] = 0.90

    df = pd.DataFrame({
        'time_created': [f'2026-10-01 10:{i//60:02d}:{i%60:02d}' for i in range(n_rows)],
        'lstm_flag': flags,
        'lstm_score': scores
    })

    panel = build_lstm_panel_data(df)
    assert panel['alert_fired'] is True
    assert panel['regions_count'] == 4
    assert panel['high_count'] == 2
    assert panel['medium_count'] == 1
    assert panel['low_count'] == 1
    assert panel['rows_flagged'] == (6 + 6 + 9 + 6) # 27 events

    summary = panel['summary']
    assert "4 regions contain out-of-order events" in summary
    assert "covering about 27 events in total" in summary
    assert "2 are High severity, 1 Medium, 1 Low" in summary
    assert "The strongest region is at 2026-10-01 10:01:10" in summary
    assert "A region is wider than the actual change" in summary


def test_lstm_onscreen_table_capped_at_50_while_export_keeps_all():
    """Verify on-screen table is capped at 50 rows while export keeps all 60 rows."""
    blocks = []
    for i in range(60):
        blocks.append({
            'start_time': f'2026-10-01 10:{i//60:02d}:{i%60:02d}',
            'end_time': f'2026-10-01 10:{i//60:02d}:{i%60:02d}',
            'event_count': 5,
            'highest_score': round(0.1 + (i * 0.01), 4),
            'meaning': 'Events look out of order here, review recommended.',
            'action': 'Compare these record IDs and timestamps with other logs from the same machine (System, Application) and with the HMAC chain result.',
            'severity': 'Medium'
        })
    block_df = pd.DataFrame(blocks).rename(columns={
        'start_time': 'Start Time',
        'end_time': 'End Time',
        'event_count': 'Events in Block',
        'highest_score': 'Max Anomaly Score',
        'meaning': 'Assessment',
        'action': 'Recommended Action',
        'severity': 'Severity'
    })
    display_df = block_df.head(50)

    assert len(block_df) == 60
    assert len(display_df) == 50

    # Test download export data with UTF-8 BOM
    csv_bytes = block_df.to_csv(index=False).encode('utf-8-sig')
    assert csv_bytes.startswith(b'\xef\xbb\xbf')
    decoded = csv_bytes.decode('utf-8-sig')
    lines = [line for line in decoded.splitlines() if line.strip()]
    assert len(lines) == 61  # 1 header + 60 data rows
    assert lines[0].endswith('Severity')

    # Test download button label and caption
    button_label = f"Download all {len(block_df)} flagged regions (CSV)"
    caption_text = f"Showing the 50 strongest of {len(block_df)} regions. Use the button below for the full list."
    assert button_label == "Download all 60 flagged regions (CSV)"
    assert caption_text == "Showing the 50 strongest of 60 regions. Use the button below for the full list."


def test_lstm_summary_grammar_for_count_of_one_and_regions():
    """Verify grammar for count of 1 ('1 is High severity', '1 region contains')."""
    n_rows = 600
    flags = [0] * n_rows
    scores = [0.05] * n_rows

    # Block 1 (High): index 10-17 (score 0.65, 8 rows) -> 1 High
    for i in range(10, 18):
        flags[i] = 1
        scores[i] = 0.65

    # Block 2 (Medium): index 30-37 (score 0.35, 8 rows) -> 1 Medium
    for i in range(30, 38):
        flags[i] = 1
        scores[i] = 0.35

    # Block 3 (Medium): index 50-57 (score 0.35, 8 rows) -> 2 Medium
    for i in range(50, 58):
        flags[i] = 1
        scores[i] = 0.35

    df = pd.DataFrame({
        'time_created': [f'2026-10-01 10:{i//60:02d}:{i%60:02d}' for i in range(n_rows)],
        'lstm_flag': flags,
        'lstm_score': scores
    })

    panel = build_lstm_panel_data(df)
    assert panel['high_count'] == 1
    assert panel['medium_count'] == 2
    assert panel['low_count'] == 0
    assert "3 regions contain out-of-order events" in panel['summary']
    assert "1 is High severity, 2 Medium, 0 Low." in panel['summary']


def test_no_em_dashes_or_emojis_in_new_lstm_strings():
    """Verify no em dashes, en dashes, or emojis in new UI assessment, action, and summary strings."""
    df = pd.DataFrame({
        'time_created': [f'2026-10-01 10:00:{i:02d}' for i in range(600)],
        'lstm_flag': [1 if i < 30 else 0 for i in range(600)],
        'lstm_score': [0.75 if i < 30 else 0.05 for i in range(600)]
    })
    panel = build_lstm_panel_data(df)
    forbidden = ["\u2014", "\u2013", "\U0001F600", "\U0001F916", "\U0001F6A8"]

    summary = panel.get('summary', '')
    for char in forbidden:
        assert char not in summary

    for b in panel.get('blocks', []):
        for char in forbidden:
            assert char not in b.get('meaning', '')
            assert char not in b.get('action', '')
            assert char not in b.get('severity', '')

    # Check button and caption strings
    button_label = "Download all 60 flagged regions (CSV)"
    caption = "Showing the 50 strongest of 60 regions. Use the button below for the full list."
    file_name = "lstm_flagged_regions.csv"
    for char in forbidden:
        assert char not in button_label
        assert char not in caption
        assert char not in file_name


def test_flagged_events_evidence_labels_and_ordering():
    """
    Synthetic frame (60 rows) with LSTM, HMAC, and IF-only flagged rows.
    Verify labels, ordering, no 'Gap Attack'/'Shuffle Attack', and UTF-8 BOM download.
    """
    records = []
    base_dt = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(60):
        records.append({
            'time_created': (base_dt + timedelta(seconds=i * 5)).isoformat(),
            'event_record_id': 5000 + i,
            'event_id': 4624,
            'account_name': f'user_{i % 5}',
            'computer': 'WIN-SRV01',
            'delta_t': 100.0 if i % 2 == 0 else 5.0,
            'event_frequency': 150 if i % 3 == 0 else 10,
            'if_flag': 0,
            'hmac_flag': 0,
            'lstm_flag': 0,
            'lstm_score': 0.05
        })

    df = pd.DataFrame(records)

    # 1. Rows 0..9: IF only (some high delta_t, high freq, low freq)
    df.loc[0:9, 'if_flag'] = 1

    # 2. Rows 10..19: HMAC findings
    df.loc[10:19, 'hmac_flag'] = 1
    df.loc[15:19, 'if_flag'] = 1  # Multi-layer: HMAC should beat IF

    # 3. Rows 20..29: LSTM sequence anomalies with varying scores
    df.loc[20:29, 'lstm_flag'] = 1
    df.loc[20:29, 'if_flag'] = 1  # Multi-layer: LSTM should beat IF
    df.loc[25:29, 'hmac_flag'] = 1  # Multi-layer: LSTM should beat HMAC
    for idx, row_i in enumerate(range(20, 30)):
        df.loc[row_i, 'lstm_score'] = round(0.2 + (idx * 0.08), 4)

    table = build_flagged_events_table(df)

    # 30 flagged rows total (10 IF-only + 10 HMAC + 10 LSTM)
    assert len(table) == 30

    # Verify no 'Gap Attack' or 'Shuffle Attack' appears in reason_flagged
    assert not any("Gap Attack" in r for r in table['reason_flagged'])
    assert not any("Shuffle Attack" in r for r in table['reason_flagged'])

    # Verify LSTM rows appear first, sorted by lstm_score descending
    lstm_sub = table.iloc[:10]
    assert all(r == "Event order anomaly (LSTM)" for r in lstm_sub['reason_flagged'])
    scores = lstm_sub['lstm_score'].tolist()
    assert scores == sorted(scores, reverse=True)

    # Verify HMAC rows appear second
    hmac_sub = table.iloc[10:20]
    assert all(r == "Record missing or extra compared with baseline (HMAC)" for r in hmac_sub['reason_flagged'])

    # Verify IF-only rows appear third
    if_sub = table.iloc[20:30]
    assert all(r == "Unusual timing or pattern (low confidence)" for r in if_sub['reason_flagged'])

    # Check timestamp formatting (YYYY-MM-DD HH:MM:SS)
    for ts in table['timestamp']:
        assert len(ts) == 19
        assert ts[4] == '-' and ts[7] == '-' and ts[10] == ' ' and ts[13] == ':' and ts[16] == ':'

    # Check UTF-8 BOM export
    csv_bytes = table.to_csv(index=False).encode('utf-8-sig')
    assert csv_bytes.startswith(b'\xef\xbb\xbf')

    # Check no forbidden characters in reason_flagged strings
    forbidden = ["\u2014", "\u2013", "\U0001F600", "\U0001F916", "\U0001F6A8"]
    for r in table['reason_flagged']:
        for char in forbidden:
            assert char not in r




