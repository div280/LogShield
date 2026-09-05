"""Tests for threat panel data builders."""
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dashboard.utils.threat_panels import (
    build_threat_map_data,
    build_processing_rate_data,
    build_classification_data,
    build_trend_data,
    build_knowledge_graph_data,
    build_all_threat_panels,
)


def _sample_df(n=200):
    times = pd.date_range(
        '2026-09-01 08:00:00', periods=n, freq='30s', tz='UTC')
    df = pd.DataFrame({
        'time_created': times,
        'event_id': np.random.choice(
            [4624, 4688, 1102, 4719], n),
        'account_name': np.random.choice(
            ['alice', 'bob', 'svc_admin'], n),
        'computer': ['WIN-HOST'] * n,
        'process_name': np.random.choice(
            ['powershell.exe', 'wevtutil.exe', 'lsass.exe'], n),
        'delta_t': np.random.exponential(2, n),
        'event_frequency': np.random.randint(1, 20, n),
        'hour_of_day': times.hour,
        'is_business_hours': 1,
        'event_id_encoded': 3,
        'is_critical_event': 0,
        'log_burst': 0,
        'if_flag': 0,
    })
    df.loc[:10, 'if_flag'] = 1
    df.loc[:10, 'delta_t'] = 500
    df.loc[5, 'is_critical_event'] = 1
    df.loc[5, 'event_id'] = 1102
    return df


def test_threat_map_returns_nodes():
    data = build_threat_map_data(_sample_df())
    assert 'nodes' in data
    assert len(data['nodes']) > 0


def test_classification_has_ranked_list():
    data = build_classification_data(_sample_df())
    assert 'ranked' in data
    assert len(data['ranked']) > 0


def test_knowledge_graph_has_timestamps():
    data = build_knowledge_graph_data(
        _sample_df(), 'SUSPICIOUS')
    assert all('timestamp' in n for n in data['nodes'])


def test_build_all_panels_keys():
    panels = build_all_threat_panels(
        _sample_df(), 'SUSPICIOUS')
    for key in [
            'threat_map', 'processing_rate',
            'classification', 'trend', 'knowledge_graph']:
        assert key in panels


def test_flagged_events_table_columns():
    from dashboard.utils.threat_panels import (
        build_flagged_events_table)
    table = build_flagged_events_table(_sample_df())
    assert list(table.columns) == [
        'timestamp', 'event_id', 'account', 'reason_flagged']
    assert len(table) > 0


def test_empty_df_does_not_crash():
    empty = pd.DataFrame(columns=[
        'time_created', 'event_id', 'account_name',
        'computer', 'process_name', 'delta_t',
        'event_frequency', 'if_flag', 'is_critical_event'])
    build_all_threat_panels(empty, 'CLEAN')
