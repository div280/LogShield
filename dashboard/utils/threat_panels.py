"""
threat_panels.py
Build primitive panel data for Threat Overview dashboard.
Time Complexity: O(n) per builder, Space Complexity: O(n)
"""
import pandas as pd
import numpy as np


GAP_DELTA_PERCENTILE = 95
INJECTION_FREQ_THRESHOLD = 100


def _assign_log_category(row, gap_threshold: float) -> str:
    if row.get('is_critical_event', 0) == 1:
        return 'Critical Event'
    if row.get('if_flag', 0) != 1:
        return 'Normal'
    delta_t = float(row.get('delta_t', 0) or 0)
    freq = float(row.get('event_frequency', 0) or 0)
    if delta_t >= gap_threshold:
        return 'Gap Attack'
    if freq >= INJECTION_FREQ_THRESHOLD:
        return 'Injection Attack'
    return 'Shuffle Attack'


def build_threat_map_data(df: pd.DataFrame) -> dict:
    """
    Build origin vs impacted node map (no fabricated geo).

    Time Complexity: O(n)
    Space Complexity: O(k)
    """
    flagged = df[df.get('if_flag', pd.Series(0, index=df.index)) == 1]
    if len(flagged) == 0:
        flagged = df.head(min(500, len(df)))

    nodes = []
    y_pos = 0.0
    if 'account_name' in df.columns:
        origins = (
            flagged['account_name'].fillna('UNKNOWN')
            .value_counts().head(8))
        for name, count in origins.items():
            nodes.append({
                'id': f'origin_{name}',
                'label': str(name)[:36],
                'node_type': 'Origin',
                'size': max(10, min(42, int(count ** 0.5 * 4))),
                'volume': int(count),
                'x': 0.12 + (y_pos % 3) * 0.06,
                'y': 0.15 + y_pos * 0.11,
                'detail': (
                    f'Account linked to {count:,} '
                    f'flagged events on this host'),
            })
            y_pos += 1

    y_pos = 0.0
    if 'computer' in df.columns and len(df) > 0:
        impacts = (
            flagged['computer'].fillna('UNKNOWN')
            .value_counts().head(8))
        if len(impacts) == 0:
            impacts = df['computer'].fillna('UNKNOWN').value_counts()
        for name, count in impacts.items():
            nodes.append({
                'id': f'impact_{name}',
                'label': str(name)[:36],
                'node_type': 'Impacted',
                'size': max(14, min(50, int(count ** 0.5 * 3))),
                'volume': int(count),
                'x': 0.78 + (y_pos % 2) * 0.05,
                'y': 0.2 + y_pos * 0.14,
                'detail': (
                    f'Host with {count:,} flagged '
                    f'events in this log export'),
            })
            y_pos += 1

    return {'nodes': nodes}


def build_processing_rate_data(df: pd.DataFrame) -> dict:
    """Compute ingestion rate from file time span. O(1) time."""
    total = len(df)
    if total == 0 or 'time_created' not in df.columns:
        return {
            'rate': 0, 'rate_label': 'events/min',
            'min_label': '0', 'max_label': '1000',
            'max_val': 1000,
        }
    times = pd.to_datetime(df['time_created'], utc=True)
    span_sec = max(
        (times.max() - times.min()).total_seconds(), 1.0)
    rate_per_min = int(total / span_sec * 60)
    max_val = max(rate_per_min * 2, 1000)
    return {
        'rate': rate_per_min,
        'rate_label': 'events/min',
        'min_label': '0',
        'max_label': f'{max_val:,}',
        'max_val': max_val,
    }


def build_classification_data(df: pd.DataFrame) -> dict:
    """Build category counts and ranked list. O(n) time."""
    if 'delta_t' not in df.columns:
        total = len(df)
        return {
            'labels': ['Normal'], 'values': [total],
            'ranked': [{'label': 'Normal', 'count': total,
                        'pct': 100.0}],
        }

    normal_delta = df[df.get('if_flag', 0) == 0]['delta_t']
    gap_threshold = float(
        normal_delta.quantile(GAP_DELTA_PERCENTILE / 100)
        if len(normal_delta) > 0 else 60.0)
    categories = df.apply(
        lambda r: _assign_log_category(r, gap_threshold), axis=1)
    counts = categories.value_counts()
    order = [
        'Normal', 'Gap Attack', 'Shuffle Attack',
        'Injection Attack', 'Critical Event']
    labels, values, ranked = [], [], []
    total = len(df)
    for label in order:
        if label in counts.index:
            c = int(counts[label])
            labels.append(label)
            values.append(c)
            ranked.append({
                'label': label,
                'count': c,
                'pct': round(c / total * 100, 2) if total else 0,
            })
    ranked.sort(key=lambda x: x['count'], reverse=True)
    return {'labels': labels, 'values': values, 'ranked': ranked}


def build_trend_data(df: pd.DataFrame, buckets: int = 48) -> dict:
    """Build multi-line trend series. O(n) time."""
    if 'time_created' not in df.columns or len(df) == 0:
        return {'times': [], 'logs': [], 'events': [], 'alarms': []}

    work = df.copy()
    work['time_created'] = pd.to_datetime(
        work['time_created'], utc=True)
    work = work.sort_values('time_created')
    work['_bucket'] = pd.cut(
        work['time_created'].astype(np.int64),
        bins=buckets, labels=False, duplicates='drop')

    times, logs, events, alarms = [], [], [], []
    for _, grp in work.groupby('_bucket', observed=True):
        t = grp['time_created'].iloc[len(grp) // 2]
        times.append(str(t)[:19])
        logs.append(int(len(grp)))
        events.append(int(len(grp)))
        if_flag = grp['if_flag'] if 'if_flag' in grp.columns else 0
        crit = (
            grp['is_critical_event']
            if 'is_critical_event' in grp.columns else 0)
        alarms.append(int(if_flag.sum() + crit.sum()))

    return {
        'times': times, 'logs': logs,
        'events': events, 'alarms': alarms,
    }


def build_knowledge_graph_data(
        df: pd.DataFrame, verdict: str) -> dict:
    """Build attack narrative graph. O(n) time."""
    if len(df) == 0:
        return {'nodes': [], 'edges': []}

    account = 'Unknown account'
    login_time = 'Unknown time'
    process = 'Unknown process'
    crit_label = 'No critical events detected'
    crit_time = ''

    if 'account_name' in df.columns:
        sus = df[df.get('if_flag', 0) == 1]['account_name']
        account = str(
            sus.mode().iloc[0] if len(sus) > 0
            else df['account_name'].mode().iloc[0])

    if 'time_created' in df.columns:
        sus_t = df[df.get('if_flag', 0) == 1]
        src = sus_t if len(sus_t) > 0 else df
        login_time = str(src['time_created'].iloc[0])[:19]

    tools = ['wevtutil', 'whoami', 'net.exe', 'runas',
             'powershell', 'cmd.exe']
    if 'process_name' in df.columns:
        procs = df['process_name'].fillna('').astype(str)
        for tool in tools:
            match = procs[procs.str.lower().str.contains(
                tool, na=False)]
            if len(match) > 0:
                process = str(match.iloc[0])[-55:]
                break

    if 'event_id' in df.columns:
        crit = df[df['event_id'].isin([1102, 4719])]
        if len(crit) > 0:
            row = crit.iloc[0]
            eid = int(row['event_id'])
            crit_label = (
                'Security log cleared (1102)'
                if eid == 1102 else
                'Audit policy modified (4719)')
            crit_time = str(row['time_created'])[:19]

    x_cols = [0.05, 0.27, 0.49, 0.71, 0.93]
    node_defs = [
        ('account', 'Account', account, login_time,
         'User or service account involved in '
         'suspicious or flagged activity', 'account'),
        ('login', 'Session', login_time, login_time,
         'Timestamp when the suspicious session '
         'or event sequence began', 'session'),
        ('process', 'Process', process, login_time,
         'Executable associated with post-exploitation '
         'or log manipulation behavior', 'process'),
        ('critical', 'Critical Event', crit_label, crit_time,
         'High-risk Windows security event that may '
         'indicate anti-forensic activity', 'event'),
        ('verdict', 'Verdict', verdict, login_time,
         'Overall integrity assessment from HMAC '
         'chain and AI detection layers', 'verdict'),
    ]

    nodes, edges = [], []
    prev_id = None
    for i, (nid, ntype, title, ts, detail, kind) in enumerate(
            node_defs):
        nodes.append({
            'id': nid,
            'label': ntype,
            'title': str(title)[:55],
            'timestamp': ts if ts else 'N/A',
            'detail': detail,
            'node_kind': kind,
            'x': x_cols[i],
            'y': 0.5,
        })
        if prev_id:
            edges.append({'from': prev_id, 'to': nid})
        prev_id = nid

    return {'nodes': nodes, 'edges': edges}


def build_flagged_events_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build a sortable preview of flagged events for examiner drill-down.

    Parameters:
        df (pd.DataFrame): Analyzed log DataFrame with model outputs.

    Returns:
        pd.DataFrame: Columns for timestamp, event ID, account, reason.

    Time Complexity: O(n)
    Space Complexity: O(k) where k is flagged row count
    """
    if 'if_flag' not in df.columns:
        return pd.DataFrame(columns=[
            'timestamp', 'event_id', 'account', 'reason_flagged'])

    flagged = df[df['if_flag'] == 1].copy()
    if len(flagged) == 0:
        return pd.DataFrame(columns=[
            'timestamp', 'event_id', 'account', 'reason_flagged'])

    gap_threshold = 60.0
    if 'delta_t' in df.columns:
        normal_delta = df[df['if_flag'] == 0]['delta_t']
        if len(normal_delta) > 0:
            gap_threshold = float(
                normal_delta.quantile(GAP_DELTA_PERCENTILE / 100))

    reasons = flagged.apply(
        lambda r: _assign_log_category(r, gap_threshold), axis=1)
    out = pd.DataFrame({
        'timestamp': flagged['time_created'].astype(str),
        'event_id': flagged['event_id'],
        'account': flagged.get(
            'account_name', pd.Series('UNKNOWN', index=flagged.index)),
        'reason_flagged': reasons,
    })
    return out.sort_values(
        'timestamp', ascending=False).head(500).reset_index(drop=True)


def build_all_threat_panels(df: pd.DataFrame, verdict: str) -> dict:
    """Build all Threat Overview primitives. O(n) time."""
    return {
        'threat_map': build_threat_map_data(df),
        'processing_rate': build_processing_rate_data(df),
        'classification': build_classification_data(df),
        'trend': build_trend_data(df),
        'knowledge_graph': build_knowledge_graph_data(
            df, verdict),
    }
