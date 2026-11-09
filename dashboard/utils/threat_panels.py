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
    Build a sortable table of flagged events for forensic drill-down.
    Evidence hierarchy:
      1. LSTM sequence anomaly: 'Event order anomaly (LSTM)'
      2. HMAC finding (tampered / extra record): 'Record missing or extra compared with baseline (HMAC)'
      3. Isolation Forest: 'Unusual timing or pattern (low confidence)'

    Time Complexity: O(n)
    Space Complexity: O(k) where k is flagged row count
    """
    if df is None or len(df) == 0:
        return pd.DataFrame(columns=[
            'timestamp', 'event_id', 'account', 'reason_flagged'])

    lstm_flag = df['lstm_flag'].values if 'lstm_flag' in df.columns else np.zeros(len(df), dtype=int)
    lstm_score = df['lstm_score'].values if 'lstm_score' in df.columns else np.zeros(len(df), dtype=float)
    if_flag = df['if_flag'].values if 'if_flag' in df.columns else np.zeros(len(df), dtype=int)

    # Check HMAC findings across standard column names (hmac_flag, hmac_extra, hmac_finding, is_extra)
    hmac_flag = np.zeros(len(df), dtype=int)
    if 'hmac_flag' in df.columns:
        hmac_flag = np.bitwise_or(hmac_flag, (df['hmac_flag'].values == 1).astype(int))
    if 'hmac_extra' in df.columns:
        hmac_flag = np.bitwise_or(hmac_flag, (df['hmac_extra'].values == 1).astype(int))
    if 'hmac_finding' in df.columns:
        hmac_flag = np.bitwise_or(hmac_flag, (df['hmac_finding'].values == 1).astype(int))
    if 'is_extra' in df.columns:
        hmac_flag = np.bitwise_or(hmac_flag, (df['is_extra'].values == 1).astype(int))

    is_flagged = (lstm_flag == 1) | (hmac_flag == 1) | (if_flag == 1)
    if not np.any(is_flagged):
        cols = ['timestamp', 'event_id', 'account', 'reason_flagged']
        if 'lstm_flag' in df.columns and 'lstm_score' in df.columns:
            cols.extend(['lstm_flag', 'lstm_score'])
        return pd.DataFrame(columns=cols)

    flagged_indices = np.where(is_flagged)[0]
    flagged_df = df.iloc[flagged_indices].copy()

    f_lstm_flags = lstm_flag[flagged_indices]
    f_lstm_scores = lstm_score[flagged_indices]
    f_hmac_flags = hmac_flag[flagged_indices]
    f_if_flags = if_flag[flagged_indices]

    reasons = []
    priorities = []
    sort_scores = []

    for lf, ls, hf, iff in zip(f_lstm_flags, f_lstm_scores, f_hmac_flags, f_if_flags):
        if lf == 1:
            reasons.append("Event order anomaly (LSTM)")
            priorities.append(1)
            sort_scores.append(float(ls))
        elif hf == 1:
            reasons.append("Record missing or extra compared with baseline (HMAC)")
            priorities.append(2)
            sort_scores.append(0.0)
        elif iff == 1:
            reasons.append("Unusual timing or pattern (low confidence)")
            priorities.append(3)
            sort_scores.append(0.0)
        else:
            reasons.append("Unusual timing or pattern (low confidence)")
            priorities.append(3)
            sort_scores.append(0.0)

    # Format timestamps consistently as YYYY-MM-DD HH:MM:SS
    if 'time_created' in flagged_df.columns:
        try:
            formatted_times = pd.to_datetime(flagged_df['time_created'], utc=True).dt.strftime('%Y-%m-%d %H:%M:%S').fillna('')
        except Exception:
            formatted_times = flagged_df['time_created'].astype(str).str.slice(0, 19)
    else:
        formatted_times = pd.Series([''] * len(flagged_df), index=flagged_df.index)

    out = pd.DataFrame({
        'timestamp': formatted_times.values,
        'event_id': flagged_df.get('event_id', pd.Series(0, index=flagged_df.index)).values,
        'account': flagged_df.get(
            'account_name', pd.Series('UNKNOWN', index=flagged_df.index)).fillna('UNKNOWN').values,
        'reason_flagged': reasons,
    })

    if 'lstm_flag' in df.columns and 'lstm_score' in df.columns:
        out['lstm_flag'] = f_lstm_flags
        out['lstm_score'] = np.round(f_lstm_scores, 4)

    out['_priority'] = priorities
    out['_sort_score'] = sort_scores
    out['_sort_time'] = formatted_times.values

    # Order: LSTM rows first by lstm_score descending, then HMAC rows, then IF only rows by timestamp
    out = out.sort_values(
        by=['_priority', '_sort_score', '_sort_time'],
        ascending=[True, False, False]
    ).drop(columns=['_priority', '_sort_score', '_sort_time']).reset_index(drop=True)

    return out


def build_lstm_panel_data(
        df: pd.DataFrame,
        threshold: float = 0.1283,
        notice: str = "") -> dict:
    """
    Build primitive data for the LSTM Event Order Check panel.

    Parameters:
        df (pd.DataFrame): DataFrame containing lstm_score, lstm_flag, time_created.
        threshold (float): Anomaly score threshold (default: 0.1283).
        notice (str): Optional notice string if LSTM could not run.

    Returns:
        dict: Summary, blocks table, raw metrics, and timeline series data.

    Time Complexity: O(n) where n is total rows in df.
    Space Complexity: O(k) where k is number of flagged blocks / sample points.
    """
    if notice:
        return {
            'status': 'notice',
            'summary': notice,
            'blocks': [],
            'rows_checked': len(df),
            'rows_flagged': 0,
            'max_score': 0.0,
            'mean_score': 0.0,
            'threshold': float(threshold),
            'timeline_data': None,
        }

    if 'lstm_flag' not in df.columns or len(df) == 0:
        return {
            'status': 'unavailable',
            'summary': "The event order check could not run for this file.",
            'blocks': [],
            'rows_checked': len(df),
            'rows_flagged': 0,
            'max_score': 0.0,
            'mean_score': 0.0,
            'threshold': float(threshold),
            'timeline_data': None,
        }

    flag_series = df['lstm_flag'].values
    score_series = (
        df['lstm_score'].values
        if 'lstm_score' in df.columns
        else np.zeros(len(df), dtype=float)
    )
    time_series = (
        df['time_created'].astype(str).values
        if 'time_created' in df.columns
        else np.array([''] * len(df))
    )

    rows_checked = int(len(df))
    rows_flagged = int(np.sum(flag_series == 1))
    max_score = float(np.max(score_series)) if len(score_series) > 0 else 0.0
    mean_score = float(np.mean(score_series)) if len(score_series) > 0 else 0.0

    def _classify_block(b_score: float):
        if b_score >= 0.5:
            return (
                'High',
                'Events are strongly out of order here, likely reordered.',
                'Compare these record IDs and timestamps with other logs from the same machine (System, Application) and with the HMAC chain result.'
            )
        elif b_score >= 0.2:
            return (
                'Medium',
                'Events look out of order here, review recommended.',
                'Compare these record IDs and timestamps with other logs from the same machine (System, Application) and with the HMAC chain result.'
            )
        else:
            return (
                'Low',
                'Slightly unusual order, may be normal activity. Low priority.',
                'Review only if nearby High severity regions exist.'
            )

    blocks = []
    in_block = False
    start_idx = 0
    for i, flag in enumerate(flag_series):
        if flag == 1 and not in_block:
            in_block = True
            start_idx = i
        elif flag == 0 and in_block:
            in_block = False
            end_idx = i - 1
            b_start_time = str(time_series[start_idx])[:19]
            b_end_time = str(time_series[end_idx])[:19]
            b_count = int(end_idx - start_idx + 1)
            b_max_score = float(np.max(score_series[start_idx : end_idx + 1]))
            sev, meaning, action = _classify_block(b_max_score)
            blocks.append({
                'start_time': b_start_time,
                'end_time': b_end_time,
                'event_count': b_count,
                'highest_score': round(b_max_score, 4),
                'meaning': meaning,
                'action': action,
                'severity': sev
            })
    if in_block:
        end_idx = len(flag_series) - 1
        b_start_time = str(time_series[start_idx])[:19]
        b_end_time = str(time_series[end_idx])[:19]
        b_count = int(end_idx - start_idx + 1)
        b_max_score = float(np.max(score_series[start_idx : end_idx + 1]))
        sev, meaning, action = _classify_block(b_max_score)
        blocks.append({
            'start_time': b_start_time,
            'end_time': b_end_time,
            'event_count': b_count,
            'highest_score': round(b_max_score, 4),
            'meaning': meaning,
            'action': action,
            'severity': sev
        })

    # Sort blocks by Max Anomaly Score descending
    blocks.sort(key=lambda x: x['highest_score'], reverse=True)

    num_blocks = len(blocks)
    h_count = sum(1 for b in blocks if b['severity'] == 'High')
    me_count = sum(1 for b in blocks if b['severity'] == 'Medium')
    l_count = sum(1 for b in blocks if b['severity'] == 'Low')
    strongest_time = blocks[0]['start_time'] if blocks else "N/A"

    flagged_frac = rows_flagged / max(rows_checked, 1)
    alert_fired = bool(rows_checked >= 500 and flagged_frac > 0.03 and num_blocks >= 3)

    if rows_checked < 500:
        summary = "File too small for a reliable event order check."
    elif alert_fired:
        region_str = "1 region contains" if num_blocks == 1 else f"{num_blocks} regions contain"
        h_str = f"{h_count} is High severity" if h_count == 1 else f"{h_count} are High severity"
        summary = (
            f"{region_str} out-of-order events, covering about {rows_flagged:,} events in total. "
            f"{h_str}, {me_count} Medium, {l_count} Low. "
            f"The strongest region is at {strongest_time}. "
            "A region is wider than the actual change because the model checks windows of 10 events, so it includes neighboring events."
        )
    else:
        summary = "No unusual event ordering was found."

    # Downsample points for visualization if dataset is large
    step = max(1, len(df) // 1500)
    sampled_indices = np.arange(0, len(df), step)
    flagged_indices = np.where(flag_series == 1)[0]
    all_indices = np.unique(np.concatenate([sampled_indices, flagged_indices]))
    all_indices.sort()

    timeline_data = {
        'times': [str(time_series[i])[:19] for i in all_indices],
        'scores': [float(score_series[i]) for i in all_indices],
        'flags': [int(flag_series[i]) for i in all_indices],
        'total_flagged': rows_flagged,
        'threshold': float(threshold)
    }

    return {
        'status': 'ok',
        'summary': summary,
        'blocks': blocks,
        'alert_fired': alert_fired,
        'regions_count': num_blocks,
        'high_count': h_count,
        'medium_count': me_count,
        'low_count': l_count,
        'strongest_time': strongest_time,
        'rows_checked': rows_checked,
        'rows_flagged': rows_flagged,
        'max_score': max_score,
        'mean_score': mean_score,
        'threshold': float(threshold),
        'timeline_data': timeline_data
    }


def build_all_threat_panels(df: pd.DataFrame, verdict: str) -> dict:
    """Build all Threat Overview primitives. O(n) time."""
    return {
        'threat_map': build_threat_map_data(df),
        'processing_rate': build_processing_rate_data(df),
        'classification': build_classification_data(df),
        'trend': build_trend_data(df),
        'knowledge_graph': build_knowledge_graph_data(
            df, verdict),
        'lstm_panel': build_lstm_panel_data(df),
    }
