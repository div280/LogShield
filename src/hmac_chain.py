"""
hmac_chain.py -- HMAC-SHA256 cryptographic integrity
chain for LogShield Windows Event Log verification.

Layer 1 of LogShield dual-layer detection framework.
Provides mathematical proof of log record tampering.
HMAC result overrides all ML model results.

Chain formula:
HMAC(n) = HMAC-SHA256(content(n) || HMAC(n-1) || key)

Time Complexity: O(n), Space Complexity: O(n)
"""
import hmac
import hashlib
import json
import os
import pandas as pd
import numpy as np
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from collections import defaultdict, deque


CHAIN_FILE = 'models_saved/hmac_chain.json'
BASELINE_MISMATCH_RATIO = 0.5
BASELINE_MISMATCH_MSG = (
    'This file may not match the baseline used for '
    'chain verification')


def _get_secret_key() -> bytes:
    """
    Load HMAC secret key from environment variable.
    Never hardcode the key. Fails closed if key not found.

    Returns:
        bytes: The secret key encoded as UTF-8 bytes.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    key = os.environ.get('LOGSHIELD_HMAC_KEY', '')
    if not key:
        key = 'logshield_default_dev_key_change_in_prod'
        print("WARNING: Using default dev key.")
        print("Set LOGSHIELD_HMAC_KEY in .env for production.")
    return key.encode('utf-8')


def _compute_record_hmac(
        record_content: str,
        previous_hmac: str,
        secret_key: bytes) -> str:
    """
    Compute HMAC for one log record.

    Parameters:
        record_content (str): String representation of record.
        previous_hmac (str): HMAC of previous record in chain.
        secret_key (bytes): Secret key bytes.

    Returns:
        str: Hex string HMAC for this record.

    Time Complexity: O(k) where k is content length
    Space Complexity: O(k)
    """
    message = (record_content + previous_hmac).encode('utf-8')
    return hmac.new(
        secret_key,
        message,
        hashlib.sha256
    ).hexdigest()


def _record_to_content_string(row: pd.Series) -> str:
    """
    Convert a DataFrame row to a deterministic string
    for HMAC computation.
    Uses only stable fields that should not change.

    Parameters:
        row (pd.Series): DataFrame row of log record.

    Returns:
        str: Deterministic pipe-delimited string.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    fields = [
        str(row.get('event_record_id', '')),
        str(row.get('event_id', '')),
        str(row.get('time_created', '')),
        str(row.get('computer', '')),
        str(row.get('channel', '')),
    ]
    return '|'.join(fields)


def _format_content_string(
        event_record_id: Any,
        event_id: Any,
        time_created: Any,
        computer: Any,
        channel: Any) -> str:
    """
    Format individual fields into a deterministic HMAC message string.

    Parameters:
        event_record_id (Any): Record identifier.
        event_id (Any): Windows Event ID.
        time_created (Any): Timestamp string.
        computer (Any): Computer hostname.
        channel (Any): Event channel name.

    Returns:
        str: Pipe-delimited record string.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    return (
        f"{str(event_record_id)}|{str(event_id)}|"
        f"{str(time_created)}|{str(computer)}|{str(channel)}"
    )


def get_chain_record_count(
        chain_filepath: str = CHAIN_FILE) -> int:
    """
    Return total_records from a stored HMAC chain file.

    Parameters:
        chain_filepath (str): Path to the chain JSON file.

    Returns:
        int: Number of records in the baseline chain, or 0 if missing.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    if not os.path.exists(chain_filepath):
        return 0
    with open(chain_filepath, 'r') as f:
        chain_data = json.load(f)
    return int(chain_data.get('total_records', 0))


def check_baseline_row_count(
        file_row_count: int,
        chain_filepath: str = CHAIN_FILE,
        threshold: float = BASELINE_MISMATCH_RATIO) -> Dict[str, Any]:
    """
    Detect when an upload row count diverges from the chain baseline.

    Parameters:
        file_row_count (int): Rows in the uploaded file.
        chain_filepath (str): Path to the stored chain file.
        threshold (float): Relative difference that triggers a warning.

    Returns:
        dict: mismatch flag, message, and counts for UI display.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    chain_count = get_chain_record_count(chain_filepath)
    if chain_count <= 0 or file_row_count <= 0:
        return {
            'mismatch': False,
            'message': '',
            'file_rows': file_row_count,
            'chain_rows': chain_count,
        }

    ratio = abs(file_row_count - chain_count) / chain_count
    mismatch = ratio > threshold
    return {
        'mismatch': mismatch,
        'message': BASELINE_MISMATCH_MSG if mismatch else '',
        'file_rows': file_row_count,
        'chain_rows': chain_count,
    }


def build_hmac_chain(
        df: pd.DataFrame,
        chain_filepath: str = CHAIN_FILE) -> Dict[str, Any]:
    """
    Build HMAC chain from a clean DataFrame.
    Call this on your trusted baseline dataset after the same
    parse and feature-extraction steps used at upload time.
    Store the chain securely.

    Parameters:
        df (pd.DataFrame): Clean parsed DataFrame (trusted baseline).
        chain_filepath (str): Destination path to save JSON chain.

    Returns:
        dict: Chain data dictionary and metadata.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    secret_key = _get_secret_key()
    df_sorted = df.sort_values(
        'time_created').reset_index(drop=True)

    n_records = len(df_sorted)
    record_ids = (
        df_sorted['event_record_id'].astype(str).values
        if 'event_record_id' in df_sorted.columns
        else np.arange(n_records).astype(str))
    event_ids = (
        df_sorted['event_id'].fillna(0).astype(int).values
        if 'event_id' in df_sorted.columns
        else np.zeros(n_records, dtype=int))
    times = (
        df_sorted['time_created'].astype(str).values
        if 'time_created' in df_sorted.columns
        else np.array([''] * n_records))
    computers = (
        df_sorted['computer'].fillna('').astype(str).values
        if 'computer' in df_sorted.columns
        else np.array([''] * n_records))
    channels = (
        df_sorted['channel'].fillna('').astype(str).values
        if 'channel' in df_sorted.columns
        else np.array([''] * n_records))

    chain = []
    previous_hmac = '0' * 64

    for idx in range(n_records):
        content = _format_content_string(
            record_ids[idx], event_ids[idx], times[idx],
            computers[idx], channels[idx])
        current_hmac = _compute_record_hmac(
            content, previous_hmac, secret_key)
        chain.append({
            'index': idx,
            'event_record_id': str(record_ids[idx]),
            'event_id': int(event_ids[idx]),
            'time_created': str(times[idx]),
            'hmac': current_hmac
        })
        previous_hmac = current_hmac

    chain_data = {
        'version': '1.0',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'total_records': len(chain),
        'final_hmac': previous_hmac,
        'chain': chain
    }

    dir_name = os.path.dirname(chain_filepath)
    os.makedirs(dir_name if dir_name else 'models_saved', exist_ok=True)
    with open(chain_filepath, 'w') as f:
        json.dump(chain_data, f, indent=2)

    print(f"HMAC chain built for {len(chain):,} records")
    print(f"Final HMAC: {previous_hmac[:16]}...")
    print(f"Saved to: {chain_filepath}")

    return chain_data


def verify_hmac_chain(
        df: pd.DataFrame,
        chain_filepath: str = CHAIN_FILE) -> pd.DataFrame:
    """
    Verify DataFrame records against stored HMAC chain.
    Detects deletion, modification, and injection.

    Parameters:
        df (pd.DataFrame): DataFrame to verify.
        chain_filepath (str): Path to stored chain file.

    Returns:
        pd.DataFrame: DataFrame with added columns:
            hmac_verified (bool): True if record verified.
            hmac_flag (int): 1 if tampered, 0 if clean.
            hmac_reason (str): Plain-English verification reason.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    if not os.path.exists(chain_filepath):
        raise FileNotFoundError(
            f"HMAC chain not found at {chain_filepath}. "
            f"Run build_hmac_chain first.")

    with open(chain_filepath, 'r') as f:
        chain_data = json.load(f)

    # Fast lookup with deque for O(1) matching
    stored_chain = defaultdict(deque)
    for entry in chain_data['chain']:
        key = (str(entry['event_record_id']), str(entry.get('time_created', '')))
        stored_chain[key].append(entry['hmac'])

    # Fallback lookup by record ID only if timestamp changed
    stored_by_id = defaultdict(deque)
    for entry in chain_data['chain']:
        stored_by_id[str(entry['event_record_id'])].append(entry['hmac'])

    secret_key = _get_secret_key()
    df_sorted = df.sort_values(
        'time_created').reset_index(drop=True)

    n_records = len(df_sorted)
    record_ids = (
        df_sorted['event_record_id'].astype(str).values
        if 'event_record_id' in df_sorted.columns
        else np.arange(n_records).astype(str))
    event_ids = (
        df_sorted['event_id'].fillna(0).astype(int).values
        if 'event_id' in df_sorted.columns
        else np.zeros(n_records, dtype=int))
    times = (
        df_sorted['time_created'].astype(str).values
        if 'time_created' in df_sorted.columns
        else np.array([''] * n_records))
    computers = (
        df_sorted['computer'].fillna('').astype(str).values
        if 'computer' in df_sorted.columns
        else np.array([''] * n_records))
    channels = (
        df_sorted['channel'].fillna('').astype(str).values
        if 'channel' in df_sorted.columns
        else np.array([''] * n_records))

    hmac_flags = []
    hmac_reasons = []
    previous_hmac = '0' * 64

    for idx in range(n_records):
        rec_id = str(record_ids[idx])
        time_val = str(times[idx])
        content = _format_content_string(
            rec_id, event_ids[idx], time_val,
            computers[idx], channels[idx])
        computed_hmac = _compute_record_hmac(
            content, previous_hmac, secret_key)

        key = (rec_id, time_val)
        if stored_chain[key]:
            stored_hmac = stored_chain[key].popleft()
            if rec_id in stored_by_id and stored_by_id[rec_id]:
                try:
                    stored_by_id[rec_id].remove(stored_hmac)
                except ValueError:
                    pass
        elif stored_by_id[rec_id]:
            stored_hmac = stored_by_id[rec_id].popleft()
        else:
            hmac_flags.append(1)
            hmac_reasons.append('INJECTED: record not in chain')
            previous_hmac = computed_hmac
            continue

        if computed_hmac != stored_hmac:
            hmac_flags.append(1)
            hmac_reasons.append('MODIFIED: HMAC mismatch')
        else:
            hmac_flags.append(0)
            hmac_reasons.append('VERIFIED')

        previous_hmac = computed_hmac

    df_sorted['hmac_flag'] = hmac_flags
    df_sorted['hmac_reason'] = hmac_reasons
    df_sorted['hmac_verified'] = (
        df_sorted['hmac_flag'] == 0)

    total = len(df_sorted)
    flagged = int(df_sorted['hmac_flag'].sum())
    print(f"=== LOGSHIELD HMAC CHAIN VERIFICATION ===")
    print(f"Total records verified: {total:,}")
    print(f"Records flagged:        {flagged:,}")
    print(f"Records clean:          {total-flagged:,}")
    print(f"Integrity:              "
          f"{'COMPROMISED' if flagged > 0 else 'INTACT'}")

    return df_sorted


def check_chain_continuity(
        df: pd.DataFrame,
        chain_filepath: str = CHAIN_FILE) -> Dict[str, Any]:
    """
    Check for gaps in the chain -- deleted records.
    Compares record IDs in chain vs DataFrame.

    Parameters:
        df (pd.DataFrame): DataFrame to check.
        chain_filepath (str): Path to stored chain file.

    Returns:
        dict: Gap and injection analysis results.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    with open(chain_filepath, 'r') as f:
        chain_data = json.load(f)

    chain_ids = set(
        str(e['event_record_id'])
        for e in chain_data['chain'])
    current_ids = (
        set(df['event_record_id'].astype(str).values)
        if 'event_record_id' in df.columns
        else set(np.arange(len(df)).astype(str)))

    missing_ids = chain_ids - current_ids
    extra_ids = current_ids - chain_ids

    result = {
        'records_in_chain': len(chain_ids),
        'records_in_file': len(current_ids),
        'missing_records': len(missing_ids),
        'extra_records': len(extra_ids),
        'gap_detected': len(missing_ids) > 0,
        'injection_detected': len(extra_ids) > 0,
        'missing_record_ids': list(missing_ids)[:20],
        'extra_record_ids': list(extra_ids)[:20]
    }

    print(f"=== CHAIN CONTINUITY CHECK ===")
    print(f"Records in chain:  {result['records_in_chain']:,}")
    print(f"Records in file:   {result['records_in_file']:,}")
    print(f"Missing (deleted): {result['missing_records']:,}")
    print(f"Extra (injected):  {result['extra_records']:,}")
    if result['gap_detected']:
        print("ALERT: Log deletion detected!")
    if result['injection_detected']:
        print("ALERT: Log injection detected!")

    return result

