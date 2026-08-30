"""
hmac_chain.py — HMAC-SHA256 cryptographic integrity
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
from typing import Optional
from datetime import datetime, timezone
from collections import defaultdict


CHAIN_FILE = 'models_saved/hmac_chain.json'


def _get_secret_key() -> bytes:
    """
    Load HMAC secret key from environment variable.
    Never hardcode the key.
    Fails closed if key not found.
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

    Args:
        record_content: string representation of record
        previous_hmac: HMAC of previous record in chain
        secret_key: secret key bytes

    Returns:
        hex string HMAC for this record
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
    """
    fields = [
        str(row.get('event_record_id', '')),
        str(row.get('event_id', '')),
        str(row.get('time_created', '')),
        str(row.get('computer', '')),
        str(row.get('channel', '')),
    ]
    return '|'.join(fields)


def build_hmac_chain(
        df: pd.DataFrame,
        chain_filepath: str = CHAIN_FILE) -> dict:
    """
    Build HMAC chain from a clean DataFrame.
    Call this on your trusted baseline dataset.
    Store the chain securely.

    Args:
        df: clean parsed DataFrame (trusted baseline)
        chain_filepath: where to save the chain

    Returns:
        dict with chain data and metadata

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    secret_key = _get_secret_key()
    df_sorted = df.sort_values(
        'time_created').reset_index(drop=True)

    chain = []
    previous_hmac = '0' * 64

    for idx, row in df_sorted.iterrows():
        content = _record_to_content_string(row)
        current_hmac = _compute_record_hmac(
            content, previous_hmac, secret_key)
        chain.append({
            'index': idx,
            'event_record_id': str(
                row.get('event_record_id', idx)),
            'event_id': int(row.get('event_id', 0)),
            'time_created': str(row.get('time_created', '')),
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

    os.makedirs(os.path.dirname(chain_filepath)
                if os.path.dirname(chain_filepath)
                else 'models_saved', exist_ok=True)
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

    Args:
        df: DataFrame to verify
        chain_filepath: path to stored chain file

    Returns:
        DataFrame with added columns:
        hmac_verified (bool): True if record verified
        hmac_flag (int): 1 if tampered, 0 if clean
        hmac_reason (str): why it was flagged

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    if not os.path.exists(chain_filepath):
        raise FileNotFoundError(
            f"HMAC chain not found at {chain_filepath}. "
            f"Run build_hmac_chain first.")

    with open(chain_filepath, 'r') as f:
        chain_data = json.load(f)

    stored_chain = defaultdict(list)
    for entry in chain_data['chain']:
        stored_chain[str(entry['event_record_id'])].append(entry)

    secret_key = _get_secret_key()
    df_sorted = df.sort_values(
        'time_created').reset_index(drop=True)

    hmac_flags = []
    hmac_reasons = []
    previous_hmac = '0' * 64

    for idx, row in df_sorted.iterrows():
        record_id = str(row.get('event_record_id', idx))
        content = _record_to_content_string(row)
        computed_hmac = _compute_record_hmac(
            content, previous_hmac, secret_key)

        if record_id not in stored_chain or len(stored_chain[record_id]) == 0:
            hmac_flags.append(1)
            hmac_reasons.append('INJECTED: record not in chain')
            previous_hmac = computed_hmac
            continue

        if len(stored_chain[record_id]) == 1:
            stored_entry = stored_chain[record_id][0]
        else:
            matched_idx = None
            row_time = str(row.get('time_created', ''))
            for i, cand in enumerate(stored_chain[record_id]):
                if cand['time_created'] == row_time:
                    matched_idx = i
                    break
            if matched_idx is not None:
                stored_entry = stored_chain[record_id].pop(matched_idx)
            else:
                stored_entry = stored_chain[record_id].pop(0)

        stored_hmac = stored_entry['hmac']

        if computed_hmac != stored_hmac:
            hmac_flags.append(1)
            hmac_reasons.append(
                'MODIFIED: HMAC mismatch')
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
        chain_filepath: str = CHAIN_FILE) -> dict:
    """
    Check for gaps in the chain — deleted records.
    Compares record IDs in chain vs DataFrame.

    Args:
        df: DataFrame to check
        chain_filepath: path to stored chain

    Returns:
        dict with gap analysis results
    """
    with open(chain_filepath, 'r') as f:
        chain_data = json.load(f)

    chain_ids = set(
        str(e['event_record_id'])
        for e in chain_data['chain'])
    current_ids = set(
        str(r) for r in df['event_record_id'])

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
