"""
dedup_dataset.py
Remove duplicate rows by (channel, time_created, event_id).
Keeps first occurrence of each duplicate group.
"""
import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def dedup_dataset(input_path: str, output_path: str) -> dict:
    """
    Deduplicate LogShield CSV and save clean copy.

    Parameters:
        input_path (str): Source CSV path.
        output_path (str): Output CSV path.

    Returns:
        dict: Summary with row counts and tamper ratio.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    df = pd.read_csv(input_path, low_memory=False)
    before = len(df)
    n0_before = int((df['is_tampered'] == 0).sum())
    n1_before = int((df['is_tampered'] == 1).sum())

    work = df.copy()
    work['time_created'] = work['time_created'].astype(str)
    deduped = work.drop_duplicates(
        subset=['channel', 'time_created', 'event_id'],
        keep='first').copy()
    deduped['time_created'] = pd.to_datetime(
        deduped['time_created'], utc=True, errors='coerce')

    after = len(deduped)
    n0 = int((deduped['is_tampered'] == 0).sum())
    n1 = int((deduped['is_tampered'] == 1).sum())
    ratio = n1 / after * 100 if after else 0.0

    os.makedirs(os.path.dirname(os.path.abspath(output_path))
                or '.', exist_ok=True)
    deduped.to_csv(output_path, index=False)

    return {
        'input_path': input_path,
        'output_path': output_path,
        'rows_before': before,
        'rows_after': after,
        'removed': before - after,
        'normal_before': n0_before,
        'tampered_before': n1_before,
        'normal_after': n0,
        'tampered_after': n1,
        'tamper_ratio_pct': round(ratio, 4),
    }


if __name__ == '__main__':
    default_in = (
        r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
        r'\logshield_master.csv')
    default_out = (
        r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
        r'\logshield_master_clean.csv')
    parser = argparse.ArgumentParser()
    parser.add_argument('input', nargs='?', default=default_in)
    parser.add_argument('output', nargs='?', default=default_out)
    args = parser.parse_args()
    report = dedup_dataset(args.input, args.output)
    print('=' * 60)
    print('DEDUP REPORT')
    print('=' * 60)
    for k, v in report.items():
        if isinstance(v, int) and v > 1000:
            print(f'{k}: {v:,}')
        else:
            print(f'{k}: {v}')
