"""Rebuild HMAC chain from logshield_master_clean.csv."""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.parser import parse_csv_from_bytes
from src.features import extract_features
from src.hmac_chain import (
    build_hmac_chain,
    verify_hmac_chain,
    check_chain_continuity)


DEFAULT_CSV = (
    r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
    r'\logshield_master_clean.csv')
CHAIN_PATH = 'models_saved/hmac_chain.json'


def load_csv(path: str):
    """
    Load CSV through the same in-memory pipeline as dashboard uploads.

    Parameters:
        path (str): Path to the baseline CSV file.

    Returns:
        pd.DataFrame: Parsed and feature-enriched baseline data.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    with open(path, 'rb') as handle:
        data = handle.read()
    df = parse_csv_from_bytes(data)
    return extract_features(df)


def main(csv_path: str) -> None:
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))
    print(f'Loading {csv_path}...')
    t0 = time.time()
    df = load_csv(csv_path)
    print(f'Loaded {len(df):,} rows in {time.time()-t0:.1f}s')
    n0 = int((df['is_tampered'] == 0).sum())
    n1 = int((df['is_tampered'] == 1).sum())
    print(f'is_tampered=0: {n0:,}')
    print(f'is_tampered=1: {n1:,}')
    print(f'Tamper ratio: {df["is_tampered"].mean()*100:.4f}%')

    print('Building HMAC chain...')
    t1 = time.time()
    result = build_hmac_chain(df, CHAIN_PATH)
    print(f'Done in {time.time()-t1:.1f}s')
    print(f'Records in chain: {result["total_records"]:,}')

    print('Verifying same file...')
    verified = verify_hmac_chain(df.copy(), CHAIN_PATH)
    cont = check_chain_continuity(df, CHAIN_PATH)
    print(f'HMAC flagged: {int(verified["hmac_flag"].sum())}')
    print(f'Missing: {cont["missing_records"]}')
    print(f'Extra: {cont["extra_records"]}')
    print(f'Gap: {cont["gap_detected"]}')
    print(f'Injection: {cont["injection_detected"]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_path', nargs='?', default=DEFAULT_CSV)
    main(parser.parse_args().csv_path)
