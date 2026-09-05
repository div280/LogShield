"""
train_isolation_forest.py
Train Isolation Forest on a LogShield CSV dataset.
"""
import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.features import extract_features
from src.models.isolation_forest import (
    train_isolation_forest,
    predict_anomalies,
    evaluate_model)


def load_and_prepare(path: str) -> pd.DataFrame:
    """
    Load CSV and apply standard preprocessing.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    df = pd.read_csv(path, low_memory=False)
    df['time_created'] = pd.to_datetime(
        df['time_created'], utc=True, errors='coerce')
    df['account_name'] = df['account_name'].fillna('UNKNOWN')
    df['process_name'] = df['process_name'].fillna('UNKNOWN')
    if 'event_data' in df.columns:
        df['event_data'] = df['event_data'].fillna('')
    df['event_id'] = pd.to_numeric(
        df['event_id'], errors='coerce').fillna(0).astype(int)
    return extract_features(df)


def main(csv_path: str) -> None:
    print(f'Loading {csv_path}...')
    df = load_and_prepare(csv_path)
    print(f'Rows: {len(df):,}')
    print(df['is_tampered'].value_counts())
    contamination = round(df['is_tampered'].mean(), 4)
    print(f'Contamination: {contamination}')
    train_isolation_forest(
        df, contamination=contamination, random_state=42)
    result = predict_anomalies(
        df, 'models_saved/isolation_forest.pkl')
    anomalies = int(result['if_flag'].sum())
    print(
        f'Anomalies flagged: {anomalies:,} / {len(result):,} '
        f'({anomalies / len(result) * 100:.2f}%)')
    evaluate_model(result)


if __name__ == '__main__':
    default = (
        r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
        r'\logshield_master_clean.csv')
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_path', nargs='?', default=default)
    args = parser.parse_args()
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))
    main(args.csv_path)
