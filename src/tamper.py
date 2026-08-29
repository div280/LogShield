"""
tamper.py — Simulates 3 types of anti-forensic attacks
on Windows Event Logs for LogShield dataset generation.
Increases tampered row ratio from 0.81% to 5-7%.
"""
import pandas as pd
import numpy as np
import os
from typing import Optional
from src.parser import parse_csv_file
from src.features import extract_features


def gap_attack(df: pd.DataFrame,
               gap_size: int = 50,
               num_gaps: int = 5,
               random_seed: int = 42) -> pd.DataFrame:
    """Simulate log deletion — gaps in sequence.

    Parameters:
        df (pd.DataFrame): Input feature-enriched DataFrame.
        gap_size (int): Number of consecutive rows to delete per gap.
        num_gaps (int): Number of deletion gaps to simulate.
        random_seed (int): Random seed for reproducibility.

    Returns:
        pd.DataFrame: Modified DataFrame with deleted rows and labeled boundary rows.

    Time Complexity: O(n) where n is the number of rows.
    Space Complexity: O(n) for the modified DataFrame.
    """
    np.random.seed(random_seed)
    df = df.copy()

    if 'tamper_type' not in df.columns:
        df['tamper_type'] = 'none'

    for _ in range(num_gaps):
        normal_indices = df[df['is_tampered'] == 0].index.tolist()
        if len(normal_indices) <= gap_size:
            break

        # Calculate safe buffer from ends
        if len(normal_indices) > 250:
            buffer = 100
        else:
            buffer = max(0, (len(normal_indices) - gap_size) // 4)

        min_pos = buffer
        max_pos = max(buffer, len(normal_indices) - gap_size - buffer)
        
        if max_pos > min_pos:
            start_pos = np.random.randint(min_pos, max_pos)
        else:
            start_pos = min_pos

        gap_indices = normal_indices[start_pos : start_pos + gap_size]

        # Mark up to 5 rows before gap as tampered
        before_indices = normal_indices[max(0, start_pos - 5) : start_pos]
        if before_indices:
            df.loc[before_indices, 'is_tampered'] = 1
            df.loc[before_indices, 'tamper_type'] = 'gap'

        # Mark up to 5 rows after gap as tampered
        after_indices = normal_indices[start_pos + gap_size : min(len(normal_indices), start_pos + gap_size + 5)]
        if after_indices:
            df.loc[after_indices, 'is_tampered'] = 1
            df.loc[after_indices, 'tamper_type'] = 'gap'

        # Delete the gap rows
        df = df.drop(index=gap_indices)

    df['tamper_type'] = df['tamper_type'].fillna('none')
    df = df.sort_values('time_created').reset_index(drop=True)
    df['delta_t'] = df['time_created'].diff().dt.total_seconds()
    df['delta_t'] = df['delta_t'].fillna(0.0).clip(lower=0.0)

    return df


def shuffle_attack(df: pd.DataFrame,
                   window: int = 200,
                   num_windows: int = 3,
                   random_seed: int = 42) -> pd.DataFrame:
    """Simulate timestamp manipulation.

    Parameters:
        df (pd.DataFrame): Input feature-enriched DataFrame.
        window (int): Size of the contiguous window to shuffle timestamps.
        num_windows (int): Number of windows to shuffle.
        random_seed (int): Random seed for reproducibility.

    Returns:
        pd.DataFrame: DataFrame with shuffled timestamps and updated delta_t.

    Time Complexity: O(n log n) due to sorting after shuffling.
    Space Complexity: O(n) for the modified DataFrame.
    """
    np.random.seed(random_seed)
    df = df.copy()

    if 'tamper_type' not in df.columns:
        df['tamper_type'] = 'none'

    n_rows = len(df)
    if n_rows > window:
        if n_rows > 500:
            buffer = 200
        else:
            buffer = max(0, (n_rows - window) // 4)

        min_pos = buffer
        max_pos = max(buffer, n_rows - window - buffer)

        for _ in range(num_windows):
            if max_pos > min_pos:
                start_pos = np.random.randint(min_pos, max_pos)
            else:
                start_pos = min_pos

            window_idx = df.index[start_pos : start_pos + window]
            times = df.loc[window_idx, 'time_created'].tolist()
            np.random.shuffle(times)
            df.loc[window_idx, 'time_created'] = times
            df.loc[window_idx, 'is_tampered'] = 1
            df.loc[window_idx, 'tamper_type'] = 'shuffle'

    df = df.sort_values('time_created').reset_index(drop=True)
    df['delta_t'] = df['time_created'].diff().dt.total_seconds()
    df['delta_t'] = df['delta_t'].fillna(0.0).clip(lower=0.0)

    return df


def injection_attack(df: pd.DataFrame,
                     num_injections: int = 500,
                     random_seed: int = 42) -> pd.DataFrame:
    """Simulate fake log entry injection.

    Parameters:
        df (pd.DataFrame): Input feature-enriched DataFrame.
        num_injections (int): Number of synthetic malicious log entries to inject.
        random_seed (int): Random seed for reproducibility.

    Returns:
        pd.DataFrame: Expanded DataFrame with injected fake records.

    Time Complexity: O(n log n) due to sorting after injection.
    Space Complexity: O(n + num_injections) for the expanded DataFrame.
    """
    np.random.seed(random_seed)
    df = df.copy()

    if 'tamper_type' not in df.columns:
        df['tamper_type'] = 'none'

    if len(df) == 0 or num_injections <= 0:
        return df

    # Sample rows from existing df as template
    sample_indices = np.random.choice(len(df), size=num_injections, replace=True)
    fake_df = df.iloc[sample_indices].copy().reset_index(drop=True)

    fake_accounts = ['FAKE_USER', 'BACKDOOR', 'INJECTED', 'MALWARE_SVC']
    fake_events = [4728, 4732, 4724, 4740]
    fake_processes = [
        r'C:\fake\malware.exe',
        r'C:\temp\backdoor.exe',
        r'C:\Windows\Temp\payload.exe'
    ]

    fake_df['account_name'] = np.random.choice(fake_accounts, size=num_injections)
    fake_df['event_id'] = np.random.choice(fake_events, size=num_injections)
    fake_df['process_name'] = np.random.choice(fake_processes, size=num_injections)
    fake_df['event_id_encoded'] = 0
    fake_df['process_is_suspicious'] = 1
    fake_df['is_tampered'] = 1
    fake_df['tamper_type'] = 'injection'

    df = pd.concat([df, fake_df], ignore_index=True)
    df = df.sort_values('time_created').reset_index(drop=True)
    df['delta_t'] = df['time_created'].diff().dt.total_seconds()
    df['delta_t'] = df['delta_t'].fillna(0.0).clip(lower=0.0)

    return df


def generate_labeled_dataset(input_filepath: str,
                              output_filepath: str,
                              random_seed: int = 42) -> pd.DataFrame:
    """Apply all 3 attacks → save labeled CSV.

    Parameters:
        input_filepath (str): Path to input clean/pre-processed CSV dataset.
        output_filepath (str): Destination path for the labeled dataset.
        random_seed (int): Random seed for reproducibility.

    Returns:
        pd.DataFrame: Final labeled tampered dataset.

    Time Complexity: O(n log n) where n is the number of rows.
    Space Complexity: O(n) for the output DataFrame.
    """
    # Step 1: Load and parse
    df = parse_csv_file(input_filepath)
    df = extract_features(df)

    # Step 2: Add tamper_type column defaulting to 'none'
    df['tamper_type'] = 'none'
    df.loc[df['is_tampered'] == 1, 'tamper_type'] = 'original'

    # Step 3: Apply all 3 attacks
    df = gap_attack(df, gap_size=50, num_gaps=8, random_seed=random_seed)
    df = shuffle_attack(df, window=200, num_windows=5, random_seed=random_seed)
    df = injection_attack(df, num_injections=800, random_seed=random_seed)

    # Step 4: Print summary
    total = len(df)
    tampered = int(df['is_tampered'].sum())
    normal = total - tampered
    ratio = (tampered / total) * 100.0

    print("=== LOGSHIELD DATASET GENERATION COMPLETE ===")
    print(f"Total rows:     {total:,}")
    print(f"Normal rows:    {normal:,} ({100-ratio:.1f}%)")
    print(f"Tampered rows:  {tampered:,} ({ratio:.1f}%)")
    print("Tamper types:")
    print(df['tamper_type'].value_counts())

    # Step 5: Validate ratio
    if ratio < 3.0:
        print("WARNING: Tampered ratio below 3% target")
    if ratio > 10.0:
        print("WARNING: Tampered ratio above 10% - too high")

    # Step 6: Save to output_filepath
    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
    df.to_csv(output_filepath, index=False)
    print(f"Saved to: {output_filepath}")

    return df
