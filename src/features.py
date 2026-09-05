"""
features.py -- Extracts 8 ML features from parsed
Windows Event Log DataFrame for LogShield models.
Time Complexity: O(n log n), Space Complexity: O(1) per row
"""
import pandas as pd
import numpy as np

CRITICAL_EVENT_IDS = [1102, 4719]
SUSPICIOUS_PROCESSES = [
    'wevtutil', 'whoami', 'net.exe', 'runas',
    'mimikatz', 'psexec', 'cmd.exe', 'powershell'
]

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add 8 ML feature columns to log DataFrame.

    Parameters:
        df (pd.DataFrame): Input DataFrame containing parsed log entries.

    Returns:
        pd.DataFrame: DataFrame with the 8 added ML feature columns.

    Time Complexity: O(n log n)
    Space Complexity: O(1) per row
    """
    try:
        # Copy to avoid SettingWithCopyWarning
        df = df.copy()
        
        # Step 1: Sort by time_created ascending
        df = df.sort_values('time_created').reset_index(drop=True)
        
        # Step 2: Add delta_t (float)
        df['delta_t'] = df['time_created'].diff().dt.total_seconds()
        df['delta_t'] = df['delta_t'].fillna(0.0)
        df['delta_t'] = df['delta_t'].clip(lower=0.0)
        
        # Step 3: Add event_frequency (int)
        times = df['time_created'].values
        window_starts = times - np.timedelta64(60, 's')
        left_indices = np.searchsorted(times, window_starts, side='left')
        right_indices = np.searchsorted(times, times, side='right')
        df['event_frequency'] = (right_indices - left_indices).astype(int)
        
        # Step 4: Add hour_of_day (int)
        df['hour_of_day'] = df['time_created'].dt.hour
        
        # Step 5: Add is_business_hours (int)
        df['is_business_hours'] = (
            (df['hour_of_day'] >= 9) &
            (df['hour_of_day'] <= 18)
        ).astype(int)
        
        # Step 6: Add event_id_encoded (int)
        encoding = {1102:1, 4719:2, 4624:3, 4625:4,
                    4634:5, 4688:6, 4663:7, 4672:8, 4698:9}
        df['event_id_encoded'] = df['event_id'].map(
            encoding).fillna(0).astype(int)
            
        # Step 7: Add is_critical_event (int)
        df['is_critical_event'] = df['event_id'].isin(
            CRITICAL_EVENT_IDS).astype(int)
            
        # Step 8: Add log_burst (int)
        df['log_burst'] = (df['event_frequency'] > 100).astype(int)
        
        # Step 9: Add process_is_suspicious (int)
        def check_suspicious(proc):
            if pd.isna(proc) or proc == 'UNKNOWN':
                return 0
            proc_lower = str(proc).lower()
            return int(any(s in proc_lower for s in SUSPICIOUS_PROCESSES))
            
        df['process_is_suspicious'] = df['process_name'].apply(
            check_suspicious)
            
        return df
    except Exception as e:
        print(f"Error in extract_features: {e}")
        return df

