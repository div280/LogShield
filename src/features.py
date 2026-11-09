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


class StreamingFeatureExtractor:
    """Stateful rolling feature extractor for real-time streaming events.

    Maintains rolling time windows to compute delta_t and 60-second frequency
    in real-time without buffering whole historical DataFrames.
    """

    def __init__(self, window_seconds: float = 60.0):
        """Initialize streaming state and rolling deque buffer.

        Parameters:
            window_seconds (float): Window size in seconds for frequency calculation.

        Returns:
            None

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self.window_seconds = float(window_seconds)
        self.last_event_time: Optional[pd.Timestamp] = None
        self.recent_timestamps: list = []
        self.encoding = {
            1102: 1, 4719: 2, 4624: 3, 4625: 4,
            4634: 5, 4688: 6, 4663: 7, 4672: 8, 4698: 9
        }

    def reset(self) -> None:
        """Reset historical state and clear timestamp buffer.

        Parameters:
            None

        Returns:
            None

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self.last_event_time = None
        self.recent_timestamps.clear()

    def extract_single(self, event: dict) -> dict:
        """Extract the 8 ML features for a single live incoming event.

        Parameters:
            event (dict): Ingested event dictionary containing time_created,
                          event_id, and process_name.

        Returns:
            dict: Event dictionary enriched with the 8 ML features.

        Time Complexity: O(k) where k is the number of events in the 60s window (typically k < 100).
        Space Complexity: O(1) per event.
        """
        res = dict(event)

        # Parse timestamp safely
        try:
            current_time = pd.to_datetime(res.get('time_created'), utc=True)
            if pd.isna(current_time):
                current_time = pd.Timestamp.now(tz='UTC')
        except Exception:
            current_time = pd.Timestamp.now(tz='UTC')

        # 1. delta_t
        if self.last_event_time is None:
            delta_t = 0.0
        else:
            diff_sec = (current_time - self.last_event_time).total_seconds()
            delta_t = max(0.0, float(diff_sec))
        self.last_event_time = current_time

        # 2. event_frequency in rolling window
        current_sec = current_time.timestamp()
        cutoff_sec = current_sec - self.window_seconds
        # Clean older timestamps
        self.recent_timestamps = [t for t in self.recent_timestamps if t >= cutoff_sec]
        self.recent_timestamps.append(current_sec)
        frequency = len(self.recent_timestamps)

        # 3. hour_of_day
        hour = int(current_time.hour)

        # 4. is_business_hours (9 to 18)
        is_bus = 1 if (9 <= hour <= 18) else 0

        # 5. event_id_encoded
        try:
            eid = int(res.get('event_id', 0))
        except (ValueError, TypeError):
            eid = 0
        eid_enc = int(self.encoding.get(eid, 0))

        # 6. is_critical_event
        is_crit = 1 if eid in CRITICAL_EVENT_IDS else 0

        # 7. log_burst
        burst = 1 if frequency > 100 else 0

        # 8. process_is_suspicious
        proc = str(res.get('process_name', '')).lower()
        is_susp_proc = int(any(s in proc for s in SUSPICIOUS_PROCESSES)) if proc and proc != 'unknown' else 0

        res['delta_t'] = delta_t
        res['event_frequency'] = frequency
        res['hour_of_day'] = hour
        res['is_business_hours'] = is_bus
        res['event_id_encoded'] = eid_enc
        res['is_critical_event'] = is_crit
        res['log_burst'] = burst
        res['process_is_suspicious'] = is_susp_proc

        return res


