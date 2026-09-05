"""
parser.py — Parses Windows .evtx files and pre-parsed
CSV files into structured DataFrames for LogShield.
Input: .evtx file path OR pre-parsed CSV path
Output: pandas DataFrame with standardized columns
Time Complexity: O(n), Space Complexity: O(n)
"""
import pandas as pd
import numpy as np
import os
from typing import Optional
import xml.etree.ElementTree as ET

def parse_evtx_file(filepath: str,
                    max_records: Optional[int] = None
                    ) -> pd.DataFrame:
    """Parse .evtx file → DataFrame. O(n) time.

    Parameters:
        filepath (str): Path to the .evtx file.
        max_records (Optional[int]): Maximum number of records to parse.

    Returns:
        pd.DataFrame: Structured DataFrame of event log records.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    if not filepath.lower().endswith('.evtx'):
        raise ValueError("Only .evtx files accepted")
        
    # Prevent path traversal
    safe_path = os.path.normpath(filepath)
    parts = safe_path.split(os.sep)
    if '..' in parts or safe_path.startswith('..'):
        raise ValueError("Path traversal detected")
        
    if not os.path.exists(safe_path):
        raise FileNotFoundError(f"File not found: {safe_path}")
        
    if os.path.getsize(safe_path) > 50 * 1024 * 1024:
        raise ValueError("File exceeds 50MB limit")
        
    import Evtx.Evtx as evtx
    
    records = []
    try:
        with evtx.Evtx(safe_path) as log:
            for idx, record in enumerate(log.records()):
                if max_records is not None and idx >= max_records:
                    break
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    
                    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    
                    event_id_el = root.find('ns:System/ns:EventID', ns)
                    event_id_val = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0
                    
                    time_created_el = root.find('ns:System/ns:TimeCreated', ns)
                    time_created_val = time_created_el.get('SystemTime') if time_created_el is not None else None
                    if time_created_val:
                        time_created_dt = pd.to_datetime(time_created_val, utc=True)
                    else:
                        time_created_dt = pd.NaT
                        
                    computer_el = root.find('ns:System/ns:Computer', ns)
                    computer_val = computer_el.text if computer_el is not None else 'UNKNOWN'
                    
                    provider_el = root.find('ns:System/ns:Provider', ns)
                    provider_val = provider_el.get('Name') if provider_el is not None else 'UNKNOWN'
                    
                    channel_el = root.find('ns:System/ns:Channel', ns)
                    channel_val = channel_el.text if channel_el is not None else 'UNKNOWN'
                    
                    level_el = root.find('ns:System/ns:Level', ns)
                    try:
                        level_val = int(level_el.text) if level_el is not None and level_el.text else 0
                    except Exception:
                        level_val = 0
                        
                    event_data_el = root.find('ns:EventData', ns)
                    event_data_str = ''
                    account_name = 'UNKNOWN'
                    process_name = 'UNKNOWN'
                    
                    if event_data_el is not None:
                        event_data_str = ET.tostring(event_data_el, encoding='utf-8').decode('utf-8')
                        
                        data_dict = {}
                        for d in event_data_el.findall('ns:Data', ns):
                            name = d.get('Name')
                            if name:
                                data_dict[name] = d.text if d.text is not None else ''
                                
                        for key in ['TargetUserName', 'SubjectUserName', 'UserName', 'AccountName']:
                            if key in data_dict and data_dict[key]:
                                account_name = data_dict[key]
                                break
                                
                        for key in ['NewProcessName', 'ProcessName', 'Image', 'ProcessPath']:
                            if key in data_dict and data_dict[key]:
                                process_name = data_dict[key]
                                break
                                
                    row = {
                        'source_file': os.path.basename(safe_path),
                        'event_record_id': idx + 1,
                        'event_id': event_id_val,
                        'time_created': time_created_dt,
                        'computer': computer_val,
                        'provider': provider_val,
                        'channel': channel_val,
                        'level': level_val,
                        'task': 0,
                        'account_name': account_name,
                        'process_name': process_name,
                        'event_data': event_data_str,
                        'raw_xml_length': len(xml_str),
                        'is_tampered': 0
                    }
                    records.append(row)
                except Exception as e:
                    print(f"Warning: Skipping malformed record: {e}")
                    continue
    except Exception as e:
        raise ValueError(f"Error parsing .evtx file: {e}")
        
    df = pd.DataFrame(records)
    if df.empty:
        columns = [
            'source_file', 'event_record_id', 'event_id', 'time_created',
            'computer', 'provider', 'channel', 'level', 'task',
            'account_name', 'process_name', 'event_data', 'raw_xml_length', 'is_tampered'
        ]
        df = pd.DataFrame(columns=columns)
        df['time_created'] = pd.to_datetime(df['time_created'], utc=True)
        df['event_id'] = df['event_id'].astype(int)
        df['event_record_id'] = df['event_record_id'].astype(int)
        df['raw_xml_length'] = df['raw_xml_length'].astype(int)
        df['is_tampered'] = df['is_tampered'].astype(int)
        df['level'] = df['level'].astype(int)
        df['task'] = df['task'].astype(int)
        
    validate_dataframe(df)
    return df

def parse_csv_file(filepath: str) -> pd.DataFrame:
    """Parse pre-processed CSV → DataFrame. O(n) time.

    Parameters:
        filepath (str): Path to the pre-processed CSV file.

    Returns:
        pd.DataFrame: Structured DataFrame of event log records.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    # Sanitize path - normalize but keep full path
    safe_path = os.path.normpath(
        os.path.abspath(filepath))
    
    # Check extension using basename only
    ext = os.path.splitext(
        os.path.basename(safe_path))[1].lower()
    if ext != '.csv':
        raise ValueError(
            f"Only .csv files accepted. "
            f"Got: {ext}")
    
    # Check file size
    if not os.path.exists(safe_path):
        raise FileNotFoundError(f"File not found: {safe_path}")
    if os.path.getsize(safe_path) > 50 * 1024 * 1024:
        raise ValueError(
            "File exceeds 50MB limit")
    
    # Read CSV
    df = pd.read_csv(safe_path, low_memory=False)
    
    # Parse timestamps
    df['time_created'] = pd.to_datetime(
        df['time_created'], utc=True, errors='coerce')
    
    # Fill nulls
    if 'account_name' in df.columns:
        df['account_name'] = (
            df['account_name'].fillna('UNKNOWN'))
    else:
        df['account_name'] = 'UNKNOWN'

    if 'process_name' in df.columns:
        df['process_name'] = (
            df['process_name'].fillna('UNKNOWN'))
    else:
        df['process_name'] = 'UNKNOWN'

    if 'event_data' in df.columns:
        df['event_data'] = (
            df['event_data'].fillna(''))
    
    # Ensure event_id is integer
    if 'event_id' in df.columns:
        df['event_id'] = pd.to_numeric(
            df['event_id'],
            errors='coerce').fillna(0).astype(int)
    else:
        df['event_id'] = 0
    
    # Validate
    validate_dataframe(df)
    
    return df

def parse_csv_from_bytes(file_bytes: bytes
                          ) -> pd.DataFrame:
    """
    Parse CSV directly from bytes (no temp file).
    Used by dashboard to avoid Windows file locking.
    
    Args:
        file_bytes: raw bytes from st.file_uploader
    Returns:
        pd.DataFrame with standardized columns
    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    import io
    
    # Read directly from bytes buffer
    buffer = io.BytesIO(file_bytes)
    df = pd.read_csv(buffer, low_memory=False)
    
    # Parse timestamps
    df['time_created'] = pd.to_datetime(
        df['time_created'], utc=True, errors='coerce')
    
    # Fill nulls
    df['account_name'] = (
        df['account_name'].fillna('UNKNOWN'))
    df['process_name'] = (
        df['process_name'].fillna('UNKNOWN'))
    if 'event_data' in df.columns:
        df['event_data'] = (
            df['event_data'].fillna(''))
    
    # Ensure event_id is integer
    df['event_id'] = pd.to_numeric(
        df['event_id'],
        errors='coerce').fillna(0).astype(int)
    
    # Validate
    validate_dataframe(df)
    
    return df

def validate_dataframe(df: pd.DataFrame) -> bool:
    """Validate DataFrame has required columns.

    Parameters:
        df (pd.DataFrame): The DataFrame to validate.

    Returns:
        bool: True if the DataFrame is valid, False otherwise.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    required_cols = ['event_id', 'time_created', 'computer', 'is_tampered']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing columns: {missing_cols}")
        
    if df['event_id'].isnull().any():
        raise ValueError("event_id contains null values")
        
    if not pd.api.types.is_datetime64_any_dtype(df['time_created']):
        raise ValueError("time_created must be datetime data type")
        
    return True
