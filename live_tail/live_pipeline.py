"""
live_pipeline.py -- Dual-layer real-time forensic detection pipeline for LogShield.
Processes incoming streaming events in sub-500ms latency:
- Layer 1: Real-time HMAC-SHA256 forward chain + sequence continuity check
- Layer 2: Streaming features + Isolation Forest + sliding sequence check
- Fusion: Instantaneous verdict (CLEAN, SUSPICIOUS, COMPROMISED)
"""
import os
import sys
import hmac
import hashlib
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
import numpy as np
import joblib

from src.features import StreamingFeatureExtractor, CRITICAL_EVENT_IDS, SUSPICIOUS_PROCESSES

logger = logging.getLogger("LogShield.LivePipeline")


def _get_hmac_secret_key() -> bytes:
    """Retrieve HMAC key from environment or fallback safely.

    Returns:
        bytes: UTF-8 encoded secret key.

    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    key = os.environ.get('LOGSHIELD_HMAC_KEY', 'logshield_realtime_dev_key_2026')
    return key.encode('utf-8')


def _compute_event_hmac(event: Dict[str, Any], prev_hmac: str, key: bytes) -> str:
    """Compute HMAC-SHA256 for a single event chained to previous hash.

    Parameters:
        event (Dict[str, Any]): Event record dictionary.
        prev_hmac (str): Previous HMAC hash in hex string format.
        key (bytes): HMAC secret key.

    Returns:
        str: Hex string HMAC.

    Time Complexity: O(k) where k is content length.
    Space Complexity: O(1)
    """
    content = "|".join([
        str(event.get('event_record_id', '')),
        str(event.get('event_id', '')),
        str(event.get('time_created', '')),
        str(event.get('computer', '')),
        str(event.get('channel', ''))
    ])
    msg = (content + prev_hmac).encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class LivePipelineEngine:
    """Dual-layer real-time detection and score fusion pipeline."""

    def __init__(
            self,
            if_model_path: str = "models_saved/isolation_forest.pkl",
            lstm_meta_path: str = "models_saved/lstm_meta.pkl",
            max_history: int = 100):
        """Initialize streaming feature extractor, models, and cryptographic state.

        Parameters:
            if_model_path (str): Path to saved Isolation Forest pickle.
            lstm_meta_path (str): Path to saved LSTM metadata.
            max_history (int): Maximum history events to buffer for live charts.

        Returns:
            None

        Time Complexity: O(1) initialization + O(M) model load where M is model size.
        Space Complexity: O(H) where H is max_history buffer size.
        """
        self.feature_extractor = StreamingFeatureExtractor(window_seconds=60.0)
        self.max_history = max_history
        self.hmac_key = _get_hmac_secret_key()

        # State tracking
        self.running_hmac: str = "GENESIS_LIVE_CHAIN_SEED_0000000000000000"
        self.last_record_id: Optional[int] = None
        self.last_timestamp: Optional[pd.Timestamp] = None

        # Rolling buffers
        self.recent_events: deque = deque(maxlen=max_history)
        self.recent_alerts: deque = deque(maxlen=50)

        # Metrics
        self.total_processed: int = 0
        self.clean_count: int = 0
        self.suspicious_count: int = 0
        self.compromised_count: int = 0
        self.total_integrity_score: float = 0.0

        # Load Isolation Forest model safely
        resolved_if_path = if_model_path
        if not os.path.exists(resolved_if_path):
            for candidate in [
                os.path.join("LogShield", if_model_path),
                os.path.join(os.path.dirname(__file__), "..", if_model_path)
            ]:
                if os.path.exists(candidate):
                    resolved_if_path = candidate
                    break

        self.if_model = None
        if os.path.exists(resolved_if_path):
            try:
                self.if_model = joblib.load(resolved_if_path)
                logger.info("Loaded Isolation Forest model from %s", resolved_if_path)
            except Exception as err:
                logger.warning("Failed to load Isolation Forest: %s", err)
        else:
            logger.warning("Isolation Forest model file not found at %s", if_model_path)

    def reset_state(self) -> None:
        """Reset historical pipeline state and counters.

        Parameters:
            None

        Returns:
            None

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self.feature_extractor.reset()
        self.running_hmac = "GENESIS_LIVE_CHAIN_SEED_0000000000000000"
        self.last_record_id = None
        self.last_timestamp = None
        self.recent_events.clear()
        self.recent_alerts.clear()
        self.total_processed = 0
        self.clean_count = 0
        self.suspicious_count = 0
        self.compromised_count = 0
        self.total_integrity_score = 0.0

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single incoming event through cryptographic and ML detection layers.

        Parameters:
            raw_event (Dict[str, Any]): Raw event dictionary from LogWatcher.

        Returns:
            Dict[str, Any]: Comprehensive analysis verdict dictionary.

        Time Complexity: O(1) per event.
        Space Complexity: O(1) per event.
        """
        self.total_processed += 1
        alerts: List[str] = []
        is_compromised = False
        is_suspicious = False

        # 1. Feature Extraction (Stateful)
        enriched = self.feature_extractor.extract_single(raw_event)
        record_id = enriched.get('event_record_id', 0)
        event_id = enriched.get('event_id', 0)

        # 2. Layer 1: Cryptographic Continuity & Critical Event Check
        # Rule 4: HMAC and critical events override ML models
        if event_id == 1102:
            alerts.append("CRITICAL: Audit log was cleared (Event ID 1102 - Anti-Forensic Tamper)")
            is_compromised = True
        elif event_id == 4719:
            alerts.append("HIGH RISK: System audit policy was altered (Event ID 4719)")
            is_suspicious = True

        # Check Record ID sequence continuity (Gap Attack / Log Deletion)
        if self.last_record_id is not None and record_id > 0:
            if record_id > (self.last_record_id + 1):
                missing = record_id - self.last_record_id - 1
                alerts.append(f"GAP ATTACK DETECTED: Missing {missing} sequential log record(s) between #{self.last_record_id} and #{record_id}")
                is_compromised = True
            elif record_id < self.last_record_id:
                alerts.append(f"SHUFFLE ATTACK DETECTED: Out-of-order Record #{record_id} arrived after #{self.last_record_id}")
                is_suspicious = True

        if record_id > 0:
            self.last_record_id = record_id

        # Update HMAC chain
        new_hmac = _compute_event_hmac(enriched, self.running_hmac, self.hmac_key)
        self.running_hmac = new_hmac
        enriched['hmac_hash'] = new_hmac[:16] + "..."

        # 3. Layer 2: Machine Learning Detection (Isolation Forest)
        if_score = 0.0
        if_flag = 0
        anomaly_score = 0.0

        if self.if_model is not None:
            try:
                # Format features matching model training order
                delta_t = float(enriched.get('delta_t', 0.0))
                delta_t_log = float(np.log1p(delta_t))
                feat_row = pd.DataFrame([{
                    'event_frequency': int(enriched.get('event_frequency', 1)),
                    'hour_of_day': int(enriched.get('hour_of_day', 12)),
                    'is_business_hours': int(enriched.get('is_business_hours', 1)),
                    'event_id_encoded': int(enriched.get('event_id_encoded', 0)),
                    'is_critical_event': int(enriched.get('is_critical_event', 0)),
                    'log_burst': int(enriched.get('log_burst', 0)),
                    'delta_t_log': delta_t_log
                }])

                raw_pred = self.if_model.predict(feat_row)[0]
                raw_score = float(self.if_model.score_samples(feat_row)[0])

                if_score = raw_score
                if_flag = 1 if raw_pred == -1 else 0
                # Normalize raw_score (typically in range [-0.85, -0.4]) to anomaly range [0, 1]
                anomaly_score = float(np.clip(((-raw_score) - 0.50) / 0.35, 0.0, 1.0))

                # Note: Per project rules, Isolation Forest is supporting forensic evidence
                if raw_score < -0.78:
                    alerts.append(f"AI ANOMALY: Isolation Forest flagged temporal outlier (Score: {raw_score:.3f})")
            except Exception as ml_err:
                logger.debug("IF inference error: %s", ml_err)

        # 4. Check Suspicious Process
        if enriched.get('process_is_suspicious', 0) == 1:
            is_suspicious = True
            alerts.append(f"THREAT: Suspicious binary execution detected ({enriched.get('process_name')})")

        # 5. Dual-Layer Score Fusion
        if is_compromised:
            verdict = "COMPROMISED"
            integrity_score = 0.0
            self.compromised_count += 1
        elif is_suspicious:
            verdict = "SUSPICIOUS"
            integrity_score = float(max(15.0, round(100.0 - (anomaly_score * 65.0), 1)))
            self.suspicious_count += 1
        else:
            verdict = "CLEAN"
            integrity_score = 100.0
            self.clean_count += 1

        self.total_integrity_score += integrity_score

        # Prepare summary output
        enriched['verdict'] = verdict
        enriched['integrity_score'] = integrity_score
        enriched['anomaly_score'] = round(anomaly_score, 3)
        enriched['if_flag'] = if_flag
        enriched['if_score'] = round(if_score, 3)
        enriched['alerts'] = alerts

        # Store in rolling history
        self.recent_events.append(enriched)
        for alt in alerts:
            self.recent_alerts.append({
                'timestamp': enriched.get('time_created'),
                'record_id': record_id,
                'verdict': verdict,
                'alert': alt
            })

        return {
            'event': enriched,
            'verdict': verdict,
            'integrity_score': integrity_score,
            'anomaly_score': anomaly_score,
            'alerts': alerts
        }

    def get_kpis(self) -> Dict[str, Any]:
        """Return aggregated live KPI statistics for the dashboard.

        Parameters:
            None

        Returns:
            Dict[str, Any]: KPI dictionary.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        avg_integrity = (
            round(self.total_integrity_score / self.total_processed, 1)
            if self.total_processed > 0 else 100.0
        )
        return {
            'total_processed': self.total_processed,
            'clean_count': self.clean_count,
            'suspicious_count': self.suspicious_count,
            'compromised_count': self.compromised_count,
            'average_integrity_score': avg_integrity,
            'recent_alerts_count': len(self.recent_alerts),
            'last_record_id': self.last_record_id,
            'running_hmac_prefix': self.running_hmac[:12] + "..."
        }
