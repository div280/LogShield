"""
isolation_forest.py — Isolation Forest model for
detecting temporal gap anomalies in Windows Event Logs.
Trained on normal logs only (unsupervised).
Uses log-transformed delta_t for better gap detection.
Saves to: models_saved/isolation_forest.pkl
Time Complexity: O(n log n), Space Complexity: O(n)
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
from typing import Optional

FEATURE_COLUMNS = [
    'delta_t',
    'event_frequency',
    'hour_of_day',
    'is_business_hours',
    'event_id_encoded',
    'is_critical_event',
    'log_burst'
]


def train_isolation_forest(
        df: pd.DataFrame,
        contamination: float = 0.0666,
        random_state: int = 42) -> IsolationForest:
    """
    Train Isolation Forest on normal log rows only.

    Args:
        df: DataFrame with feature columns and is_tampered
        contamination: expected anomaly ratio (match dataset)
        random_state: for reproducibility

    Returns:
        Trained IsolationForest model

    Time Complexity: O(n log n)
    Space Complexity: O(n)
    """
    normal_df = df[df['is_tampered'] == 0].copy()

    X_train = normal_df[FEATURE_COLUMNS].fillna(0).copy()
    X_train['delta_t_log'] = np.log1p(X_train['delta_t'])
    X_train = X_train.drop(columns=['delta_t'])

    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=200,
        max_samples=256,
        max_features=1.0
    )
    model.fit(X_train)

    os.makedirs('models_saved', exist_ok=True)
    joblib.dump(model, 'models_saved/isolation_forest.pkl')

    print(f"Trained on {len(normal_df):,} normal rows")
    print(f"Features: {list(X_train.columns)}")
    print(f"Contamination: {contamination}")
    print(f"Saved to models_saved/isolation_forest.pkl")

    return model


def predict_anomalies(
        df: pd.DataFrame,
        model_path: str) -> pd.DataFrame:
    """
    Load trained model and predict anomalies.

    Args:
        df: DataFrame with feature columns
        model_path: path to saved .pkl model file

    Returns:
        DataFrame with added if_flag and if_score columns

    Time Complexity: O(n log n)
    Space Complexity: O(n)
    """
    model = joblib.load(model_path)
    df = df.copy()

    X = df[FEATURE_COLUMNS].fillna(0).copy()
    X['delta_t_log'] = np.log1p(X['delta_t'])
    X = X.drop(columns=['delta_t'])

    raw_predictions = model.predict(X)
    raw_scores = model.score_samples(X)

    df['if_flag'] = (raw_predictions == -1).astype(int)

    score_min = raw_scores.min()
    score_max = raw_scores.max()
    if score_max != score_min:
        normalized = (raw_scores - score_min) / (
            score_max - score_min)
    else:
        normalized = np.zeros(len(raw_scores))
    df['if_score'] = 1 - normalized

    return df


def evaluate_model(df: pd.DataFrame) -> dict:
    """
    Evaluate model performance against ground truth.

    Args:
        df: DataFrame with is_tampered and if_flag columns

    Returns:
        dict with precision, recall, f1, confusion_matrix

    Time Complexity: O(n)
    Space Complexity: O(1)
    """
    from sklearn.metrics import (
        precision_score, recall_score,
        f1_score, confusion_matrix)

    y_true = df['is_tampered']
    y_pred = df['if_flag']

    precision = precision_score(
        y_true, y_pred, zero_division=0)
    recall = recall_score(
        y_true, y_pred, zero_division=0)
    f1 = f1_score(
        y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print("=== LOGSHIELD ISOLATION FOREST RESULTS ===")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("Confusion Matrix:")
    print(cm)
    print(f"TN={cm[0][0]} FP={cm[0][1]}")
    print(f"FN={cm[1][0]} TP={cm[1][1]}")
    print()
    print("Per-attack-type detection:")
    if 'tamper_type' in df.columns:
        for attack in ['gap', 'shuffle',
                       'injection', 'original']:
            rows = df[df['tamper_type'] == attack]
            if len(rows) > 0:
                detected = rows['if_flag'].sum()
                total = len(rows)
                pct = detected / total * 100
                print(f"  {attack}: "
                      f"{detected}/{total} "
                      f"({pct:.1f}%)")

    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
        'tp': int(cm[1][1]),
        'fp': int(cm[0][1]),
        'tn': int(cm[0][0]),
        'fn': int(cm[1][0])
    }
