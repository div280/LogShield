import pytest
import pandas as pd
import numpy as np
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))
from src.models.isolation_forest import (
    train_isolation_forest,
    predict_anomalies,
    evaluate_model)

np.random.seed(42)
normal_rows = pd.DataFrame({
    'delta_t': np.random.exponential(2, 180),
    'event_frequency': np.random.randint(1, 10, 180),
    'hour_of_day': np.random.randint(9, 18, 180),
    'is_business_hours': [1] * 180,
    'event_id_encoded': np.random.randint(3, 8, 180),
    'is_critical_event': [0] * 180,
    'log_burst': [0] * 180,
    'process_is_suspicious': [0] * 180,
    'is_tampered': [0] * 180,
    'tamper_type': ['none'] * 180
})
attack_rows = pd.DataFrame({
    'delta_t': np.random.exponential(500, 20),
    'event_frequency': np.random.randint(100, 200, 20),
    'hour_of_day': np.random.randint(0, 5, 20),
    'is_business_hours': [0] * 20,
    'event_id_encoded': [1] * 20,
    'is_critical_event': [1] * 20,
    'log_burst': [1] * 20,
    'process_is_suspicious': [1] * 20,
    'is_tampered': [1] * 20,
    'tamper_type': ['gap'] * 20
})
SAMPLE_DATA = pd.concat(
    [normal_rows, attack_rows],
    ignore_index=True)

def test_model_trains_without_error(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    model = train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    assert model is not None

def test_model_pkl_file_created(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    assert os.path.exists(model_path)

def test_predictions_add_if_flag_column(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    assert 'if_flag' in result.columns

def test_predictions_add_if_score_column(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    assert 'if_score' in result.columns

def test_if_flag_is_binary(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    assert result['if_flag'].isin([0, 1]).all()

def test_if_score_between_0_and_1(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    assert (result['if_score'] >= 0).all()
    assert (result['if_score'] <= 1).all()

def test_evaluate_returns_all_metrics(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    metrics = evaluate_model(result)
    assert 'precision' in metrics
    assert 'recall' in metrics
    assert 'f1' in metrics
    assert 'confusion_matrix' in metrics

def test_model_detects_obvious_anomalies(tmp_path):
    model_path = str(tmp_path / "isolation_forest.pkl")
    train_isolation_forest(
        SAMPLE_DATA, random_state=42, model_save_path=model_path)
    result = predict_anomalies(
        SAMPLE_DATA.copy(), model_path)
    attack_detected = result[
        result['is_tampered']==1]['if_flag'].sum()
    assert attack_detected > 0

