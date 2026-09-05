import pytest
import os
import sys
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..'))

def test_dashboard_file_exists():
    assert os.path.exists('dashboard/app.py')

def test_config_file_exists():
    assert os.path.exists('.streamlit/config.toml')

def test_pdf_report_module_exists():
    assert os.path.exists(
        'dashboard/utils/pdf_report.py')

def test_isolation_forest_model_exists():
    assert os.path.exists(
        'models_saved/isolation_forest.pkl')

def test_hmac_chain_exists():
    assert os.path.exists(
        'models_saved/hmac_chain.json')

def test_streamlit_importable():
    import streamlit
    assert True

def test_plotly_importable():
    import plotly.graph_objects as go
    assert True

def test_parse_csv_from_bytes_exists():
    from src.parser import parse_csv_from_bytes
    assert callable(parse_csv_from_bytes)
