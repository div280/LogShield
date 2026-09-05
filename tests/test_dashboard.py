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

def test_threat_panels_module_exists():
    assert os.path.exists(
        'dashboard/utils/threat_panels.py')

def test_threat_render_module_exists():
    assert os.path.exists(
        'dashboard/utils/threat_render.py')


def test_render_timeline_chart_builds_figure():
    import plotly.graph_objects as go
    from dashboard.app import render_timeline_chart

    class FakeStreamlit:
        last_fig = None

        @staticmethod
        def plotly_chart(fig, **kwargs):
            FakeStreamlit.last_fig = fig

    import dashboard.app as app_module
    original_st = app_module.st
    app_module.st = FakeStreamlit
    try:
        timeline = {
            'norm_times': ['2026-08-25 08:00:00+00:00'] * 1000,
            'norm_scores': [0.1] * 1000,
            'anom_times': ['2026-08-25 09:00:00+00:00'] * 50,
            'anom_scores': [0.9] * 50,
            'norm_count': 1000,
            'anom_count': 50,
        }
        render_timeline_chart(timeline, height=340)
        fig = FakeStreamlit.last_fig
        assert isinstance(fig, go.Figure)
        assert len(fig.layout.shapes) >= 1
        assert len(fig.layout.annotations) >= 1
    finally:
        app_module.st = original_st
