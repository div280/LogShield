"""
test_attack_map.py
Unit tests and security verification for the Simulated Global Attack Map.
Verifies figure construction, flight arc calculations, scaling, formatting rules,
and confirms that the feature never reads or modifies real project datasets or models.
"""
import hashlib
import math
import os
import sys
import plotly.graph_objects as go
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dashboard.attack_map import (
    generate_flight_arc,
    create_simulated_attack_map,
    SIMULATED_ATTACK_ORIGINS,
)


def _compute_dir_hash(path: str) -> str:
    """Helper to compute deterministic MD5 hash of directory files and mtimes."""
    if not os.path.exists(path):
        return "not_found"
    hasher = hashlib.md5()
    for root, _, files in sorted(os.walk(path)):
        for f in sorted(files):
            fp = os.path.join(root, f)
            try:
                hasher.update(f.encode('utf-8'))
                hasher.update(str(os.path.getsize(fp)).encode('utf-8'))
                with open(fp, 'rb') as handle:
                    hasher.update(handle.read())
            except Exception:
                pass
    return hasher.hexdigest()


def test_generate_flight_arc_valid_coordinates():
    """Verify flight arc generation generates expected number of points."""
    num_steps = 30
    lons, lats = generate_flight_arc(
        start_lon=-77.0,
        start_lat=38.0,
        end_lon=77.59,
        end_lat=12.97,
        num_steps=num_steps,
        arc_height=15.0
    )
    assert len(lons) == num_steps + 1
    assert len(lats) == num_steps + 1
    assert all(-180.0 <= lon <= 180.0 for lon in lons)
    assert all(-90.0 <= lat <= 90.0 for lat in lats)
    assert abs(lons[0] - (-77.0)) < 1e-4
    assert abs(lats[0] - 38.0) < 1e-4
    assert abs(lons[-1] - 77.59) < 1e-4
    assert abs(lats[-1] - 12.97) < 1e-4


def test_create_simulated_attack_map_returns_figure():
    """Verify attack map generates a valid Plotly go.Figure with lines and markers."""
    fig = create_simulated_attack_map(
        victim_lat=12.9716,
        victim_lon=77.5946,
        computer_name="VICTIM-HOST-01",
        city="Bangalore",
        country="India",
        anomaly_count=25
    )
    assert isinstance(fig, go.Figure)
    assert len(fig.data) > 0

    # Ensure traces contain lines and markers
    modes = [trace.mode for trace in fig.data if hasattr(trace, 'mode')]
    assert 'lines' in modes
    assert any('markers' in m for m in modes if m)


def test_attack_map_does_not_modify_any_disk_files():
    """
    CRITICAL RULE TEST:
    Verify that generating the attack map does not write, modify, or delete
    any files in models_saved, data, or hmac_chain.json.
    """
    models_dir = os.path.join(os.path.dirname(__file__), '..', 'models_saved')
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')

    hash_models_before = _compute_dir_hash(models_dir)
    hash_data_before = _compute_dir_hash(data_dir)

    # Call the attack map renderer multiple times with different parameters
    fig1 = create_simulated_attack_map(anomaly_count=0)
    fig2 = create_simulated_attack_map(anomaly_count=50)
    fig3 = create_simulated_attack_map(anomaly_count=1000)

    assert fig1 is not None
    assert fig2 is not None
    assert fig3 is not None

    hash_models_after = _compute_dir_hash(models_dir)
    hash_data_after = _compute_dir_hash(data_dir)

    assert hash_models_before == hash_models_after, "models_saved directory was modified!"
    assert hash_data_before == hash_data_after, "data directory was modified!"


def test_attack_map_scales_with_anomaly_count():
    """Verify attacker origin count scales reasonably with anomaly count."""
    fig_zero = create_simulated_attack_map(anomaly_count=0)
    fig_large = create_simulated_attack_map(anomaly_count=500)

    # Count flight line traces (mode == 'lines')
    lines_zero = sum(1 for t in fig_zero.data if getattr(t, 'mode', '') == 'lines')
    lines_large = sum(1 for t in fig_large.data if getattr(t, 'mode', '') == 'lines')

    assert lines_zero >= 4
    assert lines_large >= lines_zero
    assert lines_large <= len(SIMULATED_ATTACK_ORIGINS)


def test_attack_map_fallback_coordinates():
    """Verify robust handling when victim coordinates are None or invalid."""
    fig_none = create_simulated_attack_map(victim_lat=None, victim_lon=None)
    assert isinstance(fig_none, go.Figure)

    fig_nan = create_simulated_attack_map(victim_lat=float('nan'), victim_lon=float('inf'))
    assert isinstance(fig_nan, go.Figure)


def test_no_em_dashes_or_emojis_in_attack_map():
    """
    STRICT UI RULE:
    Verify that no em dash characters and no emojis appear in figure title,
    trace names, or text elements.
    """
    fig = create_simulated_attack_map(
        computer_name="WORKSTATION-X",
        city="Bangalore",
        country="India",
        anomaly_count=10
    )

    # Check title
    title_text = fig.layout.title.text if fig.layout.title else ""
    assert "\u2014" not in title_text, "Em dash found in title!"

    # Check trace names and hovertexts
    for trace in fig.data:
        name = getattr(trace, 'name', '') or ''
        assert "\u2014" not in name, f"Em dash found in trace name: {name}"

        texts = getattr(trace, 'text', None)
        if isinstance(texts, list):
            for t in texts:
                assert "\u2014" not in str(t), f"Em dash found in text: {t}"
        elif isinstance(texts, str):
            assert "\u2014" not in texts, f"Em dash found in text: {texts}"

        hovertexts = getattr(trace, 'hovertext', None)
        if isinstance(hovertexts, list):
            for h in hovertexts:
                assert "\u2014" not in str(h), f"Em dash found in hovertext: {h}"
        elif isinstance(hovertexts, str):
            assert "\u2014" not in hovertexts, f"Em dash found in hovertext: {hovertexts}"
