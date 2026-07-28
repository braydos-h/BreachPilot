from __future__ import annotations

from pathlib import Path

import yaml

from tools.config_manager import DEFAULT_CONFIG, KNOWN_TOP_KEYS


def test_default_config_has_autonomous_block() -> None:
    """DEFAULT_CONFIG exposes a top-level ``autonomous`` dict."""
    assert "autonomous" in DEFAULT_CONFIG
    assert isinstance(DEFAULT_CONFIG["autonomous"], dict)


def test_autonomous_defaults_off() -> None:
    """All Phase 2 capabilities default OFF / 0 so default behavior is unchanged."""
    auto = DEFAULT_CONFIG["autonomous"]
    assert auto["persistence_phase"] is False
    assert auto["checkpoint_every"] == 0
    assert auto["adaptive_replan"] is False
    assert auto["max_cycles"] == 100
    assert auto["max_pivot_depth"] == 0


def test_autonomous_in_known_top_keys() -> None:
    """``autonomous`` is a recognized top-level key so the validator won't drop it."""
    assert "autonomous" in KNOWN_TOP_KEYS


def test_config_yaml_has_autonomous_block() -> None:
    """config.yaml mirrors the DEFAULT_CONFIG autonomous block with the same defaults."""
    config_path = Path(__file__).resolve().parents[1] / "config.yaml"
    with config_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    assert "autonomous" in cfg
    auto = cfg["autonomous"]
    assert isinstance(auto, dict)
    assert auto["persistence_phase"] is False
    assert auto["checkpoint_every"] == 0