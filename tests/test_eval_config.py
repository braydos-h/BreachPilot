from __future__ import annotations

from pathlib import Path

import yaml

from tools.config_manager import CONFIG_SCHEMA, DEFAULT_CONFIG, ConfigValidator

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.yaml"


def test_default_config_has_eval_block():
    """CONFIG_SCHEMA exposes an ``eval`` top-level mapping."""
    assert "eval" in CONFIG_SCHEMA
    assert isinstance(CONFIG_SCHEMA["eval"], dict)


def test_eval_defaults():
    """The schema defaults match the harness contract."""
    ev = CONFIG_SCHEMA["eval"]
    assert ev["enabled"] is True
    assert ev["output_dir"] == "reports/eval"
    assert ev["max_rounds"] == 30
    assert ev["write_markdown"] is True
    assert ev["write_html"] is True


def test_config_yaml_has_eval_block():
    """The shipped config.yaml declares the ``eval`` block with the default output_dir."""
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "eval" in data
    assert isinstance(data["eval"], dict)
    assert data["eval"].get("output_dir") == "reports/eval"


def test_validator_accepts_eval_defaults():
    """The validator must report no errors for the default eval section."""
    validator = ConfigValidator(CONFIG_PATH)
    validator._config = dict(DEFAULT_CONFIG)
    result = validator.validate()
    assert not result.errors
