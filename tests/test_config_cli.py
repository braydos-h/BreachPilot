"""Tests for config.yaml persistence used by the interactive session flow."""

from __future__ import annotations

import yaml


def test_add_target_to_allowlist_persists_a_new_ip(tmp_path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text("exploit:\n  allowed_targets: []\n", encoding="utf-8")

    assert add_target_to_allowlist(config_path, "10.0.0.50") is True

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["10.0.0.50"]


def test_add_target_to_allowlist_retains_existing_config_comments(tmp_path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "# Operator configuration\n"
        "exploit:\n"
        "  # Explicitly authorized assets\n"
        "  allowed_targets: []\n"
        "  require_explicit_allowlist: true\n"
        "stealth:\n"
        "  rotate_ua: false\n",
        encoding="utf-8",
    )

    assert add_target_to_allowlist(config_path, "10.0.0.50") is True

    saved_text = config_path.read_text(encoding="utf-8")
    assert "# Operator configuration" in saved_text
    assert "  # Explicitly authorized assets" in saved_text
    assert "  require_explicit_allowlist: true" in saved_text
    assert yaml.safe_load(saved_text)["exploit"]["allowed_targets"] == ["10.0.0.50"]


def test_add_target_to_allowlist_normalizes_and_deduplicates_ips(tmp_path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exploit:\n  allowed_targets:\n    - 2001:db8::1\n",
        encoding="utf-8",
    )

    assert add_target_to_allowlist(config_path, "2001:0db8:0:0:0:0:0:1") is False

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["2001:db8::1"]


def test_add_target_to_allowlist_appends_to_block_style_list(tmp_path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exploit:\n  allowed_targets:\n    - 10.0.0.50\n  require_explicit_allowlist: true\n",
        encoding="utf-8",
    )

    assert add_target_to_allowlist(config_path, "10.0.0.51") is True

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["10.0.0.50", "10.0.0.51"]


def test_add_target_to_allowlist_rejects_invalid_ip(tmp_path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text("exploit:\n  allowed_targets: []\n", encoding="utf-8")

    try:
        add_target_to_allowlist(config_path, "not-an-ip")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected an invalid target to be rejected")
