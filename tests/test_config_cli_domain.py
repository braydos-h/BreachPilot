"""Tests for config_cli.add_target_to_allowlist with domain targets.

Domain targeting (Phase 1) relaxed ``add_target_to_allowlist`` to accept a
domain or ``*.wildcard`` alongside an IP. IPs are normalized via
``ipaddress.ip_address`` for deduplication; domains are persisted verbatim.
Genuinely malformed input (neither IP nor domain) is still rejected with
``ValueError``.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def test_add_domain_to_allowlist_persists_verbatim(tmp_path: Path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text("exploit:\n  allowed_targets: []\n", encoding="utf-8")

    assert add_target_to_allowlist(config_path, "example.com") is True

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["example.com"]


def test_add_wildcard_domain_to_allowlist(tmp_path: Path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text("exploit:\n  allowed_targets: []\n", encoding="utf-8")

    assert add_target_to_allowlist(config_path, "*.example.com") is True

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["*.example.com"]


def test_add_domain_deduplicates_case_insensitive(tmp_path: Path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exploit:\n  allowed_targets:\n    - example.com\n", encoding="utf-8"
    )

    # Same domain in different case should be a duplicate.
    assert add_target_to_allowlist(config_path, "EXAMPLE.COM") is False

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["exploit"]["allowed_targets"] == ["example.com"]


def test_add_domain_alongside_existing_ip(tmp_path: Path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exploit:\n  allowed_targets:\n    - 10.0.0.5\n", encoding="utf-8"
    )

    assert add_target_to_allowlist(config_path, "example.com") is True

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert "10.0.0.5" in saved["exploit"]["allowed_targets"]
    assert "example.com" in saved["exploit"]["allowed_targets"]


def test_add_garbage_target_still_rejected(tmp_path: Path):
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text("exploit:\n  allowed_targets: []\n", encoding="utf-8")

    # "not-an-ip" is neither a valid IP nor a valid FQDN.
    import pytest
    with pytest.raises(ValueError):
        add_target_to_allowlist(config_path, "not-an-ip")


def test_add_ip_still_normalizes(tmp_path: Path):
    """IPs are still normalized via ipaddress for deduplication."""
    from tools.config_cli import add_target_to_allowlist

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exploit:\n  allowed_targets:\n    - 2001:db8::1\n", encoding="utf-8"
    )

    # Equivalent IPv6 spelling should be detected as a duplicate.
    assert add_target_to_allowlist(config_path, "2001:0db8:0:0:0:0:0:1") is False