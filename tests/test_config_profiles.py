"""Tests for layered config profiles (lab / recon / ci) + stealth deprecation."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml


def test_list_profiles_covers_lab_recon_ci():
    from tools.config.profiles import list_profiles

    assert list_profiles() == ["lab", "recon", "ci"]


def test_get_profile_unknown_raises():
    from tools.config.profiles import get_profile

    with pytest.raises(ValueError, match="Unknown config profile"):
        get_profile("nope")


def test_get_profile_returns_copy():
    from tools.config.profiles import PROFILES, get_profile

    overlay = get_profile("recon")
    overlay["exploit"]["permission"] = "mutated"
    assert PROFILES["recon"]["exploit"]["permission"] == "read_only"


def test_apply_profile_does_not_mutate_input():
    from tools.config.profiles import apply_profile

    base = {"exploit": {"permission": "full_access", "attack_mode": True}}
    snapshot = copy.deepcopy(base)
    merged = apply_profile(base, "recon")
    assert base == snapshot
    assert merged["exploit"]["permission"] == "read_only"
    assert merged is not base


def test_lab_profile_restates_full_access_default():
    """The lab default is load-bearing — profiles must not change it."""
    from tools.config.profiles import apply_profile
    from tools.config.schema import CONFIG_SCHEMA

    assert CONFIG_SCHEMA["exploit"]["permission"] == "full_access"
    merged = apply_profile({"exploit": {}}, "lab")
    assert merged["exploit"]["permission"] == "full_access"
    assert merged["exploit"]["attack_mode"] is True
    assert merged["sandbox"]["enabled"] is True


def test_recon_profile_is_propose_only():
    from tools.config.profiles import apply_profile

    merged = apply_profile({"exploit": {"permission": "full_access", "attack_mode": True}}, "recon")
    assert merged["exploit"]["permission"] == "read_only"
    assert merged["exploit"]["attack_mode"] is False
    assert merged["exploit"]["auto_post_exploit"] is False


def test_ci_profile_is_hermetic():
    from tools.config.profiles import apply_profile

    merged = apply_profile({}, "ci")
    assert merged["models"]["auto_update"] is False
    assert merged["sandbox"]["enabled"] is False
    assert merged["witness"]["enabled"] is False
    assert merged["multi_model"]["enabled"] is False
    assert merged["reasoning"]["ultrathink"] is False


def test_profiles_omit_deprecated_stealth():
    """No profile may resurrect the inert stealth block."""
    from tools.config.profiles import PROFILES

    for name, overlay in PROFILES.items():
        assert "stealth" not in overlay, f"profile {name!r} must not carry stealth"


def test_load_validated_config_profile_kwarg(tmp_path: Path):
    from tools.config_manager import load_validated_config

    cfg_path = tmp_path / "config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"permission": "full_access", "attack_mode": True},
        },
        cfg_path.open("w", encoding="utf-8"),
    )
    plain = load_validated_config(cfg_path)
    assert plain["exploit"]["permission"] == "full_access"
    recon = load_validated_config(cfg_path, profile="recon")
    assert recon["exploit"]["permission"] == "read_only"
    assert recon["exploit"]["attack_mode"] is False
    # File on disk is untouched by the in-memory overlay.
    on_disk = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert on_disk["exploit"]["permission"] == "full_access"
    with pytest.raises(ValueError, match="Unknown config profile"):
        load_validated_config(cfg_path, profile="bogus")


def test_stealth_at_defaults_stays_silent(tmp_path: Path):
    """The checked-in lab file carries stealth at defaults — must warn nothing."""
    from tools.config_manager import ConfigValidator, validate_config_file

    result = validate_config_file("config.yaml")
    assert result.errors == []
    assert result.warnings == []

    cfg_path = tmp_path / "stealth-defaults.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "stealth": {"rotate_ua": False, "dns_over_https": False, "doh_provider": "cloudflare"},
        },
        cfg_path.open("w", encoding="utf-8"),
    )
    _, res = ConfigValidator(cfg_path).load_and_validate()
    assert res.is_valid
    assert not any("stealth" in w for w in res.warnings)


def test_stealth_customized_warns_not_errors(tmp_path: Path):
    """An operator actually flipping stealth knobs gets a deprecation nudge."""
    from tools.config_manager import ConfigValidator

    cfg_path = tmp_path / "stealth-custom.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "stealth": {"rotate_ua": True, "dns_over_https": False, "doh_provider": "cloudflare"},
        },
        cfg_path.open("w", encoding="utf-8"),
    )
    _, res = ConfigValidator(cfg_path).load_and_validate()
    assert res.is_valid
    assert any("stealth" in w and "deprecated" in w for w in res.warnings)
