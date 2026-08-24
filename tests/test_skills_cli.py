"""Tests for the --skills* CLI flag overrides (Tier 3.1).

Pure dict assertions against ``apply_skills_cli_overrides`` -- no LLM, no
network, no registry load. Verifies the advisory-only overrides mutate
``config["skills"]`` exactly as documented and never touch unrelated keys.
"""

from __future__ import annotations

import argparse
from typing import Any

from main import apply_skills_cli_overrides


def _args(**overrides: Any) -> argparse.Namespace:
    base = dict(
        skills=None,
        skills_list=False,
        skills_include=None,
        skills_exclude=None,
        no_skills_reselect=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _config() -> dict[str, Any]:
    return {
        "skills": {
            "enabled": True,
            "inject_startup_context": False,
            "allow_model_lookup": True,
            "default_enabled": ["alpha"],
            "exclude_names": [],
            "reselect_mid_run": True,
        }
    }


def test_apply_skills_off_disables():
    cfg = apply_skills_cli_overrides(_config(), _args(skills="off"))
    assert cfg["skills"]["enabled"] is False


def test_apply_skills_on_injects_startup_context():
    cfg = apply_skills_cli_overrides(_config(), _args(skills="on"))
    assert cfg["skills"]["enabled"] is True
    assert cfg["skills"]["inject_startup_context"] is True


def test_apply_skills_hints_is_hints_only():
    cfg = apply_skills_cli_overrides(_config(), _args(skills="hints"))
    assert cfg["skills"]["enabled"] is True
    assert cfg["skills"]["inject_startup_context"] is False


def test_apply_skills_lookup_keeps_lookup_only():
    base = _config()
    base["skills"]["allow_model_lookup"] = False
    cfg = apply_skills_cli_overrides(base, _args(skills="lookup"))
    assert cfg["skills"]["enabled"] is True
    assert cfg["skills"]["inject_startup_context"] is False
    assert cfg["skills"]["allow_model_lookup"] is True


def test_skills_include_appends_to_default_enabled():
    cfg = apply_skills_cli_overrides(_config(), _args(skills_include=["beta", "gamma"]))
    assert cfg["skills"]["default_enabled"] == ["alpha", "beta", "gamma"]


def test_skills_include_dedups_existing():
    cfg = apply_skills_cli_overrides(_config(), _args(skills_include=["alpha", "beta"]))
    assert cfg["skills"]["default_enabled"] == ["alpha", "beta"]


def test_skills_exclude_appends_to_exclude_names():
    cfg = apply_skills_cli_overrides(_config(), _args(skills_exclude=["beta", "alpha"]))
    assert cfg["skills"]["exclude_names"] == ["beta", "alpha"]


def test_no_skills_reselect_disables_reselection():
    cfg = apply_skills_cli_overrides(_config(), _args(no_skills_reselect=True))
    assert cfg["skills"]["reselect_mid_run"] is False


def test_apply_skills_none_is_noop():
    before = _config()
    cfg = apply_skills_cli_overrides(_config(), _args())
    assert cfg["skills"] == before["skills"]


def test_apply_skills_combined_overrides():
    cfg = apply_skills_cli_overrides(
        _config(),
        _args(
            skills="on",
            skills_include=["beta"],
            skills_exclude=["gamma"],
            no_skills_reselect=True,
        ),
    )
    s = cfg["skills"]
    assert s["enabled"] is True
    assert s["inject_startup_context"] is True
    assert s["default_enabled"] == ["alpha", "beta"]
    assert s["exclude_names"] == ["gamma"]
    assert s["reselect_mid_run"] is False


def test_apply_skills_does_not_touch_permission_or_audit():
    """Advisory invariant: the skills flags must never mutate exploit
    permission, scope, or audit config -- only the skills sub-dict."""
    cfg = {
        "exploit": {"permission": "read_only"},
        "skills": {"enabled": True, "default_enabled": [], "exclude_names": []},
    }
    out = apply_skills_cli_overrides(cfg, _args(skills="off", skills_include=["x"]))
    assert out["exploit"]["permission"] == "read_only"  # untouched
    assert out["skills"]["enabled"] is False
    assert out["skills"]["default_enabled"] == ["x"]


def test_parse_args_skills_flags_recognized():
    """The argparse parser accepts every new skills flag without error."""
    from main import parse_args

    ns = parse_args(
        [
            "--skills",
            "on",
            "--skills-include",
            "alpha",
            "--skills-include",
            "beta",
            "--skills-exclude",
            "gamma",
            "--no-skills-reselect",
            "--skills-list",
        ]
    )
    assert ns.skills == "on"
    assert ns.skills_include == ["alpha", "beta"]
    assert ns.skills_exclude == ["gamma"]
    assert ns.no_skills_reselect is True
    assert ns.skills_list is True
