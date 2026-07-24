"""Tests for the read-only TUI Skills screen + SkillsService (Tier 3.2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tui.services import SkillsService
from tools.skill_registry_cache import clear_cache


def _binding_actions(screen_cls) -> set[str]:
    return {b.action for b in getattr(screen_cls, "BINDINGS", [])}


def _write_skill(root: Path, name: str, tags: list[str], desc: str = "x") -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {desc}\n"
        "tags:\n" + "".join(f"- {t}\n" for t in tags)
        + "---\n# Skill\n\n## Workflow\nAuthorized use only.",
        encoding="utf-8",
    )


@pytest.fixture
def tmp_registry(tmp_path: Path):
    clear_cache()
    _write_skill(tmp_path, "alpha-skill", ["nmap", "reconnaissance"], "alpha recon methodology")
    _write_skill(tmp_path, "beta-skill", ["api", "web"], "beta web methodology")
    yield tmp_path
    clear_cache()


# ── screen registration / structure ──────────────────────────────────────


def test_skills_screen_imports():
    from tui.screens.skills_screen import SkillsScreen

    assert SkillsScreen is not None


def test_skills_screen_registered_in_screen_map():
    from tui.app import _screen_map

    assert "skills" in _screen_map()
    from tui.screens.skills_screen import SkillsScreen

    assert _screen_map()["skills"] is SkillsScreen


def test_skills_screen_exported_from_package():
    from tui.screens import SkillsScreen as Exported, __all__

    assert "SkillsScreen" in __all__
    from tui.screens.skills_screen import SkillsScreen

    assert Exported is SkillsScreen


def test_skills_screen_has_refresh_and_back_bindings():
    from tui.screens.skills_screen import SkillsScreen

    actions = _binding_actions(SkillsScreen)
    assert "refresh" in actions
    assert "pop_screen" in actions


def test_skills_screen_has_no_toggle_or_action_bindings():
    """Read-only invariant: no enable/disable/add/delete actions."""
    from tui.screens.skills_screen import SkillsScreen

    actions = _binding_actions(SkillsScreen)
    for forbidden in ("toggle", "enable", "disable", "add", "delete", "remove", "activate"):
        assert not any(forbidden in a for a in actions), f"read-only screen must not bind '{forbidden}'"


def test_app_has_goto_skills_binding_and_action():
    from tui.app import ResearchTUI

    actions = {b.action for b in getattr(ResearchTUI, "BINDINGS", [])}
    assert "goto_skills" in actions
    assert hasattr(ResearchTUI, "action_goto_skills")


def test_skills_screen_compose_has_no_button_widget():
    """The screen must not declare any Button (read-only -- no actionable
    controls that could be coerced into changing the skill set)."""
    import inspect

    from tui.screens.skills_screen import SkillsScreen

    src = inspect.getsource(SkillsScreen)
    assert "Button" not in src


# ── SkillsService ────────────────────────────────────────────────────────


def test_skills_service_list_catalog(tmp_registry: Path):
    svc = SkillsService(config={"skills": {"roots": [str(tmp_registry)]}})
    catalog = svc.list_catalog()
    names = {entry["name"] for entry in catalog}
    assert {"alpha-skill", "beta-skill"} <= names
    alpha = next(e for e in catalog if e["name"] == "alpha-skill")
    assert "nmap" in alpha["tags"]
    assert alpha["description"] == "alpha recon methodology"


def test_skills_service_active_selection_returns_payloads(tmp_registry: Path):
    svc = SkillsService(config={"skills": {
        "roots": [str(tmp_registry)],
        "default_enabled": ["alpha-skill"],
        "max_active_skills": 6,
    }})
    payloads = svc.active_selection(mode="recon", goal_name="recon")
    names = {p["name"] for p in payloads}
    assert "alpha-skill" in names
    # Payloads carry the advisory metadata fields the screen renders.
    alpha = next(p for p in payloads if p["name"] == "alpha-skill")
    assert "risk_level" in alpha
    assert "reason" in alpha


def test_skills_service_active_selection_empty_when_disabled(tmp_registry: Path):
    svc = SkillsService(config={"skills": {"roots": [str(tmp_registry)], "enabled": False}})
    assert svc.active_selection() == []


def test_skills_service_list_catalog_excludes_maybe_by_default(tmp_path: Path):
    clear_cache()
    _write_skill(tmp_path, "stable-skill", ["nmap"], "stable")
    # maybe skills live under a `maybe/` directory segment in their path.
    _write_skill(tmp_path / "maybe", "maybe-skill", ["nmap"], "m")
    svc = SkillsService(config={"skills": {"roots": [str(tmp_path)]}})
    default = {e["name"] for e in svc.list_catalog()}
    assert "stable-skill" in default
    assert "maybe-skill" not in default
    with_maybe = {e["name"] for e in svc.list_catalog(include_maybe=True)}
    assert "maybe-skill" in with_maybe
    clear_cache()