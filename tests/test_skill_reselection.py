from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.exploit_agent import _maybe_reselect_skills, _SkillReselectState
from tools.skill_registry import load_skill_registry


def _write_skill(root: Path, name: str, tags: list[str]) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {name} description.\n"
        "tags:\n" + "".join(f"- {tag}\n" for tag in tags) + "---\n"
        "# Skill\n\n## When to Use\nAuthorized use only.\n\n## Workflow\nFollow the methodology.",
        encoding="utf-8",
    )


class _FakeSettings:
    def __init__(self, target_context: dict[str, Any]) -> None:
        self.target_context = target_context


class _FakePolicy:
    def __init__(self, target_context: dict[str, Any], *, attack: bool = False) -> None:
        self.settings = _FakeSettings(target_context)
        self.is_attack_mode = attack
        # Advisory-invariant regression hooks: re-selection must never touch
        # these permission/scope/workspace attributes.
        self.permission = "read_only"
        self._scope_gate = "scope-gate-sentinel"
        self.workspace = Path("workspace-sentinel")


def _registry(tmp_path: Path):
    _write_skill(tmp_path, "nmap-recon-skill", ["nmap", "reconnaissance", "network-security"])
    _write_skill(tmp_path, "api-web-skill", ["api", "web", "owasp"])
    _write_skill(tmp_path, "ad-attack-skill", ["active-directory", "windows", "exploit"])
    return load_skill_registry([tmp_path], base_dir=tmp_path)


def _skills_cfg(**overrides) -> dict[str, Any]:
    base = {
        "enabled": True,
        "default_enabled": ["nmap-recon-skill"],
        "exclude_names": [],
        "max_active_skills": 6,
        "reselect_mid_run": True,
        "reselect_max_per_run": 3,
        "reselect_min_interval_actions": 1,
        "reselect_sticky_defaults": True,
    }
    base.update(overrides)
    return base


def _active_names(target_context: dict[str, Any]) -> set[str]:
    return {item["name"] for item in target_context.get("active_skills", []) if isinstance(item, dict)}


def test_reselect_triggers_on_new_service(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_hints": "",
        "skill_context": "",
        "skill_mode": "recon",
        "skill_goal_name": "recon",
        "skill_goal_description": "Run nmap reconnaissance",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    state.feed_services(["https 443 graphql api"])

    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(),
        messages=messages,
        recent_tool="nmap_scan",
    )

    names = _active_names(target_ctx)
    assert "api-web-skill" in names
    assert "nmap-recon-skill" in names  # sticky default retained
    assert any("[SKILL UPDATE]" in m["content"] for m in messages if m["role"] == "user")
    assert state.reselect_count == 1


def test_reselect_respects_max_per_run(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []

    # First re-selection: new service -> fires.
    state.feed_services(["https 443 graphql api"])
    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(reselect_max_per_run=1),
        messages=messages,
        recent_tool="nmap_scan",
    )
    first_count = state.reselect_count
    assert first_count == 1

    # Second re-selection: another new service, but max_per_run=1 -> no-op.
    state.feed_services(["ssh 22"])
    before = _active_names(target_ctx)
    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=20,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(reselect_max_per_run=1),
        messages=messages,
        recent_tool="nmap_scan",
    )
    assert state.reselect_count == 1
    assert _active_names(target_ctx) == before


def test_reselect_respects_min_interval(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    cfg = _skills_cfg(reselect_min_interval_actions=100)

    # First re-selection: the sentinel last_reselect_action lets it fire.
    state.feed_services(["https 443 graphql api"])
    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=cfg,
        messages=messages,
        recent_tool="nmap_scan",
    )
    assert state.reselect_count == 1
    assert state.last_reselect_action == 5

    # Second re-selection: a genuinely new service, but within the cooldown
    # (action 6 - last 5 = 1 < 100) -> blocked.
    state.feed_services(["ssh 22"])
    before = _active_names(target_ctx)
    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=6,
        new_cves=[],
        registry=registry,
        skills_cfg=cfg,
        messages=messages,
        recent_tool="nmap_scan",
    )
    assert state.reselect_count == 1
    assert _active_names(target_ctx) == before


def test_reselect_keeps_default_enabled_sticky(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    state.feed_services(["https 443 graphql api"])

    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(),
        messages=messages,
        recent_tool="nmap_scan",
    )

    # The configured default survives re-selection even though the new
    # service context points elsewhere.
    assert "nmap-recon-skill" in _active_names(target_ctx)


def test_reselect_does_not_touch_permission_or_scope(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    state.feed_services(["https 443 graphql api"])

    before_perm = policy.permission
    before_gate = policy._scope_gate
    before_ws = policy.workspace

    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(),
        messages=messages,
        recent_tool="nmap_scan",
    )

    assert policy.permission == before_perm
    assert policy._scope_gate == before_gate
    assert policy.workspace == before_ws


def test_reselect_identical_set_is_noop(tmp_path: Path):
    registry = _registry(tmp_path)
    # Current active set already contains both the sticky default and the
    # skill the new service would select -> rebuild yields the same names.
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}, {"name": "api-web-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    state.feed_services(["https 443 graphql api"])

    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(),
        messages=messages,
        recent_tool="nmap_scan",
    )

    assert state.reselect_count == 0
    assert not any("[SKILL UPDATE]" in m["content"] for m in messages if m["role"] == "user")


def test_reselect_disabled_is_noop(tmp_path: Path):
    registry = _registry(tmp_path)
    target_ctx: dict[str, Any] = {
        "active_skills": [{"name": "nmap-recon-skill"}],
        "skill_mode": "recon",
        "skill_goal_name": "recon",
    }
    policy = _FakePolicy(target_ctx)
    state = _SkillReselectState()
    messages: list[dict[str, Any]] = []
    state.feed_services(["https 443 graphql api"])

    _maybe_reselect_skills(
        policy=policy,
        state=state,
        action_count=5,
        new_cves=[],
        registry=registry,
        skills_cfg=_skills_cfg(reselect_mid_run=False),
        messages=messages,
        recent_tool="nmap_scan",
    )

    assert state.reselect_count == 0
    assert _active_names(target_ctx) == {"nmap-recon-skill"}


def test_select_runtime_skills_active_names_bonus_and_sticky_defaults(tmp_path: Path):
    from tools.skill_selector import select_runtime_skills

    registry = _registry(tmp_path)
    # With sticky_defaults, the configured default is retained even when the
    # context strongly favors a different skill and max_active is tight.
    selection = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": ["nmap-recon-skill"],
                "max_active_skills": 1,
                "min_contextual_skills": 1,
                "default_skill_weight": 5,
                "context_skill_weight": 50,
            }
        },
        goal_name="api",
        goal_description="Test API security",
        mode="recon",
        services=["https 443 graphql api"],
        sticky_defaults=True,
    )
    names = {s.name for s in selection.skills}
    assert "nmap-recon-skill" in names  # sticky default retained
