from __future__ import annotations

from pathlib import Path


def _write_skill(root: Path, name: str, tags: list[str]) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {name} description.\n"
        "tags:\n"
        + "".join(f"- {tag}\n" for tag in tags)
        + "---\n"
        "# Skill\n\n## When to Use\nAuthorized use only.\n\n## Workflow\nFollow the methodology.",
        encoding="utf-8",
    )


def _registry(tmp_path: Path):
    from tools.skill_registry import load_skill_registry

    _write_skill(tmp_path, "scanning-network-with-nmap-advanced", ["nmap", "reconnaissance", "network-security"])
    _write_skill(tmp_path, "conducting-api-security-testing", ["api", "web", "owasp"])
    _write_skill(tmp_path, "exploiting-active-directory-with-bloodhound", ["active-directory", "windows", "exploit"])
    _write_skill(tmp_path, "securing-agentic-ai-tool-invocation", ["mcp", "safety"])
    return load_skill_registry([tmp_path], base_dir=tmp_path)


def test_recon_goal_selects_nmap_skill(tmp_path: Path):
    from tools.skill_selector import select_runtime_skills

    selection = select_runtime_skills(
        _registry(tmp_path),
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 4}},
        goal_name="recon",
        goal_description="Run nmap reconnaissance",
        mode="recon",
    )

    assert "scanning-network-with-nmap-advanced" in [s.name for s in selection.skills]
    assert "RUNTIME" not in selection.prompt_context
    assert "scanning-network-with-nmap-advanced" in selection.prompt_context


def test_http_api_context_selects_api_skill(tmp_path: Path):
    from tools.skill_selector import select_runtime_skills

    selection = select_runtime_skills(
        _registry(tmp_path),
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 4}},
        goal_name="verify_cves",
        goal_description="Test API security",
        mode="recon",
        services=["https 443 graphql api"],
    )

    assert "conducting-api-security-testing" in [s.name for s in selection.skills]
    api_activation = next(a for a in selection.activations if a.name == "conducting-api-security-testing")
    assert api_activation.score > 0
    assert any(signal.startswith("service:") for signal in api_activation.signals)


def test_tag_aliases_match_corpus_metadata(tmp_path: Path):
    from tools.skill_registry import load_skill_registry
    from tools.skill_selector import select_runtime_skills

    _write_skill(tmp_path, "conducting-api-security-testing", ["api-security", "owasp"])
    registry = load_skill_registry([tmp_path], base_dir=tmp_path)

    selection = select_runtime_skills(
        registry,
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 4}},
        goal_name="verify_cves",
        goal_description="Test an API service",
        mode="recon",
        services=["https 443 graphql api"],
    )

    assert "conducting-api-security-testing" in [s.name for s in selection.skills]


def test_contextual_skills_are_reserved_ahead_of_defaults(tmp_path: Path):
    from tools.skill_registry import load_skill_registry
    from tools.skill_selector import select_runtime_skills

    for idx in range(1, 7):
        _write_skill(tmp_path, f"default-skill-{idx}", ["reporting"])
    _write_skill(tmp_path, "conducting-api-security-testing", ["api-security"])
    registry = load_skill_registry([tmp_path], base_dir=tmp_path)

    selection = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [f"default-skill-{idx}" for idx in range(1, 7)],
                "max_active_skills": 3,
                "min_contextual_skills": 2,
                "default_skill_weight": 100,
                "context_skill_weight": 10,
            }
        },
        goal_name="api",
        goal_description="Test API security",
        mode="recon",
        services=["https 443 graphql api"],
    )

    assert "conducting-api-security-testing" in [s.name for s in selection.skills]


def test_attack_only_skill_not_selected_in_recon(tmp_path: Path):
    from tools.skill_selector import select_runtime_skills

    selection = select_runtime_skills(
        _registry(tmp_path),
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 6}},
        goal_name="recon",
        goal_description="Map active directory services",
        mode="recon",
        services=["ldap 389 active directory", "smb 445 microsoft-ds"],
    )

    assert "exploiting-active-directory-with-bloodhound" not in [s.name for s in selection.skills]


def test_attack_only_alias_not_selected_in_recon(tmp_path: Path):
    from tools.skill_registry import load_skill_registry
    from tools.skill_selector import select_runtime_skills

    _write_skill(tmp_path, "red-team-playbook", ["red-team"])
    registry = load_skill_registry([tmp_path], base_dir=tmp_path)

    selection = select_runtime_skills(
        registry,
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 4}},
        goal_name="recon",
        goal_description="Review red team methodology later",
        mode="recon",
    )

    assert "red-team-playbook" not in [s.name for s in selection.skills]


def test_attack_mode_can_select_attack_skill_and_excludes_win(tmp_path: Path):
    from tools.skill_selector import select_runtime_skills

    registry = _registry(tmp_path)
    selected = select_runtime_skills(
        registry,
        config={"skills": {"enabled": True, "default_enabled": [], "max_active_skills": 6}},
        goal_name="initial_access",
        goal_description="Exploit active directory attack path",
        mode="attack",
        services=["ldap 389 active directory", "smb 445 microsoft-ds"],
    )
    excluded = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [],
                "exclude_names": ["exploiting-active-directory-with-bloodhound"],
                "max_active_skills": 6,
            }
        },
        goal_name="initial_access",
        goal_description="Exploit active directory attack path",
        mode="attack",
        services=["ldap 389 active directory"],
    )

    assert "exploiting-active-directory-with-bloodhound" in [s.name for s in selected.skills]
    assert "exploiting-active-directory-with-bloodhound" not in [s.name for s in excluded.skills]
