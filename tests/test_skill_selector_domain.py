"""Tests for the domain-target skill-selection signal (Tier 3.1).

Regression: the skill selector had no ``is_domain`` branch, so a domain
``--target`` never preferentially surfaced domain-attack skills (subdomain
enumeration, DNS recon, takeover, vhost). The ``attacking-domains-end-to-end``
skill was only active via ``default_enabled`` (every run), not via a
target:domain signal. These tests confirm the ``is_domain=True`` path emits
the domain-attack tag family with a ``target:domain`` signal.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _fake_registry_with_skills():
    """Build a fake SkillRegistry with a couple of domain skills + a non-domain one."""
    from tools.skill_registry import LoadedSkill, SkillMetadata

    def _skill(name: str, tags: tuple[str, ...], desc: str = "") -> LoadedSkill:
        meta = SkillMetadata(
            name=name,
            description=desc or f"{name} skill",
            domain="cybersecurity",
            subdomain="web-application-security",
            tags=list(tags),
            references=[],
            nist_csf=[],
            mitre_attack=[],
            version="1.0",
        )
        return LoadedSkill(metadata=meta, body=f"{name} body")

    registry = MagicMock()
    all_skills = [
        _skill("attacking-domains-end-to-end", ("domain-attack", "subdomain-enumeration", "dns-recon")),
        _skill("performing-subdomain-enumeration-with-subfinder", ("subdomain-enumeration", "reconnaissance")),
        _skill("scanning-network-with-nmap-advanced", ("nmap", "network-security", "reconnaissance")),
    ]

    # search(tags=[...]) returns skills whose tags intersect the query.
    def _search(tags=None, **_):
        if not tags:
            return all_skills
        return [s for s in all_skills if set(s.metadata.tags) & set(tags)]

    registry.search = MagicMock(side_effect=_search)
    registry.all_skills = MagicMock(return_value=all_skills)
    return registry


def test_tag_signals_emits_domain_tags_when_is_domain_true():
    """_tag_signals(is_domain=True) must emit the domain-attack tag family."""
    from tools.skill_selector import _tag_signals

    tags = _tag_signals(
        goal_text="",
        service_values=[],
        cve_text="",
        tool_text="",
        context_text="",
        mode="attack",
        is_domain=True,
    )
    # The domain-attack tags must all be present with a target:domain signal.
    for expected in ("domain-attack", "subdomain-enumeration", "dns-recon", "subdomain-takeover", "attack-surface"):
        assert expected in tags, f"expected {expected} in tags when is_domain=True, got {sorted(tags)}"
        assert "target:domain" in tags[expected]


def test_tag_signals_no_domain_tags_when_is_domain_false():
    """_tag_signals(is_domain=False) must NOT emit domain-attack tags."""
    from tools.skill_selector import _tag_signals

    tags = _tag_signals(
        goal_text="",
        service_values=[],
        cve_text="",
        tool_text="",
        context_text="",
        mode="attack",
        is_domain=False,
    )
    assert "domain-attack" not in tags
    assert "subdomain-takeover" not in tags


def test_select_runtime_skills_is_domain_surfaces_domain_skills():
    """select_runtime_skills(is_domain=True) must include domain skills in the selection."""
    from tools.skill_selector import select_runtime_skills

    registry = _fake_registry_with_skills()
    selection = select_runtime_skills(
        registry,
        config={"skills": {"enabled": True, "max_active_skills": 6, "min_contextual_skills": 1}},
        goal_name="initial_access",
        goal_description="attack",
        mode="attack",
        is_domain=True,
    )
    names = {a.name for a in selection.activations}
    # The domain-attack skill must be surfaced (it matches the target:domain tag signal).
    assert "attacking-domains-end-to-end" in names, (
        f"expected attacking-domains-end-to-end in selection, got {sorted(names)}"
    )


def test_select_runtime_skills_no_is_domain_may_not_surface_domain_skills():
    """Without is_domain, the domain skill is only surfaced via defaults/semantic — not target signal."""
    from tools.skill_selector import select_runtime_skills

    registry = _fake_registry_with_skills()
    selection = select_runtime_skills(
        registry,
        config={"skills": {"enabled": True, "max_active_skills": 6, "min_contextual_skills": 1}},
        goal_name="initial_access",
        goal_description="attack",
        mode="attack",
        is_domain=False,
    )
    # The domain skill may still appear via lexical/semantic match, but the
    # target:domain signal is NOT the reason. The key regression check is
    # that is_domain=True surfaces it with a target:domain reason.
    for a in selection.activations:
        if a.name == "attacking-domains-end-to-end":
            # When is_domain=False, the reason must NOT cite target:domain.
            assert "target:domain" not in (a.reason or "").lower(), (
                f"domain skill surfaced with target:domain when is_domain=False: {a.reason}"
            )


def test_build_skill_selection_for_context_threads_is_domain():
    """build_skill_selection_for_context(is_domain=True) passes it through."""
    from tools.skill_pipeline import build_skill_selection_for_context

    registry = _fake_registry_with_skills()
    selection = build_skill_selection_for_context(
        {"skills": {"enabled": True, "max_active_skills": 6, "min_contextual_skills": 1}},
        goal_name="initial_access",
        goal_description="attack",
        mode="attack",
        registry=registry,
        is_domain=True,
    )
    names = {a.name for a in selection.activations}
    assert "attacking-domains-end-to-end" in names, f"expected domain skill surfaced via is_domain, got {sorted(names)}"
