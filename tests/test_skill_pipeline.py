from __future__ import annotations

from tools.skill_pipeline import (
    append_phase_skill_hints,
    phase_skill_hints,
    phase_skill_payloads,
)
from tools.skill_selector import SkillActivation, SkillSelection


def _act(name: str, tags: list[str]) -> SkillActivation:
    return SkillActivation(
        name=name,
        reason="test reason",
        source="test",
        matched_tags=tuple(tags),
        risk_level="advisory",
        score=1,
        signals=(),
    )


def _selection() -> SkillSelection:
    return SkillSelection(
        activations=(
            _act("nmap-recon", ["nmap", "reconnaissance", "network-security"]),
            _act("ad-exploit", ["active-directory", "exploit", "windows"]),
            _act("api-web", ["api", "web", "owasp"]),
        )
    )


def test_phase_filter_recon_excludes_exploit_tags():
    hints = phase_skill_hints(_selection(), "recon")
    assert "nmap-recon" in hints
    assert "ad-exploit" not in hints
    assert "api-web" not in hints


def test_phase_filter_exploit_includes_web_and_ad():
    hints = phase_skill_hints(_selection(), "exploit")
    assert "ad-exploit" in hints
    assert "api-web" in hints
    assert "nmap-recon" not in hints


def test_critic_gets_full_payload():
    payloads = phase_skill_payloads(_selection(), "critic")
    names = {p["name"] for p in payloads}
    assert names == {"nmap-recon", "ad-exploit", "api-web"}


def test_reflection_gets_full_payload():
    payloads = phase_skill_payloads(_selection(), "reflection")
    assert {p["name"] for p in payloads} == {"nmap-recon", "ad-exploit", "api-web"}


def test_postexploit_alias_matches_post_exploit_tags():
    hints = phase_skill_hints(_selection(), "postexploit")
    assert "ad-exploit" in hints  # active-directory/credential tags overlap
    assert "nmap-recon" not in hints
    assert "api-web" not in hints


def test_empty_selection_returns_empty_hints():
    assert phase_skill_hints(SkillSelection(), "recon") == ""
    assert phase_skill_payloads(SkillSelection(), "critic") == []


def test_phase_hints_are_metadata_not_bodies():
    # Hints must be activation metadata only -- never sanitized skill bodies --
    # so non-exploit agents never receive untrusted markdown.
    hints = phase_skill_hints(_selection(), "recon")
    assert "<untrusted_skill_guidance" not in hints
    assert "## Workflow" not in hints


def test_append_phase_skill_hints_noop_when_empty():
    prompt = "Do the work."
    assert append_phase_skill_hints(prompt, SkillSelection(), "recon") == prompt


def test_append_phase_skill_hints_adds_block():
    prompt = "Do the work."
    out = append_phase_skill_hints(prompt, _selection(), "recon")
    assert "RUNTIME SKILL HINTS" in out
    assert "nmap-recon" in out
    assert "advisory only" in out
    assert out.startswith("Do the work.")


def test_build_skill_selection_for_swarm_respects_swarm_inject_flag():
    from tools.skill_pipeline import build_skill_selection_for_swarm

    # swarm_inject: false -> empty selection even with skills enabled.
    ctx = {"config": {"skills": {"enabled": True, "swarm_inject": False}}, "mission": {"objective": "recon"}}
    sel = build_skill_selection_for_swarm(ctx)
    assert sel.activations == ()


def test_build_skill_selection_for_swarm_disabled_skills():
    from tools.skill_pipeline import build_skill_selection_for_swarm

    ctx = {"config": {"skills": {"enabled": False, "swarm_inject": True}}, "mission": {"objective": "recon"}}
    sel = build_skill_selection_for_swarm(ctx)
    assert sel.activations == ()
