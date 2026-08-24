"""Tests for the capability-discovery + hypothesis-workflow prompt section."""

from __future__ import annotations

from tools.exploit_agent.prompt import (
    build_capability_guidance,
    build_exploit_system_prompt,
)


def test_build_capability_guidance_disabled_is_empty():
    assert build_capability_guidance(False) == ""


def test_build_capability_guidance_enabled_nonempty_and_has_key_phrases():
    text = build_capability_guidance(True)
    assert text  # non-empty
    # Section heading present.
    assert "CAPABILITY DISCOVERY + HYPOTHESIS WORKFLOW" in text
    # The six new MCP tools are named.
    for tool in (
        "get_assessment_state",
        "query_capabilities",
        "get_capability_details",
        "get_evidence",
        "record_hypothesis",
        "update_task",
    ):
        assert tool in text, f"missing tool name {tool!r}"
    # Workflow directives the design calls out.
    assert "hypothesis" in text.lower()
    assert "prerequisite" in text.lower()
    assert "FAILURE_CLASS" in text
    assert "Stop when the goal is met" in text


def test_build_exploit_system_prompt_appends_capability_guidance():
    guidance = build_capability_guidance(True)
    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="10.0.0.5",
        capability_guidance=guidance,
    )
    assert guidance in prompt
    # An existing asserted substring still survives (regression guard).
    assert "FILE & KEY HANDLING" in prompt
    assert "EXPLOITATION WORKFLOW" in prompt


def test_build_exploit_system_prompt_default_no_capability_guidance():
    """Omitting the kwarg yields no capability-guidance section (byte-identical)."""
    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="10.0.0.5",
    )
    assert "CAPABILITY DISCOVERY + HYPOTHESIS WORKFLOW" not in prompt
    assert "FILE & KEY HANDLING" in prompt
