"""Tests for the replay simulator (D2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.replay_simulator import (
    SimulationResult,
    _parse_json_block,
    _rule_based_score,
    _target_mismatch,
    render_simulation_result,
    simulate,
)

_SAMPLE_RECON = {
    "target_ip": "10.0.0.50",
    "os_verdict": "LINUX",
    "open_ports": [22, 80, 443],
    "services": [],
    "cve_findings": [{"cve": "CVE-2021-44228"}],
    "overall_risk_score": 70,
}

_SAMPLE_PLAN = {
    "target_ip": "10.0.0.50",
    "target_cves": ["CVE-2021-44228"],
    "phases": ["recon", "exploit"],
    "current_phase": "exploit",
    "current_phase_index": 1,
    "steps": [
        {
            "phase": "exploit",
            "tool": "cve_to_exploit_synth",
            "reason": "Exploit CVE-2021-44228 against port 80.",
            "target_ip": "10.0.0.50",
            "arguments": {"target_ip": "10.0.0.50", "cve_id": "CVE-2021-44228", "port": 80},
            "depends_on": [],
        },
    ],
    "attack_mode": True,
}


# ─── _target_mismatch ─────────────────────────────────────────────────────

def test_target_mismatch_returns_none_when_match() -> None:
    plan = {"target_ip": "10.0.0.50"}
    recon = {"target_ip": "10.0.0.50"}
    assert _target_mismatch(plan, recon) is None


def test_target_mismatch_returns_note_when_different() -> None:
    plan = {"target_ip": "10.0.0.99"}
    recon = {"target_ip": "10.0.0.50"}
    note = _target_mismatch(plan, recon)
    assert note is not None
    assert "10.0.0.99" in note and "10.0.0.50" in note


def test_target_mismatch_returns_none_when_empty() -> None:
    assert _target_mismatch({"target_ip": ""}, {"target_ip": "10.0.0.50"}) is None


# ─── _rule_based_score ────────────────────────────────────────────────────

def test_rule_based_score_empty_plan() -> None:
    result = _rule_based_score({"target_ip": "10.0.0.50", "steps": []}, _SAMPLE_RECON)
    assert result.confidence == 0.0
    assert "no steps" in result.critique.lower()


def test_rule_based_score_full_coverage() -> None:
    result = _rule_based_score(_SAMPLE_PLAN, _SAMPLE_RECON)
    assert 0.0 < result.confidence <= 1.0
    # CVE + port + phases + reasons all present.
    assert result.confidence >= 0.6


def test_rule_based_score_penalizes_pivot() -> None:
    plan = {
        "target_ip": "10.0.0.50",
        "steps": [
            {
                "phase": "exploit",
                "tool": "run_exploit_terminal",
                "reason": "pivot to 10.0.0.99",
                "target_ip": "10.0.0.99",  # off-target
                "arguments": {},
            }
        ],
    }
    result = _rule_based_score(plan, _SAMPLE_RECON)
    assert result.confidence <= 0.2  # phases only, minus pivot


def test_rule_based_score_proposes_branches_for_uncovered_ports() -> None:
    # Plan references port 80 only; recon has 22, 80, 443.
    result = _rule_based_score(_SAMPLE_PLAN, _SAMPLE_RECON)
    uncovered = {b["arguments"].get("ports") for b in result.branches}
    assert "22" in uncovered
    assert "443" in uncovered
    assert "80" not in uncovered


# ─── simulate (rule fallback when no model) ──────────────────────────────

def test_simulate_uses_rules_when_no_model_client() -> None:
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON)
    assert isinstance(result, SimulationResult)
    assert result.source == "rules"
    assert 0.0 <= result.confidence <= 1.0


def test_simulate_flags_target_mismatch_in_critique() -> None:
    plan = dict(_SAMPLE_PLAN, target_ip="10.0.0.99")
    result = simulate(plan, _SAMPLE_RECON)
    assert "10.0.0.99" in result.critique
    assert "10.0.0.50" in result.critique


# ─── simulate with mock LLM ──────────────────────────────────────────────

class _FakeClient:
    def __init__(self, content: str) -> None:
        self.content = content

    def chat(self, _alias, **_kwargs):
        return {"message": {"content": self.content}}


def test_simulate_uses_llm_when_model_client_provided() -> None:
    llm_json = json.dumps({
        "confidence": 0.82,
        "critique": "Plan looks solid; add an enumeration step for port 22.",
        "branches": [
            {"phase": "enumerate", "tool": "quick_scan", "reason": "port 22 open",
             "target_ip": "10.0.0.50", "arguments": {"ports": "22"}},
        ],
    })
    client = _FakeClient(llm_json)
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON, model_client=client, model_alias="glm")
    assert result.source == "llm"
    assert result.confidence == 0.82
    assert len(result.branches) == 1
    assert result.branches[0]["tool"] == "quick_scan"


def test_simulate_falls_back_to_rules_when_llm_raises() -> None:
    class _BoomClient:
        def chat(self, *_a, **_k):
            raise RuntimeError("ollama down")
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON, model_client=_BoomClient(), model_alias="glm")
    assert result.source == "rules"


def test_simulate_falls_back_to_rules_when_llm_returns_garbage() -> None:
    client = _FakeClient("this is not json at all")
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON, model_client=client, model_alias="glm")
    assert result.source == "rules"


def test_simulate_clamps_out_of_range_confidence() -> None:
    llm_json = json.dumps({"confidence": 1.5, "critique": "x", "branches": []})
    client = _FakeClient(llm_json)
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON, model_client=client, model_alias="glm")
    assert result.confidence == 1.0


# ─── _parse_json_block ───────────────────────────────────────────────────

def test_parse_json_block_handles_fenced_json() -> None:
    text = "```json\n{\"a\": 1}\n```"
    assert _parse_json_block(text) == {"a": 1}


def test_parse_json_block_handles_prose_around_json() -> None:
    text = "Here is the plan:\n{\"a\": 1}\nThat's it."
    assert _parse_json_block(text) == {"a": 1}


def test_parse_json_block_returns_none_on_garbage() -> None:
    assert _parse_json_block("no json here") is None


# ─── render_simulation_result ────────────────────────────────────────────

def test_render_simulation_result_has_required_fields() -> None:
    r = SimulationResult(
        confidence=0.75,
        critique="good plan",
        branches=[{"phase": "enumerate", "tool": "quick_scan", "reason": "x"}],
        source="llm",
        plan_target="10.0.0.50",
        recon_target="10.0.0.50",
    )
    text = render_simulation_result(r)
    assert "REPLAY_SIMULATION_RESULT:" in text
    assert "SOURCE: llm" in text
    assert "CONFIDENCE: 0.75" in text
    assert "quick_scan" in text


# ─── MCP registration (opt-in) ───────────────────────────────────────────

def _server(tmp_path: Path, config: dict):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path,
        config,
    )


@pytest.mark.asyncio
async def test_replay_simulate_not_registered_when_disabled(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"replay_simulator": {"enabled": False}})
    names = {tool.name for tool in await mcp.list_tools()}
    assert "replay_simulate" not in names


@pytest.mark.asyncio
async def test_replay_simulate_registered_when_enabled(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"replay_simulator": {"enabled": True}})
    names = {tool.name for tool in await mcp.list_tools()}
    assert "replay_simulate" in names


@pytest.mark.asyncio
async def test_replay_simulate_rejects_empty_args(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"replay_simulator": {"enabled": True}})
    result = await mcp.call_tool("replay_simulate", {"plan_json": "", "recon_json": ""})
    text = result.content[0].text if hasattr(result, "content") else str(result)
    assert "BLOCKED" in text


@pytest.mark.asyncio
async def test_replay_simulate_runs_rule_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Force no model client so the LLM path is skipped and rules run.
    import tools.mcp_tools.replay_simulator as _rs
    monkeypatch.setattr(_rs, "_get_model_client", lambda _c: (None, ""))
    mcp = _server(tmp_path, {"replay_simulator": {"enabled": True}})
    result = await mcp.call_tool("replay_simulate", {
        "plan_json": json.dumps(_SAMPLE_PLAN),
        "recon_json": json.dumps(_SAMPLE_RECON),
    })
    text = result.content[0].text if hasattr(result, "content") else str(result)
    assert "REPLAY_SIMULATION_RESULT:" in text
    assert "SOURCE: rules" in text
