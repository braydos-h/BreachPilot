"""Tests for peer-model outcome judging (D3).

Cross-model validation of "did we actually compromise it" -- one alias plans,
a *different* alias grades the evidence. Advisory only; the deterministic
OutcomeJudge stays the authority.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class _FakeClient:
    def __init__(self, alias: str, content: str | None = None) -> None:
        self.alias = alias
        self.content = content or f'{{"agree": true, "confidence": 0.8, "reason": "ok from {alias}"}}'

    def chat(self, _model, **_kwargs):
        return {"message": {"content": self.content}}


class _FakeRouter:
    def __init__(self, aliases: list[str], content: str | None = None) -> None:
        self._clients = {alias: _FakeClient(alias, content) for alias in aliases}

    def get_client(self, alias: str) -> _FakeClient:
        return self._clients[alias]


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


def _config(*, peer_review: bool = True, consult_aliases=("kimi", "deepseek", "glm")) -> dict:
    return {
        "ollama": {"host": "http://localhost:11434"},
        "models": {
            "registry": {
                "kimi": "kimi-k2.6:cloud",
                "deepseek": "deepseek-v4-pro:cloud",
                "glm": "glm-5.2:cloud",
                "minimax": "minimax-m3:cloud",
            },
            "default_alias": "glm",
        },
        "multi_model": {
            "enabled": True,
            "consult_aliases": list(consult_aliases),
            "max_consultations": 10,
            "max_question_chars": 4000,
            "max_answer_chars": 8000,
        },
        "outcome_judgment": {"peer_review": peer_review},
    }


def _text(result) -> str:
    if isinstance(result, tuple) and result:
        return _text(result[0])
    if isinstance(result, list):
        return "\n".join(getattr(item, "text", str(item)) for item in result)
    content = getattr(result, "content", result)
    if isinstance(content, list):
        return "\n".join(getattr(item, "text", str(item)) for item in content)
    return str(content)


# ─── Registration / gating ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_peer_review_outcome_registered_when_multi_model_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config(peer_review=True))
    names = {tool.name for tool in await mcp.list_tools()}
    assert "peer_review_outcome" in names


@pytest.mark.asyncio
async def test_peer_review_outcome_absent_when_multi_model_disabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    cfg = _config()
    cfg["multi_model"]["enabled"] = False
    mcp = _server(tmp_path, cfg)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "peer_review_outcome" not in names


# ─── Arg validation ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_peer_review_outcome_blocks_empty_verdict(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config())
    text = _text(await mcp.call_tool("peer_review_outcome", {"verdict": "", "evidence": "x"}))
    assert "BLOCKED" in text


@pytest.mark.asyncio
async def test_peer_review_outcome_blocks_empty_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config())
    text = _text(await mcp.call_tool("peer_review_outcome", {"verdict": "compromised", "evidence": ""}))
    assert "BLOCKED" in text


@pytest.mark.asyncio
async def test_peer_review_outcome_disabled_when_peer_review_false(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config(peer_review=False))
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "shell returned"},
    ))
    assert "DISABLED" in text
    assert "peer_review" in text


# ─── Grader selection ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_peer_review_outcome_excludes_planner_alias(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    monkeypatch.setattr(server_mod, "_get_model_router", lambda _c: _FakeRouter(["kimi", "deepseek", "glm"]))
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config())
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {
            "verdict": "compromised",
            "evidence": "whoami returned root",
            "planner_alias": "glm",
            "preferred_grader_aliases": "kimi,deepseek,glm",
        },
    ))
    # glm was the planner; it must NOT appear as a grader.
    assert "PLANNER_ALIAS: glm" in text
    assert "GRADERS: kimi, deepseek" in text
    assert "COMPLETED" in text


@pytest.mark.asyncio
async def test_peer_review_outcome_no_graders_available(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    # Only glm available, and it's the planner -> no graders.
    monkeypatch.setattr(server_mod, "_get_model_router", lambda _c: _FakeRouter(["glm"]))
    monkeypatch.setenv("AI_NMAP_ACTIVE_MODEL_ALIAS", "glm")
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config(consult_aliases=["glm"]))
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "x", "planner_alias": "glm"},
    ))
    assert "UNAVAILABLE" in text
    assert "no grader" in text.lower()


# ─── Disagreement detection ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_peer_review_outcome_flags_disagreement(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    disagree_content = '{"agree": false, "confidence": 0.7, "reason": "evidence is weak"}'
    monkeypatch.setattr(
        server_mod,
        "_get_model_router",
        lambda _c: _FakeRouter(["kimi", "deepseek"], content=disagree_content),
    )
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config(consult_aliases=["kimi", "deepseek"]))
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "weak signal", "planner_alias": "glm"},
    ))
    assert "DISAGREEMENT: yes" in text
    assert "AUTHORITY: deterministic OutcomeJudge" in text


@pytest.mark.asyncio
async def test_peer_review_outcome_no_disagreement_when_all_agree(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    agree_content = '{"agree": true, "confidence": 0.9, "reason": "solid evidence"}'
    monkeypatch.setattr(
        server_mod,
        "_get_model_router",
        lambda _c: _FakeRouter(["kimi", "deepseek"], content=agree_content),
    )
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config(consult_aliases=["kimi", "deepseek"]))
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "whoami returned root", "planner_alias": "glm"},
    ))
    assert "DISAGREEMENT: no" in text


# ─── Router failure degrades gracefully ───────────────────────────────────

@pytest.mark.asyncio
async def test_peer_review_outcome_unavailable_when_router_none(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    monkeypatch.setattr(server_mod, "_get_model_router", lambda _c: None)
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config())
    text = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "x"},
    ))
    assert "UNAVAILABLE" in text
    assert "router" in text.lower()


@pytest.mark.asyncio
async def test_peer_review_outcome_shares_consultation_budget(tmp_path, monkeypatch) -> None:
    """peer_review_outcome must decrement the shared max_consultations budget."""
    import mcp_exploit_server as server_mod

    monkeypatch.setattr(server_mod, "_consultation_count", 0)
    monkeypatch.setattr(
        server_mod,
        "_get_model_router",
        lambda _c: _FakeRouter(["kimi", "deepseek"]),
    )
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    cfg = _config()
    cfg["multi_model"]["max_consultations"] = 1
    mcp = _server(tmp_path, cfg)

    first = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "whoami returned root", "planner_alias": "glm"},
    ))
    assert "COMPLETED" in first
    assert "REMAINING_BUDGET: 0" in first

    second = _text(await mcp.call_tool(
        "peer_review_outcome",
        {"verdict": "compromised", "evidence": "more evidence", "planner_alias": "glm"},
    ))
    assert "BUDGET_EXHAUSTED" in second
