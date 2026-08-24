from __future__ import annotations

from pathlib import Path

import pytest

from tools.cve_lookup import CVESearchSettings, NVDClient
from tools.exploit_search import ExploitSearch, ExploitSearchSettings
from tools.web_researcher import WebResearcher, WebResearcherSettings


class _FakeClient:
    def __init__(self, alias: str, content: str | None = None) -> None:
        self.alias = alias
        self.content = content or f"advice from {alias}"

    def chat(self, _model, **_kwargs):
        return {"message": {"content": self.content}}


class _FakeRouter:
    def __init__(self, aliases: list[str], content: str | None = None) -> None:
        self._clients = {alias: _FakeClient(alias, content) for alias in aliases}

    def get_client(self, alias: str) -> _FakeClient:
        return self._clients[alias]


def _server(tmp_path: Path, config: dict):
    from mcp_exploit_server import create_mcp_server

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path,
        config,
    )


def _config(**multi_model_overrides) -> dict:
    multi_model = {
        "enabled": True,
        "consult_aliases": ["kimi", "deepseek", "glm", "minimax"],
        "max_consultations": 10,
        "max_question_chars": 4000,
        "max_answer_chars": 8000,
    }
    multi_model.update(multi_model_overrides)
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
        "multi_model": multi_model,
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


@pytest.mark.asyncio
async def test_consult_peer_models_absent_when_disabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config(enabled=False))

    names = {tool.name for tool in await mcp.list_tools()}

    assert "consult_peer_models" not in names


@pytest.mark.asyncio
async def test_consult_peer_models_registered_when_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    mcp = _server(tmp_path, _config(enabled=True))

    names = {tool.name for tool in await mcp.list_tools()}

    assert "consult_peer_models" in names


@pytest.mark.asyncio
async def test_consult_peer_models_excludes_active_model_and_honors_budget(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    monkeypatch.setattr(server_mod, "_consultation_count", 0)
    monkeypatch.setattr(server_mod, "_get_model_router", lambda _config: _FakeRouter(["kimi", "deepseek", "minimax"]))
    monkeypatch.setenv("AI_NMAP_ACTIVE_MODEL_ALIAS", "deepseek")
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config(enabled=True, max_consultations=1))

    first = _text(
        await mcp.call_tool(
            "consult_peer_models",
            {
                "question": "Review this exploit strategy",
                "preferred_aliases": "deepseek,kimi",
            },
        )
    )
    second = _text(
        await mcp.call_tool(
            "consult_peer_models",
            {"question": "Try again", "preferred_aliases": "kimi"},
        )
    )

    assert "CONSULTED: kimi" in first
    assert "deepseek" in first
    assert "REMAINING_BUDGET: 0" in first
    assert "BUDGET_EXHAUSTED" in second


@pytest.mark.asyncio
async def test_consult_peer_models_truncates_answers(tmp_path, monkeypatch) -> None:
    import mcp_exploit_server as server_mod

    monkeypatch.setattr(server_mod, "_consultation_count", 0)
    monkeypatch.setattr(server_mod, "_get_model_router", lambda _config: _FakeRouter(["kimi"], content="abcdefghij"))
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)

    mcp = _server(tmp_path, _config(enabled=True, consult_aliases=["kimi"], max_answer_chars=5))

    text = _text(
        await mcp.call_tool(
            "consult_peer_models",
            {"question": "Need a second opinion", "preferred_aliases": "kimi"},
        )
    )

    assert "[kimi]" in text
    assert "abcde\n[truncated]" in text


def test_multi_model_cli_flags_are_tristate() -> None:
    from main import parse_args

    assert parse_args([]).multi_model_consult is None
    assert parse_args(["--multi-model-consult"]).multi_model_consult is True
    assert parse_args(["--no-multi-model-consult"]).multi_model_consult is False


def test_exploit_prompt_mentions_peer_consultation_only_when_enabled() -> None:
    from tools.exploit_agent import build_exploit_system_prompt

    disabled = build_exploit_system_prompt(attacker_os="Windows", target_ip="10.0.0.1")
    enabled = build_exploit_system_prompt(
        attacker_os="Windows",
        target_ip="10.0.0.1",
        multi_model_enabled=True,
    )

    assert "consult_peer_models" not in disabled
    assert "consult_peer_models" in enabled
    assert "Use it sparingly" in enabled
