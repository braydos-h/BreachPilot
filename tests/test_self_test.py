"""Tests for the --self-test localhost smoke test module."""

from __future__ import annotations

import asyncio
import json
from argparse import Namespace
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class FakeMcpSession:
    """Minimal stand-in for an MCP ClientSession used by self_test."""

    def __init__(self, *, raise_on: set[str] | None = None) -> None:
        self._raise_on = raise_on or set()
        self.initialize = AsyncMock(return_value=None)
        self.list_tools = AsyncMock(
            return_value=MagicMock(
                tools=[
                    type("Tool", (), {"name": "check_os"})(),
                    type("Tool", (), {"name": "quick_scan"})(),
                    type("Tool", (), {"name": "search_cve_intel"})(),
                    type("Tool", (), {"name": "list_workspace"})(),
                    type("Tool", (), {"name": "write_python_file"})(),
                ]
            )
        )
        self.call_tool = AsyncMock(side_effect=self._dispatch)
        self.call_tool_calls: list[tuple[str, dict[str, Any]]] = []

    async def _dispatch(self, name: str, arguments: dict[str, Any]) -> Any:
        self.call_tool_calls.append((name, arguments))
        if name in self._raise_on:
            raise BaseExceptionGroup(
                f"simulated stdio death on {name}",
                [ConnectionError("epipe")],
            )
        return MagicMock(content=[MagicMock(text=f"fake {name} output")])


def _make_args(**overrides: Any) -> Namespace:
    defaults = dict(
        target="127.0.0.1",
        config=Path("config.yaml"),
        reports_dir=Path("reports"),
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _fake_open_session(session: FakeMcpSession):
    """Return an async context manager that yields the fake session."""

    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, exc_type, exc, tb):
            return False

    return lambda *_a, **_k: _Ctx()


@pytest.fixture
def patch_env_checks():
    """Patch doctor checks so self_test environment validation always passes."""
    with (
        patch(
            "tools.self_test.load_validated_config",
            return_value={
                "ollama": {"host": "http://localhost:11434"},
                "models": {"registry": {"kimi": "kimi-k2.6:cloud"}},
                "mcp": {"http_port": 8001},
            },
        ),
        patch("tools.self_test._check_python", return_value={"name": "python_version", "ok": True}),
        patch("tools.self_test._check_imports", return_value={"name": "python_imports", "ok": True}),
        patch("tools.self_test._check_nmap", return_value={"name": "nmap_binary", "ok": True}),
        patch("tools.self_test._check_workspace", return_value={"name": "workspace_writable", "ok": True}),
        patch("tools.self_test._check_config", return_value={"name": "config_valid", "ok": True}),
        patch("tools.self_test._check_ollama", return_value={"name": "ollama_reachable", "ok": True}),
        patch("tools.self_test._check_models", return_value={"name": "model_registry", "ok": True}),
        patch("tools.self_test._check_port", return_value={"name": "port_free", "ok": True}),
    ):
        yield


def test_self_test_rejects_non_localhost(tmp_path: Path):
    """--self-test must refuse to run against anything other than localhost."""
    from tools.self_test import run_self_test

    args = _make_args(target="10.0.0.50", reports_dir=tmp_path)
    result = asyncio.run(run_self_test(args))
    assert result == 1


def test_self_test_runs_allowed_tools_only(tmp_path: Path, patch_env_checks):
    """self_test should only invoke the safe allow-list of tools."""
    from tools.self_test import run_self_test

    args = _make_args(reports_dir=tmp_path)
    fake = FakeMcpSession()

    with patch("tools.self_test.open_exploit_mcp_session", _fake_open_session(fake)):
        result = asyncio.run(run_self_test(args))

    assert result == 0
    called_tools = [name for name, _ in fake.call_tool_calls]
    assert "check_os" in called_tools
    assert "quick_scan" in called_tools
    assert "search_cve_intel" in called_tools
    assert "list_workspace" in called_tools
    assert "write_python_file" not in called_tools
    assert "run_python_file" not in called_tools
    assert "run_exploit_terminal" not in called_tools


def test_self_test_writes_report(tmp_path: Path, patch_env_checks):
    """self_test must write JSON and Markdown reports to the workspace."""
    from tools.self_test import run_self_test

    args = _make_args(reports_dir=tmp_path)
    fake = FakeMcpSession()

    with patch("tools.self_test.open_exploit_mcp_session", _fake_open_session(fake)):
        asyncio.run(run_self_test(args))

    workspaces = [d for d in tmp_path.iterdir() if d.is_dir() and d.name.startswith("self_test_")]
    assert len(workspaces) == 1
    ws = workspaces[0]
    json_report = ws / "self_test_report.json"
    md_report = ws / "self_test_report.md"
    assert json_report.exists()
    assert md_report.exists()

    data = json.loads(json_report.read_text(encoding="utf-8"))
    assert data["mode"] == "self_test"
    assert data["target_ip"] == "127.0.0.1"
    assert data["overall_ok"] is True
    assert any(stage.get("name") == "mcp_boot" and stage.get("ok") for stage in data["stages"])


def test_self_test_handles_tool_failure(tmp_path: Path, patch_env_checks):
    """If an allowed tool raises BaseExceptionGroup, the self-test should mark it but still write a report."""
    from tools.self_test import run_self_test

    args = _make_args(reports_dir=tmp_path)
    fake = FakeMcpSession(raise_on={"quick_scan"})

    with patch("tools.self_test.open_exploit_mcp_session", _fake_open_session(fake)):
        result = asyncio.run(run_self_test(args))

    assert result == 1
    workspaces = [d for d in tmp_path.iterdir() if d.is_dir() and d.name.startswith("self_test_")]
    assert len(workspaces) == 1
    data = json.loads((workspaces[0] / "self_test_report.json").read_text(encoding="utf-8"))
    quick_scan_result = next(r for r in data["tool_results"] if r["tool"] == "quick_scan")
    assert quick_scan_result["ok"] is False
