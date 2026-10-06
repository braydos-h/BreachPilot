"""Agent terminal tools must refuse execution when no sandbox worker exists."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from tools.mcp_tools.terminal.execute import _register_execute_tools


class _ToolRegistry:
    def __init__(self) -> None:
        self.tools = {}

    def tool(self):
        return lambda fn: self.tools.setdefault(fn.__name__, fn)


def test_terminal_family_never_executes_or_probes_from_host(tmp_path: Path, monkeypatch) -> None:
    registry = _ToolRegistry()
    context = SimpleNamespace(
        workspace=tmp_path,
        config={"exploit": {"allowed_targets": ["example.com"]}},
        audit_tool=lambda fn: fn,
        sandbox=None,
    )
    _register_execute_tools(registry, ctx=context)

    def forbidden(*args, **kwargs):
        raise AssertionError("agent-controlled work must never execute or probe on the host")

    monkeypatch.setattr("tools.mcp_tools.terminal.execute._run_with_pgrp_timeout", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("tools.exploit_search.url_exists", forbidden)

    calls = {
        "run_exploit_terminal": {"command": "id"},
        "run_exploit_terminals": {"commands": ["id"]},
        "run_as_root": {"command": "id"},
        "git_clone": {"repo_url": "https://github.com/example/repo.git"},
    }
    for name, arguments in calls.items():
        result = registry.tools[name](**arguments)
        assert "SANDBOX_UNSUPPORTED" in result
        assert "active sandbox worker" in result


def test_terminal_checks_scope_before_reporting_missing_worker(tmp_path: Path) -> None:
    registry = _ToolRegistry()
    context = SimpleNamespace(
        workspace=tmp_path,
        config={"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["example.com"]}},
        audit_tool=lambda fn: fn,
        sandbox=None,
    )
    _register_execute_tools(registry, ctx=context)

    result = registry.tools["run_exploit_terminal"](command="curl https://outside.example.net/")

    assert "not in the explicit allowlist" in result
    assert "SANDBOX_UNSUPPORTED" not in result
