"""Unit tests for the MCP sandbox execution funnel (tools/mcp_tools/sandbox_exec.py).

Covers:
- Destination extraction for the scope gate (IPs, endpoints, encoded forms).
- Disabled sandbox => (False, None) so documented legacy mode still works.
- Active sandbox => contained execution via the manager.
- Any sandbox failure becomes a canonical SANDBOX_* block (never host exec).
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.mcp_tools.sandbox_exec import (
    collect_command_targets,
    run_argv_in_sandbox,
    run_command_in_sandbox,
    sandbox_error_block,
)
from tools.sandbox.exceptions import SandboxScopeError, SandboxUnavailableError


class FakeManager:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.raise_error: Exception | None = None

    def execute(self, command, **kwargs):
        self.calls.append(("cmd", command, kwargs))
        if self.raise_error:
            raise self.raise_error
        from tools.sandbox.models import SandboxResult

        return SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, duration_seconds=0.1)

    def execute_argv(self, argv, **kwargs):
        self.calls.append(("argv", argv, kwargs))
        if self.raise_error:
            raise self.raise_error
        from tools.sandbox.models import SandboxResult

        return SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, duration_seconds=0.1)

    def container_path(self, host_path):
        return f"/workspace/{host_path.name}"


class Ctx:
    def __init__(self, manager: Any) -> None:
        self.sandbox = manager


class TestCollectCommandTargets:
    def test_plain_ip_extracted(self):
        targets = collect_command_targets("nmap -sV 192.0.2.10")
        assert "192.0.2.10" in targets

    def test_encoded_ip_expanded(self):
        # decimal-encoded IP (http://127.0.0.1 == http://2130706433) is expanded
        targets = collect_command_targets("curl http://2130706433/")
        assert any(t in ("127.0.0.1", "2130706433") for t in targets)

    def test_no_destination_means_empty(self):
        assert collect_command_targets("python -c 'print(1)'") == []


class TestRunCommandInSandbox:
    def test_disabled_returns_false(self):
        ran, result = run_command_in_sandbox(Ctx(None), "id", timeout=30)
        assert ran is False
        assert result is None

    def test_active_runs_through_manager(self):
        mgr = FakeManager()
        ran, result = run_command_in_sandbox(Ctx(mgr), "nmap 192.0.2.10", timeout=30, tool_name="run_exploit_terminal")
        assert ran is True
        assert result.exit_code == 0
        kind, command, kwargs = mgr.calls[0]
        assert kind == "cmd"
        assert kwargs["target_ip"] == "192.0.2.10"

    def test_scope_error_propagates_fail_closed(self):
        mgr = FakeManager()
        mgr.raise_error = SandboxScopeError("not allowed")
        with pytest.raises(SandboxScopeError):
            run_command_in_sandbox(Ctx(mgr), "id", timeout=30)


class TestRunArgvInSandbox:
    def test_active_runs_argv(self):
        mgr = FakeManager()
        ran, result = run_argv_in_sandbox(Ctx(mgr), ["nmap", "-sV", "192.0.2.10"], target_ip="192.0.2.10", timeout=60)
        assert ran is True
        kind, argv, kwargs = mgr.calls[0]
        assert kind == "argv"
        assert argv == ["nmap", "-sV", "192.0.2.10"]

    def test_disabled_returns_false(self):
        assert run_argv_in_sandbox(Ctx(None), ["ls"], timeout=5) == (False, None)


class TestSandboxErrorBlock:
    def test_scope_error_block(self):
        block = sandbox_error_block(SandboxScopeError("target denied"), tool_name="run_exploit_terminal")
        assert "SANDBOX_SCOPE_DENIED" in block
        assert "fail closed" in block.lower().replace("-", " ") or "not run on the host" in block

    def test_unavailable_error_block(self):
        block = sandbox_error_block(SandboxUnavailableError("no docker"))
        assert "SANDBOX_UNAVAILABLE" in block

    def test_unexpected_error_still_fails_closed(self):
        block = sandbox_error_block(RuntimeError("boom"))
        assert "SANDBOX_UNAVAILABLE" in block
        assert "boom" in block
