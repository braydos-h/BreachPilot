"""Regression tests for target-facing MCP commands using only the sandbox funnel."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.mcp_tools.sandbox_exec import run_tool_argv_in_sandbox
from tools.sandbox.exceptions import SandboxUnavailableError
from tools.sandbox.models import SandboxResult


def test_target_tool_blocks_when_worker_manager_is_unavailable() -> None:
    status, code, output, _elapsed = run_tool_argv_in_sandbox(
        SimpleNamespace(sandbox=None),
        ["impacket-secretsdump", "user@10.0.0.5"],
        target_ip="10.0.0.5",
        timeout=10,
        tool_name="dump_credentials",
    )
    assert status == "blocked"
    assert code is None
    assert "SANDBOX_UNSUPPORTED" in output
    assert "EXECUTED: nowhere" in output


def test_target_tool_maps_workspace_paths_and_checks_all_targets(tmp_path: Path) -> None:
    class FakeManager:
        def __init__(self) -> None:
            self.targets: list[str] = []
            self.argv: list[str] = []
            self.cwd: str | None = None
            self.input_text = ""

        def container_path(self, path: Path) -> str:
            rel = Path(path).resolve().relative_to(tmp_path.resolve())
            return f"/workspace/{rel.as_posix()}"

        def _enforce_scope(self, target: str, *, command: str = "") -> None:
            self.targets.append(target)

        def execute_argv(self, argv, *, cwd=None, **_kwargs):
            self.argv = list(argv)
            self.cwd = cwd
            self.input_text = _kwargs.get("input_text", "")
            return SandboxResult(0, "ok", "", False, 0.01, status="completed")

    manager = FakeManager()
    artifact = tmp_path / "attempt-1" / "out.txt"
    artifact.parent.mkdir()
    status, code, output, _elapsed = run_tool_argv_in_sandbox(
        SimpleNamespace(sandbox=manager),
        ["impacket-secretsdump", "-outputfile", str(artifact)],
        target_ip="10.0.0.5",
        targets=["10.0.0.5", "10.0.0.6"],
        cwd_host=artifact.parent,
        timeout=10,
        tool_name="dump_credentials",
        input_text='{"request":"contained"}',
    )
    assert (status, code, output) == ("completed", 0, "ok")
    assert manager.argv[-1] == "/workspace/attempt-1/out.txt"
    assert manager.cwd == "/workspace/attempt-1"
    assert manager.targets == ["10.0.0.5", "10.0.0.6"]
    assert manager.input_text == '{"request":"contained"}'


def test_sandbox_failure_does_not_call_host_subprocess(monkeypatch) -> None:
    import subprocess

    def forbidden(*_args, **_kwargs):
        raise AssertionError("host subprocess fallback was reached")

    monkeypatch.setattr(subprocess, "run", forbidden)

    class FailedManager:
        def _enforce_scope(self, target: str, *, command: str = "") -> None:
            return None

        def execute_argv(self, *_args, **_kwargs):
            raise SandboxUnavailableError("worker unavailable")

    status, code, output, _elapsed = run_tool_argv_in_sandbox(
        SimpleNamespace(sandbox=FailedManager()),
        ["impacket-secretsdump", "user@10.0.0.5"],
        target_ip="10.0.0.5",
        timeout=10,
        tool_name="dump_credentials",
    )
    assert status == "blocked"
    assert code is None
    assert "SANDBOX_UNAVAILABLE" in output
    assert "EXECUTED: nowhere" in output


@pytest.mark.asyncio
async def test_bridge_direct_mcp_call_keeps_exploit_policy_gate() -> None:
    import asyncio

    from tools.swarm_bridge import SwarmMcpBridge

    class Policy:
        approved = True

        async def approve_action(self, name: str, command: str) -> bool:
            self.last_call = (name, command)
            return self.approved

    class Session:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def call_tool(self, name: str, *, arguments: dict[str, object]) -> str:
            self.calls.append((name, arguments))
            return "ok"

    bridge = SwarmMcpBridge()
    policy = Policy()
    session = Session()
    bridge.attach(session, [], policy, asyncio.get_running_loop())

    assert await bridge.call_tool_on_loop("run_full_recon", {"target_ip": "192.0.2.10"}) == "ok"
    assert policy.last_call[0] == "run_full_recon"
    assert session.calls == [("run_full_recon", {"target_ip": "192.0.2.10"})]

    policy.approved = False
    with pytest.raises(PermissionError, match="ExploitPolicy denied"):
        await bridge.call_tool_on_loop("run_full_recon", {"target_ip": "192.0.2.10"})
    assert len(session.calls) == 1
