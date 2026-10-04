from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register


def _identity_decorator(fn):
    return fn


class _WorkerThatPlantsLogSymlink:
    def __init__(self, sentinel: Path) -> None:
        self.sentinel = sentinel
        self.attempt_dirs: list[Path] = []

    def container_path(self, host_path: Path) -> str:
        return str(host_path)

    def execute(self, _command: str, **kwargs):
        from tools.sandbox.models import SandboxResult

        attempt_dir = Path(kwargs["cwd"])
        self.attempt_dirs.append(attempt_dir)
        (attempt_dir / "terminal.log").symlink_to(self.sentinel)
        return SandboxResult(
            exit_code=0,
            stdout="worker output",
            stderr="",
            timed_out=False,
            duration_seconds=0.01,
            sandbox_id="test-worker",
            status="completed",
        )


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("run_exploit_terminal", {"command": "echo safe"}),
        ("run_exploit_terminals", {"commands": ["echo safe"]}),
    ],
)
def test_sandbox_terminal_never_follows_worker_created_log_symlink(
    tmp_path: Path,
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    from tools.mcp_tools.terminal.execute import _register_execute_tools

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sentinel = tmp_path / "operator-data.txt"
    sentinel.write_text("keep this host file", encoding="utf-8")
    sandbox = _WorkerThatPlantsLogSymlink(sentinel)
    ctx = SimpleNamespace(
        workspace=workspace,
        config={
            "sandbox": {"enabled": True},
            "exploit": {"allowed_targets": [], "require_explicit_allowlist": False},
        },
        sandbox=sandbox,
        audit_tool=_identity_decorator,
    )
    mcp = _FakeMCP()
    _register_execute_tools(mcp, ctx=ctx)

    result = mcp.tools[tool_name](**arguments)

    assert sentinel.read_text(encoding="utf-8") == "keep this host file"
    assert (sandbox.attempt_dirs[0] / "terminal.log").is_symlink()
    assert "LOG_PERSISTENCE: skipped" in result
    assert "OUTPUT:\nworker output" in result
