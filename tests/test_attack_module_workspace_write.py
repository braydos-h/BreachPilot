from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):
        def register(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return register


@pytest.mark.parametrize("script_source", ["run", "generate"])
@pytest.mark.parametrize("target_ip", ["192.0.2.10", f"{'a' * 60}.example.com"])
def test_generated_attack_script_does_not_follow_workspace_modules_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script_source: str, target_ip: str
) -> None:
    from tools.mcp_tools import attack_modules as attack_modules_tools

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "modules").symlink_to(outside, target_is_directory=True)

    script = "print('generated safely')\n"
    result = {"status": "script_generated", "script": script if script_source == "run" else ""}
    module = SimpleNamespace(
        applicability=lambda _ctx: 1,
        run=lambda _ctx: result,
        generate_python_script=lambda _ctx: script,
    )
    monkeypatch.setattr(attack_modules_tools, "get_module", lambda _name: module)
    monkeypatch.setattr(attack_modules_tools, "validate_target_or_ip", lambda _target: True)

    mcp = _FakeMCP()

    def identity(fn: Any) -> Any:
        return fn

    ctx = SimpleNamespace(
        workspace=workspace,
        config={},
        search=None,
        nvd=None,
        researcher=None,
        audit_tool=identity,
        require_allowlist=lambda: identity,
    )
    attack_modules_tools.register_attack_module_tools(mcp, ctx=ctx)

    response = mcp.tools["run_attack_module"]("ExampleModule", target_ip)

    assert "SCRIPT_SAVED:" in response
    saved_line = next(line for line in response.splitlines() if line.startswith("SCRIPT_SAVED: "))
    saved_path = Path(saved_line.removeprefix("SCRIPT_SAVED: "))
    assert saved_path.parent == workspace
    assert len(saved_path.stem) <= 80
    assert saved_path.read_text(encoding="utf-8") == script
    assert list(outside.iterdir()) == []
    assert (workspace / "modules").is_symlink()
