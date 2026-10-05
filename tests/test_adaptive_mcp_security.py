from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_tools.modules import adaptive
from tools.mcp_tools.registry import ToolContext
from tools.payload_crafter import PayloadCrafter


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register


def _register_mutate_tool(workspace: Path) -> Any:
    mcp = _FakeMCP()

    def identity(fn):
        return fn

    adaptive.register_adaptive_tools(
        mcp,
        ctx=ToolContext(
            workspace=workspace,
            config={"adaptive_exploits": {"enabled": True}},
            search=None,
            nvd=None,
            researcher=None,
            audit_tool=identity,
            require_allowlist=lambda: identity,
        ),
    )
    return mcp.tools["mutate_exploit"]


def test_mutate_exploit_rejects_symlink_to_host_file_before_model_use(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "worker"
    exploits = workspace / "exploits"
    exploits.mkdir(parents=True)
    generation_id = "gen-1712345678-deadbeef"
    host_secret = tmp_path / "host-secret.txt"
    host_secret.write_text("host credential must stay private", encoding="utf-8")
    script_path = exploits / f"{generation_id}.py"
    try:
        script_path.symlink_to(host_secret)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")
    (exploits / f"{generation_id}.json").write_text(
        json.dumps({"generation_id": generation_id, "parent_id": None}), encoding="utf-8"
    )

    def unexpected_model_use(*_args, **_kwargs):
        raise AssertionError("host file contents must be rejected before model setup")

    monkeypatch.setattr(adaptive, "_get_model_client", unexpected_model_use)
    mutate_exploit = _register_mutate_tool(workspace)

    result = mutate_exploit(generation_id, "connection failed")

    assert result.startswith("ERROR: Exploit mutation failed")
    assert "host credential must stay private" not in result
    assert host_secret.read_text(encoding="utf-8") == "host credential must stay private"


def test_mutate_exploit_rejects_path_traversal_identifier(tmp_path: Path, monkeypatch) -> None:
    mutate_exploit = _register_mutate_tool(tmp_path / "worker")
    monkeypatch.setattr(
        adaptive,
        "_get_model_client",
        lambda *_args, **_kwargs: pytest.fail("invalid identifier must be rejected before model setup"),
    )

    result = mutate_exploit("../../host-secret", "connection failed")

    assert result == "ERROR: script_id must be a valid generated exploit id."


def test_payload_crafter_does_not_follow_symlinked_output(tmp_path: Path) -> None:
    workspace = tmp_path / "worker"
    mutation_dir = workspace / "mutations"
    mutation_dir.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep original", encoding="utf-8")
    generation_id = "gen-1712345678-deadbeef"
    output_path = mutation_dir / f"{generation_id}.py"
    try:
        output_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")

    crafter = PayloadCrafter(workspace=workspace)

    with pytest.raises(OSError):
        crafter._save_script(generation_id, "print('untrusted')", parent_id=None, strategy="generate")

    assert outside.read_text(encoding="utf-8") == "keep original"
