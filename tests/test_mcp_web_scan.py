"""Tests for the structured ``run_web_scan`` MCP tool (idea 7).

Covers: registration, the scanner allowlist, IPv4 validation, the target-IP
allowlist lock (via ``@require_allowlist``), shell-metachar ``options``
rejection, the happy path, and the not-installed friendly message.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = True,
    allowed_targets: list[str] | None = None,
):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.sandbox.models import SandboxResult
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    class FakeSandbox:
        def __init__(self) -> None:
            self.cfg = SimpleNamespace(remove_stale_on_startup=False)
            self.calls: list[dict[str, Any]] = []
            self.result = SandboxResult(
                exit_code=0,
                stdout="ok\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.1,
                status="completed",
            )

        def container_path(self, host_path: Path) -> str:
            return f"/workspace/{host_path.name}"

        def execute_argv(self, argv: list[str], **kwargs: Any) -> SandboxResult:
            self.calls.append({"kind": "argv", "argv": list(argv), **kwargs})
            return self.result

    sandbox = FakeSandbox()

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets if allowed_targets is not None else ["10.0.0.50"],
        }
    }
    with patch("tools.sandbox.resolve_manager_with_fallback", return_value=(sandbox, "")):
        server = create_mcp_server(
            ExploitSearch(ExploitSearchSettings()),
            NVDClient(CVESearchSettings()),
            WebResearcher(WebResearcherSettings()),
            tmp_path,
            config,
        )
    server._test_sandbox = sandbox
    return server


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


@pytest.mark.asyncio
async def test_run_web_scan_is_registered(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "run_web_scan" in names


@pytest.mark.asyncio
async def test_run_web_scan_rejects_unsupported_scanner(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nessus", "target_ip": "10.0.0.50"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "unsupported scanner" in text


@pytest.mark.asyncio
async def test_run_web_scan_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "not-an-ip"},
        )
    )
    assert text.startswith("BLOCKED:")
    # The target allowlist decorator rejects malformed/out-of-scope input
    # before the tool body or sandbox can run.
    assert not mcp._test_sandbox.calls


@pytest.mark.asyncio
async def test_run_web_scan_blocks_out_of_allowlist_target(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "10.0.0.99"},
        )
    )
    # @require_allowlist blocks before the function body runs.
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_run_web_scan_rejects_shell_metachar_options(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "10.0.0.50", "options": "x; rm -rf /"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "metacharacters" in text


@pytest.mark.asyncio
async def test_run_web_scan_happy_path(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)

    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "10.0.0.50", "port": 8080},
        )
    )
    assert "WEB_SCAN_RESULT: completed" in text
    assert "SCANNER: nikto" in text
    assert "TARGET: 10.0.0.50:8080" in text
    # The process goes through the worker manager as argv, never a host runner.
    calls = [call for call in mcp._test_sandbox.calls if call["kind"] == "argv"]
    assert calls
    assert calls[0]["argv"][0] == "nikto"
    assert "10.0.0.50" in calls[0]["argv"]
    assert "8080" in calls[0]["argv"]


@pytest.mark.asyncio
async def test_run_web_scan_does_not_follow_worker_log_symlink(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    outside = tmp_path / "operator-data.txt"
    outside.write_text("keep", encoding="utf-8")
    from tools.mcp_tools import sandbox_exec

    execute = sandbox_exec.run_argv_in_sandbox

    def create_worker_symlink(ctx: Any, argv: list[str], **kwargs: Any):
        attempt_dir = kwargs["cwd_host"]
        (attempt_dir / "nikto.log").symlink_to(outside)
        return execute(ctx, argv, **kwargs)

    monkeypatch.setattr(sandbox_exec, "run_argv_in_sandbox", create_worker_symlink)
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "10.0.0.50"},
        )
    )

    assert "WEB_SCAN_RESULT: completed" in text
    assert outside.read_text(encoding="utf-8") == "keep"


@pytest.mark.asyncio
async def test_run_web_scan_not_installed(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    from tools.sandbox.models import SandboxResult

    mcp._test_sandbox.result = SandboxResult(
        exit_code=127,
        stdout="",
        stderr="not found",
        timed_out=False,
        duration_seconds=0.1,
        status="failed",
    )
    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nikto", "target_ip": "10.0.0.50"},
        )
    )
    assert "scanner 'nikto' is not installed in the sandbox worker image" in text


@pytest.mark.asyncio
async def test_run_web_scan_builds_url_scanner_argv(tmp_path: Path, monkeypatch) -> None:
    """nuclei/sqlmap/whatweb/wpscan take a URL, not -h; confirm the argv shape."""
    mcp = _make_server(tmp_path, require_allowlist=False)

    text = _text(
        await mcp.call_tool(
            "run_web_scan",
            {"scanner": "nuclei", "target_ip": "10.0.0.50", "port": 80, "path": "/"},
        )
    )
    calls = [call for call in mcp._test_sandbox.calls if call["kind"] == "argv"]
    assert "WEB_SCAN_RESULT: completed" in text
    assert calls[0]["argv"][0] == "nuclei"
    assert "-u" in calls[0]["argv"]
    assert "http://10.0.0.50:80/" in calls[0]["argv"]
