"""Regression tests for the lateral-movement / credential-harvest MCP tools.

Before the fix in mcp_exploit_server.py the three tools ``lateral_exec``,
``dump_credentials`` and ``kerberoast`` were registered ``@mcp.tool()``s whose
bodies referenced parameters (``method``, ``ntlm_hash``, ``domain``, ``dc_ip``,
``username``, ``password``) that were NOT declared in their signatures — so every
real call raised ``NameError`` before doing any work, with zero test coverage.

These tests prove the signatures now match the bodies: the guard paths that
previously ``NameError``'d return the intended ``BLOCKED`` messages, and valid
calls execute end-to-end (subprocess mocked). The allowlist gate (shared
``require_allowlist`` decorator) is also exercised for one tool.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool,
    allowed_targets: list[str] | None = None,
):
    from mcp_exploit_server import create_mcp_server
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.cve_lookup import NVDClient, CVESearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets or [],
        }
    }
    return create_mcp_server(
        search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config
    )


def _text(result) -> str:
    """Extract the concatenated text payload from a FastMCP call_tool result.

    Handles both the (content_list, structured) tuple shape and a CallToolResult
    object with a ``.content`` attribute, across SDK versions.
    """
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


def _ok_run(*args, **kwargs):
    """Mocked subprocess.run that always reports success."""
    return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok output", stderr="")


# ── lateral_exec ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lateral_exec_guard_missing_method(tmp_path: Path) -> None:
    """Regression: body referenced `method` (absent from old signature) -> NameError."""
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("lateral_exec", {"target_ip": "10.0.0.1", "method": ""}))
    assert "BLOCKED" in text and "method is required" in text


@pytest.mark.asyncio
async def test_lateral_exec_guard_unsupported_method(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "lateral_exec", {"target_ip": "10.0.0.1", "method": "foo", "username": "admin"}
    ))
    assert "BLOCKED" in text and "unsupported method 'foo'" in text


@pytest.mark.asyncio
async def test_lateral_exec_guard_missing_secret(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "lateral_exec", {"target_ip": "10.0.0.1", "method": "psexec", "username": "admin"}
    ))
    assert "BLOCKED" in text and "either password or ntlm_hash must be provided" in text


@pytest.mark.asyncio
async def test_lateral_exec_guard_invalid_hash(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {"target_ip": "10.0.0.1", "method": "psexec", "username": "admin", "ntlm_hash": "zzz"},
    ))
    assert "BLOCKED" in text and "ntlm_hash must be 32 hex chars" in text


@pytest.mark.asyncio
async def test_lateral_exec_valid_run(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", _ok_run)
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {
            "target_ip": "10.0.0.1",
            "method": "psexec",
            "username": "admin",
            "password": "pass",
            "command": "whoami",
        },
    ))
    assert "LATERAL_EXEC_RESULT: completed" in text
    assert "METHOD: psexec" in text


@pytest.mark.asyncio
async def test_lateral_exec_blocked_by_allowlist(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["192.168.1.50"])
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {
            "target_ip": "10.0.0.99",
            "method": "psexec",
            "username": "admin",
            "password": "pass",
            "command": "whoami",
        },
    ))
    assert "not in the explicit allowlist" in text


# ── dump_credentials ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dump_credentials_guard_missing_method(tmp_path: Path) -> None:
    """Regression: body referenced `method` (absent from old signature) -> NameError."""
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("dump_credentials", {"target_ip": "10.0.0.1", "method": ""}))
    assert "BLOCKED" in text and "method is required" in text


@pytest.mark.asyncio
async def test_dump_credentials_guard_unsupported_method(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("dump_credentials", {"target_ip": "10.0.0.1", "method": "foo"}))
    assert "BLOCKED" in text and "unsupported method 'foo'" in text


@pytest.mark.asyncio
async def test_dump_credentials_secretsdump_missing_username(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials", {"target_ip": "10.0.0.1", "method": "secretsdump", "password": "pass"}
    ))
    assert "BLOCKED" in text and "username is required for secretsdump" in text


@pytest.mark.asyncio
async def test_dump_credentials_secretsdump_missing_secret(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials", {"target_ip": "10.0.0.1", "method": "secretsdump", "username": "admin"}
    ))
    assert "BLOCKED" in text and "either password or ntlm_hash must be provided for secretsdump" in text


@pytest.mark.asyncio
async def test_dump_credentials_sam_local_valid(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", _ok_run)
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("dump_credentials", {"target_ip": "10.0.0.1", "method": "sam_local"}))
    assert "CRED_DUMP_RESULT: completed" in text
    assert "METHOD: sam_local" in text


# ── dump_credentials: dcsync (DCSync via DRSUAPI) ──────────────────────────

@pytest.mark.asyncio
async def test_dump_credentials_dcsync_missing_username(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials", {"target_ip": "10.0.0.1", "method": "dcsync", "password": "pass"}
    ))
    assert "BLOCKED" in text and "username is required for dcsync" in text


@pytest.mark.asyncio
async def test_dump_credentials_dcsync_missing_secret(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials", {"target_ip": "10.0.0.1", "method": "dcsync", "username": "admin"}
    ))
    assert "BLOCKED" in text and "either password or ntlm_hash must be provided for dcsync" in text


@pytest.mark.asyncio
async def test_dump_credentials_dcsync_valid_run(monkeypatch, tmp_path: Path) -> None:
    """DCSync must build an impacket-secretsdump argv with -just-dc (no shell)."""
    captured: dict[str, Any] = {}

    def _run(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", _run)
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials",
        {
            "target_ip": "10.0.0.1",
            "method": "dcsync",
            "username": "admin",
            "password": "pass",
            "domain": "corp",
            "target_user": "krbtgt",
        },
    ))
    assert "CRED_DUMP_RESULT: completed" in text
    assert "METHOD: dcsync" in text
    argv = captured["argv"]
    assert argv[0] == "impacket-secretsdump"
    assert "corp/admin:pass@10.0.0.1" in argv
    assert "-just-dc" in argv
    assert "-just-dc-user" in argv and "krbtgt" in argv
    assert "-outputfile" in argv
    # No shell metachar injection vector: argv list, not a bash -c string.
    assert "bash" not in argv and "-c" not in argv


@pytest.mark.asyncio
async def test_dump_credentials_dcsync_with_ntlm_hash(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _run(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", _run)
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "dump_credentials",
        {
            "target_ip": "10.0.0.1",
            "method": "dcsync",
            "username": "admin",
            "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        },
    ))
    assert "CRED_DUMP_RESULT: completed" in text
    argv = captured["argv"]
    assert "-hashes" in argv
    # Only the NT half (after the colon) is passed to -hashes.
    idx = argv.index("-hashes")
    assert argv[idx + 1] == ":31d6cfe0d16ae931b73c59d7e0c089c0"


# ── kerberoast ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kerberoast_guard_missing_domain(tmp_path: Path) -> None:
    """Regression: body referenced `domain` (absent from old signature) -> NameError."""
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("kerberoast", {"target_ip": "10.0.0.1", "domain": ""}))
    assert "BLOCKED" in text and "domain is required" in text


@pytest.mark.asyncio
async def test_kerberoast_guard_missing_secret(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool("kerberoast", {"target_ip": "10.0.0.1", "domain": "corp"}))
    assert "BLOCKED" in text and "either password or ntlm_hash must be provided" in text


@pytest.mark.asyncio
async def test_kerberoast_guard_invalid_dc_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "kerberoast",
        {"target_ip": "10.0.0.1", "domain": "corp", "password": "p", "dc_ip": "not-an-ip"},
    ))
    assert "ERROR: Invalid IPv4 address for dc_ip" in text


@pytest.mark.asyncio
async def test_kerberoast_valid_run(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", _ok_run)
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "kerberoast",
        {"target_ip": "10.0.0.1", "domain": "corp", "username": "svc", "password": "pass"},
    ))
    assert "KERBEROAST_RESULT: completed" in text
    assert "DOMAIN: corp" in text