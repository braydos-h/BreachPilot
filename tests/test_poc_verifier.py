"""Tests for self-healing PoC verification (D1, Killer Feature #3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.poc_verifier import (
    VerifyResult,
    code_sha256,
    docker_check,
    poc_verification_config,
    render_verify_result,
    syntax_check,
    verify_poc,
)

# ─── syntax_check ─────────────────────────────────────────────────────────


def test_syntax_check_accepts_valid_code() -> None:
    result = syntax_check("def ok():\n    return 1\n")
    assert result.syntax_ok is True
    assert result.stderr == ""


def test_syntax_check_rejects_syntax_error() -> None:
    result = syntax_check("def broken(:\n    pass\n")
    assert result.syntax_ok is False
    assert "SyntaxError" in result.stderr or "invalid" in result.stderr.lower() or result.stderr != ""


def test_syntax_check_rejects_empty_code() -> None:
    assert syntax_check("").syntax_ok is False
    assert syntax_check("   \n  ").syntax_ok is False


def test_syntax_check_does_not_execute_code() -> None:
    # A file that would raise at runtime must still pass the syntax gate
    # (py_compile does not execute). This proves the gate is compile-only.
    result = syntax_check("import sys\nraise SystemExit(7)\n")
    assert result.syntax_ok is True


# ─── code_sha256 ──────────────────────────────────────────────────────────


def test_code_sha256_is_16_hex_chars() -> None:
    sha = code_sha256("def ok():\n    return 1\n")
    assert len(sha) == 16
    assert all(c in "0123456789abcdef" for c in sha)


def test_code_sha256_changes_with_code() -> None:
    assert code_sha256("a=1\n") != code_sha256("a=2\n")


# ─── docker_check (monkeypatched -- no real Docker in CI) ─────────────────


def test_docker_check_returns_none_when_docker_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.poc_verifier._docker_available", lambda: False)
    ok, err = docker_check("def ok():\n    return 1\n")
    assert ok is None
    assert "not available" in err


def test_docker_check_runs_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Proc:
        returncode = 0
        stderr = ""

    monkeypatch.setattr("tools.poc_verifier._docker_available", lambda: True)
    monkeypatch.setattr(
        "tools.poc_verifier.subprocess.run",
        lambda *a, **k: _Proc(),
    )
    ok, err = docker_check("def ok():\n    return 1\n")
    assert ok is True


def test_docker_check_fails_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Proc:
        returncode = 1
        stderr = "SyntaxError: invalid"

    monkeypatch.setattr("tools.poc_verifier._docker_available", lambda: True)
    monkeypatch.setattr(
        "tools.poc_verifier.subprocess.run",
        lambda *a, **k: _Proc(),
    )
    ok, err = docker_check("def broken(:\n    pass\n")
    assert ok is False
    assert "SyntaxError" in err


# ─── verify_poc (integration of syntax + docker) ─────────────────────────


def test_verify_poc_syntax_only_when_docker_disabled() -> None:
    result = verify_poc("def ok():\n    return 1\n", use_docker=False)
    assert isinstance(result, VerifyResult)
    assert result.syntax_ok is True
    assert result.docker_ok is None  # degraded


def test_verify_poc_returns_none_docker_when_syntax_fails() -> None:
    result = verify_poc("def broken(:\n    pass\n", use_docker=True)
    assert result.syntax_ok is False
    # Syntax failure short-circuits before the docker path is even consulted.
    assert result.docker_ok is None


def test_verify_poc_degrades_to_syntax_only_when_no_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.poc_verifier._docker_available", lambda: False)
    result = verify_poc("def ok():\n    return 1\n", use_docker=True)
    assert result.syntax_ok is True
    assert result.docker_ok is None


# ─── render_verify_result ────────────────────────────────────────────────


def test_render_verify_result_has_required_fields() -> None:
    r = VerifyResult(syntax_ok=True, docker_ok=None, stderr="", code_sha256="abc123", image="python:3.11-slim")
    text = render_verify_result(r)
    assert "VERIFY_POC_RESULT:" in text
    assert "CODE_SHA256: abc123" in text
    assert "SYNTAX_OK: true" in text
    assert "DOCKER_OK: skipped" in text


# ─── poc_verification_config ─────────────────────────────────────────────


def test_poc_verification_config_defaults_when_absent() -> None:
    cfg = poc_verification_config(None)
    assert cfg["enabled"] is False
    assert cfg["docker_image"] == "python:3.11-slim"
    assert cfg["compile_timeout_seconds"] == 30
    assert cfg["max_retries"] == 3
    assert cfg["docker_network"] == "none"
    assert cfg["docker_read_only"] is True
    assert cfg["docker_memory"] == "256m"


def test_poc_verification_config_overlays_user_values() -> None:
    cfg = poc_verification_config({"poc_verification": {"enabled": True, "docker_memory": "512m", "max_retries": 5}})
    assert cfg["enabled"] is True
    assert cfg["docker_memory"] == "512m"
    assert cfg["max_retries"] == 5
    # Untouched keys keep their defaults.
    assert cfg["docker_image"] == "python:3.11-slim"


# ─── MCP registration (tool is registered + callable) ────────────────────


def _server(tmp_path: Path, config: dict):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path,
        config,
    )


@pytest.mark.asyncio
async def test_verify_poc_tool_is_registered(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"poc_verification": {"enabled": False}})
    names = {tool.name for tool in await mcp.list_tools()}
    assert "verify_poc" in names


@pytest.mark.asyncio
async def test_verify_poc_tool_rejects_empty_code(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"poc_verification": {"enabled": False}})
    result = await mcp.call_tool("verify_poc", {"code": ""})
    text = result.content[0].text if hasattr(result, "content") else str(result)
    assert "BLOCKED" in text


@pytest.mark.asyncio
async def test_verify_poc_tool_syntax_ok_when_docker_disabled(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"poc_verification": {"enabled": False}})
    result = await mcp.call_tool("verify_poc", {"code": "def ok():\n    return 1\n"})
    text = result.content[0].text if hasattr(result, "content") else str(result)
    assert "SYNTAX_OK: true" in text
    # Docker disabled in config -> degraded path.
    assert "DOCKER_OK: skipped" in text


@pytest.mark.asyncio
async def test_verify_poc_tool_syntax_error(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"poc_verification": {"enabled": False}})
    result = await mcp.call_tool("verify_poc", {"code": "def broken(:\n    pass\n"})
    text = result.content[0].text if hasattr(result, "content") else str(result)
    assert "SYNTAX_OK: false" in text


# ─── cve_to_exploit_synth wiring ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_cve_to_exploit_synth_inlines_syntax_check_when_enabled(tmp_path: Path) -> None:
    mcp = _server(tmp_path, {"poc_verification": {"enabled": True}})
    # The target IP must be in the allowlist for the @require_allowlist gate.
    import os

    os.environ["EXPLOIT_TARGET"] = "10.0.0.50"
    try:
        result = await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.50", "cve_id": "CVE-2021-44228"},
        )
        text = result.content[0].text if hasattr(result, "content") else str(result)
        assert "PoC Verification" in text or "SYNTAX_OK" in text
    finally:
        del os.environ["EXPLOIT_TARGET"]
