"""Regression tests for the sudo-or-pivot short-circuit (Gap 3).

``apt_install`` / ``install_package`` (apt+snap branches) / ``run_as_root``
used to prepend ``sudo`` via ``bash -c`` with no ``-n`` and no precheck, so on
a sudo-less / password-required operator box the subprocess HANGS on an
interactive password prompt. The fix short-circuits BEFORE spawning the
subprocess and returns a ``BLOCKED:`` pivot message. The ``BLOCKED:`` prefix
makes the LLM's existing BLOCKED-result detection treat it as a hard
constraint.

These tests patch ``tools.env_probe._can_passwordless_sudo`` and assert the
subprocess is NOT spawned on the no-sudo path (no hang), while the sudo path
still proceeds. They also confirm pip (no sudo) is unaffected.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest


def _make_server(tmp_path: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config: dict[str, Any] = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    return create_mcp_server(search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config)


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


def _patch_pgrp_nospawn(monkeypatch):
    """Patch _run_with_pgrp_timeout to FAIL the test if invoked (the pivot must
    short-circuit before it)."""
    import mcp_exploit_server as mes

    def _boom(args, timeout, *a, **k):
        raise AssertionError(
            f"_run_with_pgrp_timeout must not be called on the no-sudo pivot path; got argv={list(args)}"
        )

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _boom)


def _patch_subprocess_run_nospawn(monkeypatch):
    """Patch subprocess.run to FAIL the test if invoked (apt_install/pip_install
    use subprocess.run, not _run_with_pgrp_timeout)."""

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must not be called on the no-sudo pivot path")

    monkeypatch.setattr(subprocess, "run", _boom)


# ── apt_install ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apt_install_pivots_without_sudo(monkeypatch, tmp_path: Path) -> None:
    """No passwordless sudo -> BLOCKED pivot, no subprocess spawned (no hang)."""
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    _patch_subprocess_run_nospawn(monkeypatch)
    _patch_pgrp_nospawn(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("apt_install", {"packages": "nmap hydra"}))
    assert text.startswith("BLOCKED:")
    assert "passwordless sudo" in text
    assert "PIVOT" in text
    assert "write_python_file" in text


@pytest.mark.asyncio
async def test_apt_install_proceeds_with_sudo(monkeypatch, tmp_path: Path) -> None:
    """Passwordless sudo available -> normal apt path runs (mocked)."""
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: True)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a, returncode=0, stdout="", stderr=""),
    )
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("apt_install", {"packages": "nmap"}))
    assert text.startswith("APT_INSTALL_RESULT: completed")


# ── run_as_root ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_as_root_pivots_without_sudo(monkeypatch, tmp_path: Path) -> None:
    """No passwordless sudo -> BLOCKED pivot, no subprocess spawned."""
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    _patch_pgrp_nospawn(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("run_as_root", {"command": "whoami"}))
    assert text.startswith("BLOCKED:")
    assert "passwordless sudo" in text
    assert "PIVOT" in text


@pytest.mark.asyncio
async def test_run_as_root_target_lock_still_wins(monkeypatch, tmp_path: Path) -> None:
    """The target-IP lock fires BEFORE the sudo pivot (lock reports first on
    out-of-scope commands). No sudo, off-target command -> lock block, not pivot."""
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    _patch_pgrp_nospawn(monkeypatch)
    # Build an allowlist-enforcing server directly (require_explicit_allowlist=True).
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.5"]}},
    )
    text = _text(await mcp.call_tool("run_as_root", {"command": "nmap 10.0.0.99"}))
    assert "ROOT_CMD_RESULT: blocked" in text
    assert "allowlist" in text or "target lock" in text.lower()
    # The pivot message must NOT win over the target lock.
    assert "PIVOT" not in text


# ── install_package ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_install_package_apt_branch_pivots_without_sudo(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    _patch_subprocess_run_nospawn(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("install_package", {"manager": "apt", "packages": "nmap"}))
    assert text.startswith("BLOCKED:")
    assert "passwordless sudo" in text


@pytest.mark.asyncio
async def test_install_package_snap_branch_pivots_without_sudo(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    _patch_subprocess_run_nospawn(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("install_package", {"manager": "snap", "packages": "nmap"}))
    assert text.startswith("BLOCKED:")
    assert "passwordless sudo" in text


@pytest.mark.asyncio
async def test_install_package_pip_branch_unaffected_by_sudo(monkeypatch, tmp_path: Path) -> None:
    """pip does not use sudo; even with no sudo it proceeds (mocked)."""
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: False)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a, returncode=0, stdout="", stderr=""),
    )
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("install_package", {"manager": "pip", "packages": "requests"}))
    assert text.startswith("INSTALL_RESULT: completed")


@pytest.mark.asyncio
async def test_apt_install_pivots_on_windows(monkeypatch, tmp_path: Path) -> None:
    """On Windows _can_passwordless_sudo returns False -> pivot, no bogus sudo spawn."""
    import tools.env_probe as ep

    monkeypatch.setattr(ep.platform, "system", lambda: "Windows")
    # _can_passwordless_sudo checks platform.system() first -> returns False
    _patch_subprocess_run_nospawn(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("apt_install", {"packages": "nmap"}))
    assert text.startswith("BLOCKED:")
    assert "passwordless sudo" in text
