"""Regression tests for the git_clone existence preflight (Gap 4).

``git_clone`` only validated URL *format*, so a hallucinated PoC URL failed
only at clone time. The fix surfaces a ``PREFLIGHT_WARNING`` BEFORE the (slow)
clone attempt when the URL does not resolve. It never hard-blocks (private /
auth-gated repos 404 to unauthenticated HEAD), and skips the check for ssh/git
URLs. Also tests the shared ``tools.exploit_search.url_exists`` verdict helper.
"""

from __future__ import annotations

import urllib.error
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


def _patch_clone_ok(monkeypatch):
    """Patch _run_with_pgrp_timeout so git clone 'succeeds' without running git."""
    import mcp_exploit_server as mes

    def _fake(args, timeout, stdout=None, stderr=None, **k):
        return 0, "Cloning into 'repo'...", ""

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)


# ── url_exists verdict helper ───────────────────────────────────────────────


def test_url_exists_classifies_success(monkeypatch):
    from tools import exploit_search as es

    class _Resp:
        def __init__(self, code):
            self._c = code

        def getcode(self):
            return self._c

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        es.urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(200),
    )
    assert es.url_exists("https://github.com/x/y") == (True, None)


def test_url_exists_classifies_404_as_not_found(monkeypatch):
    from tools import exploit_search as es

    def _raise(*a, **k):
        raise urllib.error.HTTPError(a[0], 404, "Not Found", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(es.urllib.request, "urlopen", _raise)
    ok, reason = es.url_exists("https://github.com/x/y")
    assert ok is False
    assert reason == "not_found"


def test_url_exists_classifies_connection_error(monkeypatch):
    from tools import exploit_search as es

    def _raise(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(es.urllib.request, "urlopen", _raise)
    ok, reason = es.url_exists("https://github.com/x/y")
    assert ok is False
    assert reason == "connection_error"


# ── git_clone preflight integration ────────────────────────────────────────


@pytest.mark.asyncio
async def test_git_clone_warns_on_404(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "tools.exploit_search.url_exists",
        lambda url, timeout=8: (False, "not_found"),
    )
    _patch_clone_ok(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool("git_clone", {"repo_url": "https://github.com/user/repo.git", "target_dir": "repo"})
    )
    assert "PREFLIGHT_WARNING" in text
    assert "not_found" in text
    # Clone still proceeds (never hard-blocks).
    assert "GIT_CLONE_RESULT: completed" in text


@pytest.mark.asyncio
async def test_git_clone_warns_on_connection_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "tools.exploit_search.url_exists",
        lambda url, timeout=8: (False, "connection_error"),
    )
    _patch_clone_ok(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool("git_clone", {"repo_url": "https://github.com/user/repo.git", "target_dir": "repo"})
    )
    assert "PREFLIGHT_WARNING" in text
    assert "connection_error" in text


@pytest.mark.asyncio
async def test_git_clone_silent_when_url_ok(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "tools.exploit_search.url_exists",
        lambda url, timeout=8: (True, None),
    )
    _patch_clone_ok(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool("git_clone", {"repo_url": "https://github.com/user/repo.git", "target_dir": "repo"})
    )
    assert "PREFLIGHT_WARNING" not in text
    assert "GIT_CLONE_RESULT: completed" in text


@pytest.mark.asyncio
async def test_git_clone_import_failure_does_not_block(monkeypatch, tmp_path: Path) -> None:
    """If the url_exists import itself blows up, the clone still proceeds."""

    def _boom(*a, **k):
        raise ImportError("simulated")

    # Patch the lazy import target so the `from tools.exploit_search import url_exists`
    # inside git_clone resolves to a name that raises when called.
    import tools.exploit_search as es

    monkeypatch.setattr(es, "url_exists", _boom)
    _patch_clone_ok(monkeypatch)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool("git_clone", {"repo_url": "https://github.com/user/repo.git", "target_dir": "repo"})
    )
    assert "GIT_CLONE_RESULT: completed" in text
    assert "PREFLIGHT_WARNING" not in text


@pytest.mark.asyncio
async def test_git_clone_format_block_still_wins(monkeypatch, tmp_path: Path) -> None:
    """An invalid URL format is rejected before any preflight."""
    called: list[str] = []
    import tools.exploit_search as es

    monkeypatch.setattr(es, "url_exists", lambda *a, **k: called.append("called") or (True, None))
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("git_clone", {"repo_url": "not-a-url"}))
    assert text.startswith("BLOCKED:")
    assert "invalid repo URL" in text
    assert called == []  # preflight never ran on a format-rejected URL


# NOTE: ssh:// / git:// URLs are rejected by git_clone's format regex today
# (it only allows http(s) GitHub/GitLab URLs), so there is no live ssh-clone
# path to test the skip against. The skip is exercised implicitly: any URL
# that passes the format regex is http(s), so the preflight always runs for
# accepted URLs. If ssh clones are later allowed, add a test asserting
# url_exists is NOT called for ssh:// URLs.
