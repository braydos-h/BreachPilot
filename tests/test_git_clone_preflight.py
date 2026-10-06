"""Pinned URL verification and sandbox-only Git clone regressions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.exploit_search import _is_allowed_poc_url, url_exists


def test_url_exists_classifies_status_using_pinned_transport(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_probe(url: str, **kwargs: Any) -> tuple[int, str]:
        calls.append({"url": url, **kwargs})
        return 200, url

    monkeypatch.setattr("tools.exploit_search.probe_url", fake_probe)

    assert url_exists("https://github.com/org/repo") == (True, None)
    assert len(calls) == 1
    assert calls[0]["policy"].allowed_domains
    assert calls[0]["user_agent"]


def test_url_exists_preserves_not_found_classification(monkeypatch) -> None:
    monkeypatch.setattr("tools.exploit_search.probe_url", lambda *args, **kwargs: (404, args[0]))
    assert url_exists("https://www.exploit-db.com/exploits/123") == (False, "not_found")


def test_url_exists_rejects_untrusted_authorities_before_network(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("tools.exploit_search.probe_url", lambda url, **kwargs: calls.append(url))

    assert not _is_allowed_poc_url("https://github.com@127.0.0.1:2375/path")
    assert url_exists("https://github.com@127.0.0.1:2375/path") == (False, "connection_error")
    assert url_exists("https://github.com.attacker.invalid/path") == (False, "connection_error")
    assert url_exists("http://github.com/path") == (False, "connection_error")
    assert calls == []


class _ToolRegistry:
    def __init__(self) -> None:
        self.tools = {}

    def tool(self):
        return lambda fn: self.tools.setdefault(fn.__name__, fn)


def _git_clone_tool(tmp_path: Path, sandbox: object):
    from tools.mcp_tools.terminal.execute import _register_execute_tools

    registry = _ToolRegistry()
    context = SimpleNamespace(
        workspace=tmp_path,
        config={"exploit": {"allowed_targets": []}},
        audit_tool=lambda fn: fn,
        sandbox=sandbox,
        sandbox_notice="",
    )
    _register_execute_tools(registry, ctx=context)
    return registry.tools["git_clone"]


def test_git_clone_has_no_host_url_preflight_and_runs_inside_worker(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    result = SimpleNamespace(status="completed", exit_code=0, stdout="cloned", stderr="", duration_seconds=0.1)

    def fake_run(_ctx: Any, argv: list[str], **kwargs: Any):
        calls.append((argv, kwargs))
        return True, result

    def forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("git URL preflight must not make a host-side request")

    monkeypatch.setattr("tools.mcp_tools.terminal.execute.run_argv_in_sandbox", fake_run)
    monkeypatch.setattr("tools.exploit_search.url_exists", forbidden)
    tool = _git_clone_tool(tmp_path, object())

    text = tool(repo_url="https://github.com/user/repo.git", target_dir="repo")

    assert "GIT_CLONE_RESULT: completed" in text
    assert "sandbox)" in text
    assert len(calls) == 1
    assert calls[0][0] == ["git", "clone", "--", "https://github.com/user/repo.git", "repo"]


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "http://github.com/user/repo.git",
        "https://github.com@127.0.0.1/user/repo.git",
        "https://attacker.invalid/user/repo.git",
        "https://github.com:443/user/repo.git",
        "https://github.com/user/repo.git?redirect=attacker.invalid",
    ],
)
def test_git_clone_rejects_untrusted_url_before_worker(monkeypatch, tmp_path: Path, url: str) -> None:
    def forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("invalid URL must not be sent to the worker")

    monkeypatch.setattr("tools.mcp_tools.terminal.execute.run_argv_in_sandbox", forbidden)
    text = _git_clone_tool(tmp_path, object())(repo_url=url)
    assert text.startswith("BLOCKED:")
    assert "invalid repo URL" in text
