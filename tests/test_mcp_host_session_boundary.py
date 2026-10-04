from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.sandbox.manager import NATIVE_CONSENT_ENV, NATIVE_CONSENT_VALUE


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


def _context(tmp_path: Path, *, sandbox: Any, config: dict[str, Any] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        workspace=tmp_path,
        config=config
        or {
            "sandbox": {"enabled": True, "fallback_native": False},
            "exploit": {"allowed_targets": [], "require_explicit_allowlist": False},
        },
        sandbox=sandbox,
        search=None,
        nvd=None,
        researcher=None,
        audit_tool=_identity_decorator,
        require_allowlist=lambda *args, **kwargs: _identity_decorator,
    )


def test_session_and_listener_tools_fail_closed_with_sandbox(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools import sessions

    mcp = _FakeMCP()
    ctx = _context(tmp_path, sandbox=object())
    sessions.register_session_tools(mcp, ctx=ctx)
    monkeypatch.setattr(sessions, "get_session_manager", lambda *_args: pytest.fail("host session manager used"))

    calls = {
        "start_tmux_session": ("job", "echo harmless"),
        "send_to_session": ("job", "echo harmless"),
        "read_session_output": ("job",),
        "kill_session": ("job",),
        "start_background_job": ("job", "echo harmless"),
        "read_job_output": ("job",),
        "stop_background_job": ("job",),
        "start_listener": ("listener", 4444),
        "read_listener_output": ("listener",),
        "stop_listener": ("listener",),
        "list_sessions": (),
        "list_processes": (),
        "kill_process": ("1234",),
    }
    for name, args in calls.items():
        assert "SANDBOX_UNSUPPORTED" in mcp.tools[name](*args), name


def test_missing_manager_does_not_imply_native_session_consent(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools import sessions

    monkeypatch.delenv(NATIVE_CONSENT_ENV, raising=False)
    mcp = _FakeMCP()
    config = {
        "sandbox": {"enabled": False},
        "exploit": {"allowed_targets": [], "require_explicit_allowlist": False},
    }
    sessions.register_session_tools(mcp, ctx=_context(tmp_path, sandbox=None, config=config))
    monkeypatch.setattr(sessions, "get_session_manager", lambda *_args: pytest.fail("host session manager used"))

    result = mcp.tools["start_background_job"]("job", "echo harmless")
    assert result.startswith("BLOCKED: NATIVE_EXECUTION_CONSENT")


def test_explicit_native_mode_and_consent_allow_legacy_session(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools import sessions

    monkeypatch.setenv(NATIVE_CONSENT_ENV, NATIVE_CONSENT_VALUE)
    mcp = _FakeMCP()
    config = {
        "sandbox": {"enabled": False},
        "exploit": {"allowed_targets": [], "require_explicit_allowlist": False},
    }
    sessions.register_session_tools(mcp, ctx=_context(tmp_path, sandbox=None, config=config))
    called: list[tuple[str, str]] = []

    class _Manager:
        def start_background_job(self, name, command, *, cwd):
            called.append((name, command))
            return {"success": True, "pid": 123, "log": str(tmp_path / "job.log")}

    monkeypatch.setattr(sessions, "get_session_manager", lambda *_args: _Manager())
    result = mcp.tools["start_background_job"]("job", "echo authorized")
    assert result.startswith("JOB_STARTED: job")
    assert called == [("job", "echo authorized")]


def test_operator_listener_wrappers_share_host_execution_gate(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools import operator_connection

    monkeypatch.delenv(NATIVE_CONSENT_ENV, raising=False)
    mcp = _FakeMCP()
    config = {
        "sandbox": {"enabled": True, "fallback_native": False},
        "exploit": {
            "allowed_targets": ["10.0.0.1", "10.0.0.2"],
            "require_explicit_allowlist": False,
        },
    }
    operator_connection.register_operator_connection_tools(mcp, ctx=_context(tmp_path, sandbox=object(), config=config))
    monkeypatch.setattr(
        "tools.persistent_session_manager.get_session_manager",
        lambda *_args: pytest.fail("host session manager used"),
    )

    listener = mcp.tools["rce_listener_start"](4444)
    assert "SANDBOX_UNSUPPORTED" in listener
    persistence = mcp.tools["establish_persistence"](
        "10.0.0.1",
        callback_host="10.0.0.2",
        auto_start_listener=True,
    )
    assert "SANDBOX_UNSUPPORTED" in persistence


def test_environment_probe_rejects_paths_and_runs_names_in_worker(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools.terminal import privilege
    from tools.sandbox.models import SandboxResult

    class _Sandbox:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def execute_argv(self, argv, **_kwargs):
            self.calls.append(list(argv))
            return SandboxResult(
                exit_code=0,
                stdout="AVAILABLE\tnmap\tNmap version 7.95\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.01,
                sandbox_id="test-worker",
                status="completed",
            )

    sandbox = _Sandbox()
    ctx = _context(tmp_path, sandbox=sandbox)
    mcp = _FakeMCP()
    privilege._register_privilege_tools(mcp, ctx=ctx)
    monkeypatch.setattr(privilege.subprocess, "run", lambda *_a, **_k: pytest.fail("host process started"))

    rejected = mcp.tools["check_environment"]("/tmp/workspace/payload")
    assert rejected.startswith("BLOCKED:")
    assert sandbox.calls == []
    result = mcp.tools["check_environment"]("nmap")
    assert "sandbox worker" in result
    assert "Nmap version 7.95" in result
    assert sandbox.calls and sandbox.calls[0][0:2] == ["sh", "-c"]
    monkeypatch.setattr("tools.env_probe.preflight_env_probe", lambda: pytest.fail("host preflight used"))
    assert "not relevant while contained" in mcp.tools["preflight_env_check"]()


def test_missing_worker_tool_does_not_probe_host_sudo(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools.terminal import privilege
    from tools.sandbox.models import SandboxResult

    class _Sandbox:
        def execute_argv(self, _argv, **_kwargs):
            return SandboxResult(
                exit_code=0,
                stdout="MISSING\tnmap\t\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.01,
                sandbox_id="test-worker",
                status="completed",
            )

    monkeypatch.setattr(
        "tools.env_probe._can_passwordless_sudo",
        lambda: pytest.fail("host sudo probe ran while contained"),
    )
    mcp = _FakeMCP()
    privilege._register_privilege_tools(mcp, ctx=_context(tmp_path, sandbox=_Sandbox()))

    result = mcp.tools["check_environment"]("nmap")
    assert "NOT FOUND in sandbox" in result
    assert "Host package installation is unavailable while contained" in result


def test_native_environment_probe_refuses_workspace_executable(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools.terminal import privilege

    monkeypatch.setenv(NATIVE_CONSENT_ENV, NATIVE_CONSENT_VALUE)
    monkeypatch.setattr(privilege.shutil, "which", lambda _tool: str(tmp_path / "nmap"))
    monkeypatch.setattr(privilege.subprocess, "run", lambda *_a, **_k: pytest.fail("workspace tool executed"))
    config = {
        "sandbox": {"enabled": False},
        "exploit": {"allowed_targets": [], "require_explicit_allowlist": False},
    }
    mcp = _FakeMCP()
    privilege._register_privilege_tools(mcp, ctx=_context(tmp_path, sandbox=None, config=config))

    result = mcp.tools["check_environment"]("nmap")
    assert result.startswith("BLOCKED: refusing to execute a workspace-local")


def test_package_install_tools_do_not_spawn_host_commands_in_sandbox(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools.terminal import package

    mcp = _FakeMCP()
    package._register_package_tools(mcp, ctx=_context(tmp_path, sandbox=object()))
    monkeypatch.setattr(package.subprocess, "run", lambda *_a, **_k: pytest.fail("host subprocess started"))
    monkeypatch.setattr(package, "_run_with_pgrp_timeout", lambda *_a, **_k: pytest.fail("host subprocess started"))
    monkeypatch.setattr(package.shutil, "move", lambda *_a, **_k: pytest.fail("host file install attempted"))

    results = [
        mcp.tools["apt_install"]("nmap"),
        mcp.tools["pip_install"]("requests"),
        mcp.tools["install_package"]("pip", "requests"),
        mcp.tools["download_and_install"]("https://example.invalid/tool.zip"),
        mcp.tools["update_system"](),
    ]
    assert all("SANDBOX_UNSUPPORTED" in result for result in results)


def test_host_metasploit_bridge_requires_native_mode(monkeypatch, tmp_path: Path) -> None:
    from tools.mcp_tools import metasploit

    mcp = _FakeMCP()
    metasploit.register_metasploit_tools(mcp, ctx=_context(tmp_path, sandbox=object()))
    monkeypatch.setattr(
        metasploit,
        "get_metasploit_bridge",
        lambda *_args: pytest.fail("host Metasploit bridge used"),
    )
    result = mcp.tools["msfconsole_start"]()
    assert "SANDBOX_UNSUPPORTED" in result


def test_mcp_server_aborts_if_sandbox_manager_resolution_raises(monkeypatch, tmp_path: Path) -> None:
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    def fail_resolution(*_args):
        raise RuntimeError("sandbox setup failure")

    monkeypatch.setattr("tools.sandbox.resolve_manager_with_fallback", fail_resolution)
    with pytest.raises(RuntimeError, match="refusing to expose tools"):
        create_mcp_server(
            ExploitSearch(ExploitSearchSettings()),
            NVDClient(CVESearchSettings()),
            WebResearcher(WebResearcherSettings()),
            tmp_path,
            {"exploit": {"allowed_targets": [], "require_explicit_allowlist": False}},
        )
