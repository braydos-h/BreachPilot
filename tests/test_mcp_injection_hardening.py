"""Regression tests for the MCP exploit-tool shell-injection hardening.

These cover the fixes in ``mcp_exploit_server.py`` for the confirmed bugs:

- C1  ``run_msf_module``: module/opts/target validation + resource-file argv.
- H1  ``lateral_exec`` / ``dump_credentials`` / ``kerberoast``: argv lists.
- H2  ``generate_payload``: msfvenom options shlex-parsed + argv list.
- H3  ``git_clone``: target_dir validation + argv list.
- H4  ``run_exploit_terminal``: allowlist covers IPv6/hostname/bracketed.
- H5/M5  ``run_as_root``: target-IP allowlist lock (destructive gate removed in lab build).
- H6  ``download_and_install``: target_name validation + argv install.
- M4  ``run_python_file``: target validation + sandbox-only execution.
- M8  ``cve_to_exploit_synth``: validate_ipv4 + service_name/version reject.

Each test mocks subprocess / network (no live tools) and asserts a malicious
payload is either rejected with a ``BLOCKED`` result or passed as a literal
argv element (no shell string, no injected token executed).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

# ── Harness helpers ─────────────────────────────────────────────────────────


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = False,
    allowed_targets: list[str] | None = None,
    with_sandbox: bool = True,
):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.sandbox.models import SandboxResult
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    class FakeSandbox:
        """In-process worker double: records requests and never runs commands."""

        def __init__(self) -> None:
            self.workspace = tmp_path.resolve()
            self.cfg = SimpleNamespace(remove_stale_on_startup=False)
            self.calls: list[dict[str, Any]] = []

        def container_path(self, path: str | Path) -> str:
            resolved = Path(path).resolve()
            if resolved != self.workspace and self.workspace not in resolved.parents:
                raise ValueError("path outside fake worker workspace")
            relative = resolved.relative_to(self.workspace).as_posix()
            return "/workspace" if relative == "." else f"/workspace/{relative}"

        def _enforce_scope(self, target: str) -> None:
            self.calls.append({"kind": "scope", "target": target})

        def execute_argv(self, argv: list[str], **kwargs: Any) -> SandboxResult:
            self.calls.append({"kind": "argv", "argv": list(argv), **kwargs})
            return SandboxResult(
                exit_code=0,
                stdout="ok\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.1,
                sandbox_id="test-worker",
                status="completed",
            )

        def execute(self, command: str, **kwargs: Any) -> SandboxResult:
            self.calls.append({"kind": "command", "command": command, **kwargs})
            return SandboxResult(
                exit_code=0,
                stdout="ok\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.1,
                sandbox_id="test-worker",
                status="completed",
            )

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets or [],
        }
    }
    sandbox = FakeSandbox()
    selected_sandbox = sandbox if with_sandbox else None
    with patch("tools.sandbox.resolve_manager_with_fallback", return_value=(selected_sandbox, "")):
        server = create_mcp_server(search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config)
    server._test_sandbox = selected_sandbox
    return server


def _text(result) -> str:
    """Extract concatenated text from a FastMCP call_tool result."""
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


# ── C1: run_msf_module ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_msf_module_rejects_shell_metachar_module(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_msf_module",
            {"module": "exploit/foo; rm -rf /", "target_ip": "10.0.0.1"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "module path must match" in text


@pytest.mark.asyncio
async def test_run_msf_module_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_msf_module",
            {"module": "exploit/multi/http/log4shell", "target_ip": "10.0.0.1; whoami"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "valid IP address or domain" in text


@pytest.mark.asyncio
async def test_run_msf_module_rejects_opts_without_equals(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_msf_module",
            {"module": "exploit/multi/http/x", "target_ip": "10.0.0.1", "options": "RHOSTS"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "key=value" in text


@pytest.mark.asyncio
async def test_run_msf_module_rejects_metachar_option_value(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_msf_module",
            {"module": "exploit/multi/http/x", "target_ip": "10.0.0.1", "options": "RHOSTS=10.0.0.1;id"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "forbidden shell metacharacters" in text


@pytest.mark.asyncio
async def test_run_msf_module_uses_argv_list_no_shell(monkeypatch, tmp_path: Path) -> None:
    """Valid call invokes msfconsole as an argv list (no bash -c)."""
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_msf_module",
            {
                "module": "exploit/multi/http/log4shell_header_injection",
                "target_ip": "10.0.0.1",
                "options": "RHOSTS=10.0.0.1 LPORT=443",
            },
        )
    )
    assert "MSF_RESULT:" in text
    # The worker receives argv and never an MCP-host process request.
    calls = [call for call in mcp._test_sandbox.calls if call["kind"] == "argv"]
    assert calls
    argv = calls[0]["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "msfconsole"
    assert "-r" in argv
    assert not any("bash" in str(a) for a in argv)
    # No argv element may contain a shell-injected semicolon.
    assert not any(";" in str(a) for a in argv if a not in ("exit -y",))


@pytest.mark.asyncio
async def test_establish_persistence_refuses_symlinked_attempt_directory(monkeypatch, tmp_path: Path) -> None:
    """A worker-created attempt symlink cannot redirect the host implant write."""
    mcp = _make_server(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    attempt_id = "worker-controlled-attempt"
    (tmp_path / attempt_id).symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        "tools.mcp_tools.operator_connection._attempt_dir",
        lambda workspace: (workspace / attempt_id, attempt_id),
    )

    text = _text(
        await mcp.call_tool(
            "establish_persistence",
            {
                "target_ip": "10.0.0.1",
                "method": "linux_cron",
                "callback_host": "10.0.0.2",
                "auto_start_listener": False,
            },
        )
    )

    assert text.startswith("BLOCKED: implant script could not be written safely")
    assert not list(outside.glob("implant_*.py"))


# ── H1: lateral_exec / dump_credentials / kerberoast ───────────────────────


@pytest.mark.asyncio
async def test_lateral_exec_uses_argv_list_password_literal(monkeypatch, tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "lateral_exec",
            {
                "target_ip": "10.0.0.1",
                "method": "psexec",
                "username": "admin",
                "password": "p'; rm -rf /; echo",
                "command": "whoami",
            },
        )
    )
    assert "LATERAL_EXEC_RESULT:" in text
    argv = next(call["argv"] for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    assert isinstance(argv, list)
    assert argv[0] == "impacket-psexec"
    # The malicious password must be a single literal argv element, not split
    # by a shell into separate tokens.
    assert "p'; rm -rf /; echo" in argv
    assert not any(v == "-c" and i + 1 < len(argv) and "bash" in argv[i - 1] for i, v in enumerate(argv))


@pytest.mark.asyncio
async def test_lateral_exec_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "lateral_exec",
            {"target_ip": "10.0.0.1$(id)", "method": "psexec", "username": "a", "password": "p"},
        )
    )
    assert text.startswith("BLOCKED:") or "Invalid target (IP or domain)" in text


@pytest.mark.asyncio
async def test_dump_credentials_secretsdump_argv_list(monkeypatch, tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "dump_credentials",
            {"target_ip": "10.0.0.1", "method": "secretsdump", "username": "admin", "password": "secret'$(id)"},
        )
    )
    assert "CRED_DUMP_RESULT:" in text
    argv = next(call["argv"] for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    assert argv[0] == "impacket-secretsdump"
    # The whole 'domain/user:password@ip' target is one literal argv element.
    assert any("secret'$(id)" in a for a in argv)
    assert not any(a == "-c" for a in argv)


@pytest.mark.asyncio
async def test_kerberoast_argv_list(monkeypatch, tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "kerberoast",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "svc", "password": "p`whoami`"},
        )
    )
    assert "KERBEROAST_RESULT:" in text
    argv = next(call["argv"] for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    assert argv[0] == "impacket-GetUserSPNs.py"
    assert any("p`whoami`" in a for a in argv)
    assert not any(a == "-c" for a in argv)


# ── H2: generate_payload ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_payload_rejects_metachar_options(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "generate_payload",
            {
                "payload_type": "reverse_tcp",
                "lhost": "10.0.0.1",
                "lport": 4444,
                "format": "raw",
                "platform": "linux",
                "arch": "x64",
                "options": "CMD='net user; rm -rf /'",
            },
        )
    )
    assert text.startswith("BLOCKED:")
    assert "forbidden shell metacharacters" in text


@pytest.mark.asyncio
async def test_generate_payload_uses_argv_list(monkeypatch, tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "generate_payload",
            {
                "payload_type": "reverse_tcp",
                "lhost": "10.0.0.1",
                "lport": 4444,
                "format": "raw",
                "platform": "linux",
                "arch": "x64",
                "options": "CMD='net user x'",
            },
        )
    )
    assert "PAYLOAD_RESULT:" in text
    argv = next(call["argv"] for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    assert argv[0] == "msfvenom"
    assert "-p" in argv
    # The shlex-parsed option must be a single literal argv element.
    assert any("net user x" in a for a in argv)
    assert not any(a == "-c" for a in argv)


# ── H3: git_clone ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_git_clone_rejects_traversal_target_dir(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "git_clone",
            {"repo_url": "https://github.com/user/repo.git", "target_dir": "../evil"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "target_dir must match" in text


@pytest.mark.asyncio
async def test_git_clone_uses_argv_list(monkeypatch, tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "git_clone",
            {"repo_url": "https://github.com/user/repo.git", "target_dir": "repo"},
        )
    )
    assert "GIT_CLONE_RESULT:" in text
    argv = next(call["argv"] for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    assert argv[:3] == ["git", "clone", "--"]
    # URL and dir are literal argv elements (no shell concatenation).
    assert "https://github.com/user/repo.git" in argv
    assert not any(a == "-c" for a in argv)


# ── H4: run_exploit_terminal allowlist covers IPv6/hostname ─────────────────


@pytest.mark.asyncio
async def test_run_exploit_terminal_blocks_ipv6_not_in_allowlist(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "curl http://[::1]"}))
    assert "TERMINAL_RESULT: blocked" in text
    assert "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_run_exploit_terminal_blocks_hostname_not_in_allowlist(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -sV evil.example.com"}))
    assert "TERMINAL_RESULT: blocked" in text
    assert "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_run_exploit_terminal_allows_allowlisted_target(tmp_path: Path) -> None:
    """A target in the allowlist is not blocked by the egress gate."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -sV 10.0.0.5"}))
    # Not blocked by the allowlist (it may still fail on subprocess, but it must
    # not be a preflight allowlist block).
    assert "not in the explicit allowlist" not in text
    assert "Missing tools on PATH" not in text  # command runs in worker, not MCP host


@pytest.mark.asyncio
async def test_terminal_does_not_follow_worker_log_symlink(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    outside = tmp_path / "operator-data.txt"
    outside.write_text("keep", encoding="utf-8")
    import tools.mcp_tools.terminal.execute as terminal_execute

    run_in_sandbox = terminal_execute.run_command_in_sandbox

    def create_worker_symlink(ctx: Any, command: str, **kwargs: Any):
        attempt_dir = kwargs["cwd_host"]
        (attempt_dir / "terminal.log").symlink_to(outside)
        return run_in_sandbox(ctx, command, **kwargs)

    monkeypatch.setattr(terminal_execute, "run_command_in_sandbox", create_worker_symlink)
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "echo harmless"}))

    assert "TERMINAL_RESULT: completed" in text
    assert outside.read_text(encoding="utf-8") == "keep"


# ── H5/M5: run_as_root ──────────────────────────────────────────────────────
# LAB BUILD: the destructive/python -c/find -delete gates were removed -- the
# AI may do whatever it takes as root. The one safety kept is the target-IP
# lock (enforced at the tool layer via the allowlist when
# require_explicit_allowlist is true).


@pytest.mark.asyncio
async def test_run_as_root_allows_destructive_in_lab(monkeypatch, tmp_path: Path) -> None:
    """LAB BUILD: a destructive command is NOT refused -- it runs (mocked here)
    because the destructive gate was removed. Only the target-IP lock remains,
    and it is off here (require_explicit_allowlist=False)."""
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("run_as_root", {"command": "rm -rf /tmp"}))
    assert text.startswith("ROOT_CMD_RESULT: completed")
    call = next(call for call in mcp._test_sandbox.calls if call["kind"] == "command")
    assert call["command"] == "rm -rf /tmp"
    assert call["user"] == "root"


@pytest.mark.asyncio
async def test_run_as_root_blocks_non_target_ip(tmp_path: Path) -> None:
    """LAB BUILD target lock: with require_explicit_allowlist=True and an
    allowlist of [10.0.0.5], a command targeting a different IP (10.0.0.99) is
    refused by the tool-layer allowlist. No pivot to other hosts."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_as_root", {"command": "nmap 10.0.0.99"}))
    assert "ROOT_CMD_RESULT: blocked" in text
    assert "not in the explicit allowlist" in text or "target lock" in text.lower()


@pytest.mark.asyncio
async def test_kerberoast_blocks_non_target_dc_ip(tmp_path: Path) -> None:
    """LAB BUILD target lock: kerberoast's dc_ip is an impacket -dc-ip egress
    target. @require_allowlist only covers target_ip, so an explicit dc_ip that
    is not the runtime target must be gated through the allowlist -- otherwise
    kerberoast pivots to an off-target DC. The block fires before any impacket
    run, so no subprocess mock is needed."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(
        await mcp.call_tool(
            "kerberoast",
            {
                "target_ip": "10.0.0.5",
                "domain": "lab",
                "password": "p",
                "dc_ip": "10.0.0.99",
            },
        )
    )
    assert text.startswith("BLOCKED:")
    assert "not in the explicit allowlist" in text
    assert "DC_IP: 10.0.0.99" in text


@pytest.mark.asyncio
async def test_run_python_file_blocks_off_target_script_body(tmp_path: Path) -> None:
    """LAB BUILD target lock: run_python_file executes the script body verbatim,
    so a literal-IP pivot written into the script (reverse shell / nc to another
    host) must be caught by the same _target_lock_block the terminal uses --
    otherwise run_python_file is a trivial bypass of the no-pivoting lock.
    The block fires before the script runs, so no subprocess mock is needed."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    written = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "pivot.py", "code": 'import os\nos.system("nc 10.0.0.99 4444")'},
        )
    )
    assert "PYTHON_FILE_WRITTEN" in written
    text = _text(await mcp.call_tool("run_python_file", {"target_ip": "10.0.0.5", "filename": "pivot.py"}))
    assert text.startswith("BLOCKED:")
    assert "not in the explicit allowlist" in text
    assert "run_python_file" in text


@pytest.mark.asyncio
async def test_run_python_file_passes_target_both_positional_and_flag(monkeypatch, tmp_path: Path) -> None:
    """run_python_file passes the target IP as BOTH a bare positional (sys.argv[1])
    AND --target <ip>, so a script reading sys.argv[1] (the attack-module template
    / orchestrator convention) and a script using argparse --target both receive
    the IP. Regression guard for the log bug where sys.argv[1] was the literal
    string "--target" and the script connected to "--target:445"."""
    mcp = _make_server(tmp_path)

    written = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "argcheck.py", "code": "import sys\nprint(sys.argv[1:])\n"},
        )
    )
    assert "PYTHON_FILE_WRITTEN" in written
    text = _text(await mcp.call_tool("run_python_file", {"target_ip": "10.0.0.5", "filename": "argcheck.py"}))
    assert "PYTHON_RUN_RESULT" in text

    call = next(call for call in mcp._test_sandbox.calls if call["kind"] == "argv")
    argv = call["argv"]
    assert "10.0.0.5" in argv
    assert "--target" in argv
    assert argv.index("10.0.0.5") < argv.index("--target")


@pytest.mark.asyncio
async def test_msfconsole_command_blocks_portfwd_to_non_target(tmp_path: Path) -> None:
    """LAB BUILD target lock: a meterpreter ``portfwd add -r <other_ip>`` pivot
    names a remote host via -r, not RHOSTS/RHOST. The msf free-text command gate
    must extract the portfwd -r host (and route/autoroute subnets) and refuse any
    host not in the allowlist -- an existing-session pivot to another host. The
    block fires before the msf bridge is touched, so no bridge mock is needed."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.5"])
    text = _text(
        await mcp.call_tool(
            "msfconsole_command",
            {"command": "portfwd add -l 8080 -p 80 -r 10.0.0.99"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "not in the explicit allowlist" in text
    assert "msfconsole_command" in text


@pytest.mark.asyncio
async def test_run_as_root_uses_argv_no_shell(monkeypatch, tmp_path: Path) -> None:
    """A non-destructive command runs via _run_with_pgrp_timeout (no bash -c of
    a raw concatenation that could be injected). The sudo command still uses
    bash -c but the input is the original command (operator-controlled), not a
    string built from untrusted args."""
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("run_as_root", {"command": "whoami"}))
    assert "ROOT_CMD_RESULT:" in text
    call = next(call for call in mcp._test_sandbox.calls if call["kind"] == "command")
    assert call["command"] == "whoami"
    assert call["user"] == "root"


# ── H6: host package-install tools ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_package_install_tools_never_execute_on_mcp_host(monkeypatch, tmp_path: Path) -> None:
    """Legacy package tool names must not inherit host privileges or secrets."""
    import subprocess

    mcp = _make_server(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("agent package tools must not spawn a host command")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr("tools.mcp_tools.registry._run_with_pgrp_timeout", forbidden)
    calls = [
        ("apt_install", {"packages": "nmap"}),
        ("pip_install", {"packages": "requests"}),
        ("install_package", {"manager": "apt", "packages": "nmap"}),
        ("download_and_install", {"url": "http://127.0.0.1/host-tool.deb"}),
        ("update_system", {"upgrade": True}),
    ]
    for name, arguments in calls:
        text = _text(await mcp.call_tool(name, arguments))
        assert text.startswith("BLOCKED:")
        assert "MCP host process" in text


# ── M4: run_python_file ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_python_file_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_python_file",
            {"target_ip": "10.0.0.1; rm -rf /", "filename": "x.py"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "valid IP address or domain" in text


@pytest.mark.asyncio
async def test_run_python_file_without_worker_fails_closed(tmp_path: Path) -> None:
    """Python exploit scripts are never executed by the MCP host."""
    mcp = _make_server(tmp_path, with_sandbox=False)
    text = _text(await mcp.call_tool("run_python_file", {"target_ip": "10.0.0.1", "filename": "x.py"}))

    assert text.startswith("PYTHON_RUN_RESULT: blocked")
    assert "active sandbox" in text
    assert "host execution is disabled" in text


# ── M8: cve_to_exploit_synth ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cve_to_exploit_synth_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.1`id`", "cve_id": "CVE-2021-44228"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "valid IP address or domain" in text


@pytest.mark.asyncio
async def test_cve_to_exploit_synth_rejects_newline_in_version(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.1", "cve_id": "CVE-2021-44228", "service_name": "http", "version": "1.0\n# injected"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "forbidden characters" in text


@pytest.mark.asyncio
async def test_cve_to_exploit_synth_rejects_quote_in_service_name(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.1", "cve_id": "CVE-2021-44228", "service_name": "http'; rm -rf /", "version": ""},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "forbidden characters" in text


@pytest.mark.asyncio
async def test_cve_to_exploit_synth_valid_run(tmp_path: Path, monkeypatch) -> None:
    """A clean valid call still produces the synth result (no false blocks)."""
    mcp = _make_server(tmp_path)
    # Mock nvd.search_sync and search.search_web_exploit to avoid network.
    search_obj = mcp  # FastMCP exposes the tool funcs via call_tool only
    # Patch the NVDClient and ExploitSearch instances via the module closure is
    # hard; instead patch the class methods used.
    from tools.cve_lookup import NVDClient
    from tools.exploit_search import ExploitSearch

    monkeypatch.setattr(NVDClient, "search_sync", lambda self, q: [])
    monkeypatch.setattr(ExploitSearch, "search_web_exploit", lambda self, q: "no results")
    text = _text(
        await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.1", "cve_id": "CVE-2021-44228", "service_name": "http", "version": "2.14.1"},
        )
    )
    assert "CVE_TO_EXPLOIT_SYNTH:" in text
    assert "CVE-2021-44228" in text


# ── Matrix: allowlist matcher regression (is_target_in_allowlist) ─────────────


def test_allowlist_cidr_allows_in_range() -> None:
    """CIDR 10.0.0.0/24 must allow 10.0.0.5 but not 10.0.1.1 (boundary)."""
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("10.0.0.5", ["10.0.0.0/24"]) is True
    assert is_target_in_allowlist("10.0.0.254", ["10.0.0.0/24"]) is True


def test_allowlist_cidr_blocks_out_of_range() -> None:
    """CIDR 10.0.0.0/24 should block 10.0.1.1 (outside /24)."""
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("10.0.1.1", ["10.0.0.0/24"]) is False
    assert is_target_in_allowlist("10.0.1.1", ["10.0.0.0/24", "192.168.1.0/24"]) is False


def test_allowlist_cidr_strict_false_network() -> None:
    """CIDR via ip_network(strict=False) — 10.0.0.1/24 normalizes to 10.0.0.0/24."""
    from tools.validation_utils import is_target_in_allowlist

    # 10.0.0.1/24 as an allowlist entry (operator typo) should still behave as /24
    assert is_target_in_allowlist("10.0.0.5", ["10.0.0.1/24"]) is True
    assert is_target_in_allowlist("10.0.1.1", ["10.0.0.1/24"]) is False


def test_allowlist_wildcard_allows_subdomain() -> None:
    """*.evil.com must match sub.evil.com and deep.sub.evil.com (dot-boundary)."""
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("sub.evil.com", ["*.evil.com"]) is True
    assert is_target_in_allowlist("deep.sub.evil.com", ["*.evil.com"]) is True
    assert is_target_in_allowlist("a.b.evil.com", ["*.evil.com"]) is True


def test_allowlist_wildcard_blocks_suffix_collision() -> None:
    """*.evil.com must NOT match notevil.com (suffix collision without dot)."""
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("notevil.com", ["*.evil.com"]) is False
    assert is_target_in_allowlist("badnot_evil.com", ["*.evil.com"]) is False
    assert is_target_in_allowlist("evil.com", ["*.evil.com"]) is False  # apex not matched by wildcard


def test_allowlist_domain_lower_casing() -> None:
    """Domain matching must be case-insensitive (lower-casing)."""
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("SUB.EVIL.COM", ["*.evil.com"]) is True
    assert is_target_in_allowlist("Sub.Evil.Com", ["*.EVIL.COM"]) is True
    assert is_target_in_allowlist("NOTEvil.COM", ["*.evil.com"]) is False


@pytest.mark.asyncio
async def test_terminal_blocks_cidr_outside_allowlist(tmp_path: Path) -> None:
    """Terminal lock: nmap to 10.0.1.1 must be blocked when allowlist is 10.0.0.0/24."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.0/24"])
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -sV 10.0.1.1"}))
    assert "TERMINAL_RESULT: blocked" in text or "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_discovered_target_allowlist_checked(tmp_path: Path, monkeypatch) -> None:
    """Discovered target expansion must be allowlist-checked.

    With base allowlist example.com, adding sub.example.com succeeds but
    badexample.com / evil.com are denied (subdomain boundary via is_subdomain_of).
    """
    import os

    # Isolate env for this test
    for k in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.kernel.allowlist import _allowed_target_list, add_discovered_target

    # Valid subdomain should be added
    add_discovered_target("sub.example.com", "1.2.3.4")
    assert "sub.example.com" in _allowed_target_list({"exploit": {"allowed_targets": ["example.com"]}})
    # Invalid suffix collision must be denied (not added)
    add_discovered_target("badexample.com")
    assert "badexample.com" not in os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "")
    # Unrelated domain must be denied
    add_discovered_target("evil.com")
    assert "evil.com" not in os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "")
    # Terminal with valid discovered subdomain should not be blocked (after valid add)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])
    # Re-add via the same env (simulating that discovered env is part of union)
    monkeypatch.setenv("EXPLOIT_DISCOVERED_TARGETS", os.environ.get("EXPLOIT_DISCOVERED_TARGETS", ""))
    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "curl http://sub.example.com"}))
    assert "not in the explicit allowlist" not in text
    # But a non-subdomain evil host must still be blocked even after failed add
    text2 = _text(await mcp.call_tool("run_exploit_terminal", {"command": "curl http://evil.com"}))
    assert "TERMINAL_RESULT: blocked" in text2 or "not in the explicit allowlist" in text2
