"""Lifecycle helpers for the owned MCP exploit-server subprocess and HTTP transport.

The implementations live here so ``tools.mcp_session`` can focus on session
coordination. The old module re-exports these helpers; calls made through this
module resolve patched names from that facade to preserve its test and caller
seams while internal references move.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

from tools.attack_ui import get_ui

MCP_HTTP_RETRY_INITIAL_SECONDS: float = 0.2
# Windows SDK values used by subprocess.Popen.send_signal. Python only exposes
# these names when running on Windows, which makes direct references fail the
# cross-platform mypy debt pass on Linux.
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_CTRL_BREAK_EVENT = 1


def _mcp_session_symbol(name: str, fallback: Any) -> Any:
    """Resolve a legacy ``mcp_session`` seam at call time when it is loaded."""
    session_module = sys.modules.get("tools.mcp_session")
    return getattr(session_module, name, fallback) if session_module is not None else fallback


def start_exploit_http_server(
    *,
    server_path: Path,
    config_path: Path,
    port: int,
    workspace: Path,
    env: dict[str, str],
    config_fingerprint: str | None = None,
    private_config_snapshot: bool = False,
) -> tuple[subprocess.Popen[str], Any]:
    if _mcp_session_symbol("port_is_open", port_is_open)("127.0.0.1", port):
        raise RuntimeError(f"Exploit MCP HTTP port {port} is already in use. Stop the process using it.")

    workspace.mkdir(parents=True, exist_ok=True)
    log_path = workspace / "mcp_exploit_server.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            # Isolate the server in its own console process group so shutdown
            # can signal it independently and taskkill can remove descendants.
            popen_kwargs["creationflags"] = _WINDOWS_CREATE_NEW_PROCESS_GROUP
        else:
            # Gives POSIX shutdown a process group to terminate, including any
            # tool subprocesses that are still alive when the session closes.
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen(
            [
                sys.executable,
                str(server_path),
                "--transport",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                *(["--private-config-snapshot"] if private_config_snapshot else []),
                "--config",
                str(config_path.resolve()),
                *(["--expected-config-sha256", config_fingerprint] if config_fingerprint is not None else []),
                "--workspace",
                str(workspace.resolve()),
            ],
            cwd=str(server_path.parent),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            **popen_kwargs,
        )
    except BaseException:
        # Bug #20: if Popen raises (e.g. bad env, OOM), the log handle we
        # just opened would leak. Close it before re-raising.
        log_handle.close()
        raise
    return process, log_handle


_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_.-]*(?:api[_-]?key|key|secret|token|password|passwd|auth)[A-Z0-9_.-]*)"
    r"(\s*[:=]\s*)([\"']?)([^\s,\"']+|[^\"']*)([\"']?)"
)
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+|bearer\s+)[^\s,;]+")
_URL_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@")


def _redact_startup_text(text: str, *, secret_values: tuple[str, ...] = ()) -> str:
    """Redact common credential forms before startup diagnostics are shown."""
    for value in sorted(set(secret_values), key=len, reverse=True):
        if len(value) >= 4:
            text = text.replace(value, "[REDACTED]")
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", text)

    def _replace_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    return _SECRET_ASSIGNMENT_RE.sub(_replace_assignment, text)


def _server_log_tail(
    log_path: Path | None,
    *,
    max_lines: int = 20,
    max_chars: int = 4000,
    secret_values: tuple[str, ...] = (),
) -> str:
    """Return a bounded server-log excerpt suitable for a startup error."""
    if log_path is None:
        return ""
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = deque(handle, maxlen=max_lines)
    except OSError as exc:
        return f"\nServer log: {log_path} (could not read: {exc})"
    excerpt = "".join(lines).rstrip("\r\n")
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
    excerpt = _mcp_session_symbol("_redact_startup_text", _redact_startup_text)(excerpt, secret_values=secret_values)
    if not excerpt:
        excerpt = "(empty)"
    return f"\nServer log: {log_path}\n--- log tail ---\n{excerpt}"


@contextlib.asynccontextmanager
async def _streamable_http_transport(
    url: str,
    *,
    token: str = "",
) -> AsyncIterator[tuple[Any, Any, Any]]:
    """Open the loopback SDK transport without routing through OS proxies."""
    import httpx
    from mcp.client.streamable_http import streamable_http_client

    headers = {"Authorization": f"Bearer {token}"} if token else None
    # read must exceed the longest tool timeout (600s msf / some terminal
    # commands) plus agent idle time between calls, or a slow tool call trips
    # the SSE/POST read timeout and kills the whole MCP session.
    timeout = httpx.Timeout(_mcp_session_symbol("MCP_BOOT_TIMEOUT_SECONDS", 30.0), read=1800.0)
    async with httpx.AsyncClient(
        follow_redirects=True,
        headers=headers,
        timeout=timeout,
        trust_env=False,
    ) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            yield streams


def _child_exit_error(
    process: subprocess.Popen[str] | None,
    *,
    endpoint: str,
    log_path: Path | None,
    secret_values: tuple[str, ...] = (),
) -> RuntimeError | None:
    if process is None:
        return None
    returncode = process.poll()
    if returncode is None:
        return None
    log_tail = _mcp_session_symbol("_server_log_tail", _server_log_tail)(log_path, secret_values=secret_values)
    return RuntimeError(f"MCP HTTP server exited with code {returncode} before becoming ready at {endpoint}.{log_tail}")


def _concise_startup_error(exc: BaseException, *, max_chars: int = 1000) -> str:
    message = _mcp_session_symbol("_redact_startup_text", _redact_startup_text)(
        str(exc).replace("\r", " ").replace("\n", " ")
    )
    rendered = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
    if len(rendered) > max_chars:
        rendered = rendered[:max_chars] + "..."
    return rendered


async def wait_for_mcp_http_ready(
    url: str,
    timeout_seconds: float,
    *,
    process: subprocess.Popen[str] | None = None,
    log_path: Path | None = None,
    secret_values: tuple[str, ...] = (),
    identity_secret: str | None = None,
    retry_initial_seconds: float = MCP_HTTP_RETRY_INITIAL_SECONDS,
) -> None:
    """Wait for the owned HTTP child to listen within one cold-start budget."""
    endpoint = urlsplit(url)
    host, port = endpoint.hostname or "", endpoint.port
    deadline = time.monotonic() + timeout_seconds
    delay = max(0.0, retry_initial_seconds)
    attempts = 0

    while True:
        child_error = _mcp_session_symbol("_child_exit_error", _child_exit_error)(
            process,
            endpoint=url,
            log_path=log_path,
            secret_values=secret_values,
        )
        if child_error is not None:
            raise child_error
        attempts += 1
        if port is not None and _mcp_session_symbol("port_is_open", port_is_open)(host, port):
            identity_timeout = max(0.05, min(1.0, deadline - time.monotonic()))
            if identity_secret is None or await _verify_mcp_http_identity(
                url, identity_secret, timeout_seconds=identity_timeout
            ):
                return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(delay, remaining))

    log_tail = _mcp_session_symbol("_server_log_tail", _server_log_tail)(log_path, secret_values=secret_values)
    raise RuntimeError(
        f"Timed out after {timeout_seconds:g}s waiting for the MCP HTTP listener identity at "
        f"{url} ({attempts} attempts).{log_tail}"
    )


async def _verify_mcp_http_identity(url: str, identity_secret: str, *, timeout_seconds: float = 1.0) -> bool:
    """Authenticate the owned child before sending it the MCP bearer token.

    A port-open check alone cannot distinguish the child from a process that
    won the local bind race. The challenge is public, but only the child and
    parent know the per-session secret used to create its proof.
    """
    import httpx

    endpoint = urlsplit(url)
    if not endpoint.scheme or not endpoint.netloc or not identity_secret:
        return False
    challenge = secrets.token_urlsafe(32).encode("ascii")
    expected = hmac.new(identity_secret.encode("utf-8"), challenge, hashlib.sha256).hexdigest()
    identity_url = f"{endpoint.scheme}://{endpoint.netloc}/.well-known/breachpilot-mcp-identity"
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(max(0.1, timeout_seconds)),
            trust_env=False,
        ) as client:
            response = await client.get(
                identity_url,
                headers={"X-BreachPilot-Challenge": challenge.decode("ascii")},
            )
    except (httpx.HTTPError, OSError, ValueError):
        return False
    proof = response.headers.get("X-BreachPilot-Proof", "")
    return response.status_code == 200 and hmac.compare_digest(proof, expected)


def stop_process(
    process: subprocess.Popen[str],
    *,
    host: str = "127.0.0.1",
    port: int | None = None,
) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            process.send_signal(_WINDOWS_CTRL_BREAK_EVENT)
            process.wait(timeout=3)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        # terminate()/kill() affect only the direct child on Windows. taskkill
        # /T is the stdlib-accessible way to remove its descendant tree too.
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            # Fall through to direct-child kill below. This cannot guarantee
            # descendant cleanup, but still prevents shutdown from hanging.
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                process.kill()
        else:
            process.kill()
        process.wait(timeout=5)

    # ponytail: on Windows, taskkill /T can miss uvicorn's descendant worker
    # threads, leaving the port bound by an orphan that the next boot's
    # port_is_open guard catches as "already in use" (the recon→attack phase
    # transition hits this). When the caller passes the port, poll until the
    # socket is actually released and retry taskkill /F /T once if it isn't.
    # This is the root-cause fix for the MCP HTTP readiness probe 30s timeout
    # that triggers the stdio fallback twice per run (~60s wasted).
    if port is not None:
        _mcp_session_symbol("_verify_port_freed", _verify_port_freed)(host, port, process.pid)


def _verify_port_freed(host: str, port: int, pid: int) -> None:
    """Poll until the port is unbound; retry taskkill once if it stays bound."""
    import time

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not _mcp_session_symbol("port_is_open", port_is_open)(host, port):
            return
        time.sleep(0.2)
    # Still bound — try one more forceful tree kill in case a descendant
    # survived the first pass. Best-effort; log but don't raise (we're in a
    # finally and must not mask the real exception).
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not _mcp_session_symbol("port_is_open", port_is_open)(host, port):
                return
            time.sleep(0.2)
    if _mcp_session_symbol("port_is_open", port_is_open)(host, port):
        # Don't raise — we're in a finally block and the real exception
        # (if any) must propagate. The next boot's start_exploit_http_server
        # will raise a clear "port already in use" with the orphan-kill path.
        _mcp_session_symbol("ui", get_ui()).warning(
            f"MCP HTTP port {host}:{port} still bound after stop_process "
            f"(pid {pid}); next boot will attempt orphan cleanup"
        )


def port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False
