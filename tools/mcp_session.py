"""MCP exploit server session helpers."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, AsyncIterator

from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions

ui = get_ui()

# Maximum time to wait for the MCP exploit server subprocess to finish booting
# (stdio transport) before bailing out with a soft-fail ``[WARN]`` line. The
# server imports ``tools.exploit_search``, ``tools.cve_lookup``,
# ``tools.web_researcher``, ``tools.recon_pipeline``, ``tools.attack_planner``,
# ``tools.attack_modules``, ``tools.payload_crafter``, ``tools.metasploit_bridge``
# plus the MCP SDK and FastMCP, which on a cold start can take 5–15 seconds.
# 30 seconds is generous: any healthy boot completes in < 15 s on developer
# hardware, and a hung subprocess is exactly what we want to detect here.
MCP_BOOT_TIMEOUT_SECONDS: float = 30.0


class _RunHeartbeat:
    """Lightweight mutable holder the exploit loop updates each round so the
    sibling ``_elapsed_ticker`` task can report WHAT is happening, not just
    that something is still running.

    Both the loop and the ticker run as tasks on the SAME event loop, so the
    holder needs no lock — the ticker only reads between its own
    ``await asyncio.sleep`` yields, and the loop only writes between its own
    awaits. Cooperative scheduling serializes the access.
    """

    __slots__ = ("round", "action", "phase")

    def __init__(self) -> None:
        self.round = 0
        self.action = 0
        self.phase = "starting"

    def update(self, *, round: int = 0, action: int = 0, phase: str = "") -> None:
        self.round = round
        self.action = action
        self.phase = phase


async def _elapsed_ticker(
    label: str,
    *,
    interval: float = 15.0,
    heartbeat: "_RunHeartbeat | None" = None,
) -> None:
    """Print elapsed-time info lines every `interval` seconds.

    Run as a sibling task alongside a long blocking call (e.g. run_exploit_agent)
    so the user can tell the difference between "stuck" and "just slow".
    When a ``heartbeat`` holder is supplied, each line also shows the current
    round / action count / phase, so a 30-minute run says "round 8, 23 actions,
    service_enumeration" instead of a bare "still running".
    """
    start = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        m, s = divmod(int(time.monotonic() - start), 60)
        if heartbeat is not None:
            ui.info(
                f"{label} still running… {m}:{s:02d} elapsed "
                f"(round {heartbeat.round}, {heartbeat.action} actions, {heartbeat.phase})"
            )
        else:
            ui.info(f"{label} still running… {m}:{s:02d} elapsed")


# ---------------------------------------------------------------------------
# MCP Exploit Session
# ---------------------------------------------------------------------------

def _filter_env_for_log(env: dict[str, str]) -> dict[str, str]:
    """Return env dict with secrets masked for safe logging."""
    safe: dict[str, str] = {}
    for k, v in env.items():
        lower = k.lower()
        if any(s in lower for s in ("key", "secret", "token", "password", "passwd", "api", "auth")):
            safe[k] = "***"
        else:
            safe[k] = v
    return safe


@contextlib.asynccontextmanager
async def open_exploit_mcp_session(
    *,
    transport: str,
    config_path: Path,
    target_ip: str,
    exploit_port: int,
    workspace: Path,
    multi_model_enabled: bool | None = None,
    active_model_alias: str = "",
    soft_fail: bool = False,
) -> AsyncIterator[Any]:
    """Open an MCP client session against the exploit server.

    ``soft_fail`` (default ``False``): when True, any error during boot OR
    inside the caller's ``async with`` body is swallowed and the context
    manager yields ``None`` (a sentinel) instead of propagating. This is
    intended for the recon-first path, which is allowed to proceed with a
    minimal ``UNKNOWN`` assessment when the MCP server is unavailable; the
    post-recon attack path keeps the default ``False`` so a session death
    there is treated as a fatal error. The "Booting MCP server" /
    "Initializing MCP session" spinners are also passed ``soft_fail=True``
    when this flag is set, so their exit line reads ``[WARN]`` rather than
    the alarming ``[ERROR]`` that would otherwise suggest the whole
    session is about to abort.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        if soft_fail:
            # The recon-first path explicitly tolerates MCP being unavailable;
            # surface a single WARN line and yield None so the caller can
            # degrade. We do NOT yield when the import itself failed (a real
            # environment problem) because there is no point continuing.
            ui.warning("MCP Python SDK is not installed; recon skipped.")
            yield None
            return
        raise RuntimeError(
            "The MCP Python SDK is not installed. Run: python -m pip install -r requirements.txt"
        ) from exc

    # ``mcp_exploit_server.py`` lives at the repo root, one level above this
    # module (``tools/``). ``with_name`` would resolve to ``tools/`` and miss
    # it, so walk up to the parent directory.
    server_path = Path(__file__).parent.parent / "mcp_exploit_server.py"
    server_path = server_path.resolve()
    env = os.environ.copy()
    env["EXPLOIT_TARGET"] = target_ip
    env["EXPLOIT_WORKSPACE"] = str(workspace.resolve())
    if multi_model_enabled is not None:
        env["AI_NMAP_MULTI_MODEL_ENABLED"] = "1" if multi_model_enabled else "0"
    if active_model_alias:
        env["AI_NMAP_ACTIVE_MODEL_ALIAS"] = active_model_alias

    # Bug #21: a soft-failed boot used to print a green ``[SUCCESS]`` tail
    # because the soft-fail path catches the error and returns cleanly out
    # of the spinner. This mutable flag lets the soft-fail returns signal
    # the spinner to print ``[WARN]`` instead. Shared across the stdio and
    # HTTP boot blocks below.
    boot_failed = [False]

    # Persistent boot checklist. Each step prints a [BOOT] "starting" line that
    # appends to the log (stdout) and is never overwritten by the spinner
    # (which animates on stderr), then a [OK]/[FAILED] line when the step
    # resolves. The spinner remains as transient decoration; these lines are
    # what a log scraper greps. See AttackUi.boot_step / boot_section.
    ui.boot_section("MCP exploit session boot sequence")

    if transport == "stdio":
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[
                str(server_path),
                "--transport", "stdio",
                "--config", str(config_path.resolve()),
                "--workspace", str(workspace.resolve()),
            ],
            env=env,
        )

        _stdio_label = "Booting MCP server (stdio)"
        ui.boot_step(_stdio_label, ok=False)
        with ui.spinner(
            f"Booting MCP server (stdio)...",
            soft_fail=soft_fail,
            # Show elapsed seconds on the boot spinner. The MCP server
            # imports several heavy modules (see ``MCP_BOOT_TIMEOUT_SECONDS``
            # docstring) which can take 5–15 s on a cold start. Without
            # this heartbeat the user sees a static label that looks
            # frozen; with it, the seconds counter makes progress visible
            # and the perceived "stuck in a loop" goes away.
            heartbeat_seconds=1.0,
            format_message=lambda t: f"Booting MCP server (stdio)... {t:.1f}s",
            soft_fail_flag=boot_failed,
        ):
            try:
                async with stdio_client(server_params) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        # Cap boot at ``MCP_BOOT_TIMEOUT_SECONDS``. A hung
                        # ``initialize()`` would otherwise leave the
                        # spinner looping forever with no recourse other
                        # than Ctrl-C. ``asyncio.shield`` is not needed
                        # here — the timeout cancels the wait, the
                        # ``ClientSession`` context manager still gets
                        # cleaned up on the way out via the surrounding
                        # ``async with`` blocks (anyio's task group will
                        # tear down the subprocess on cancellation).
                        try:
                            await asyncio.wait_for(
                                session.initialize(),
                                timeout=MCP_BOOT_TIMEOUT_SECONDS,
                            )
                            ui.boot_step(_stdio_label, ok=True)
                        except asyncio.TimeoutError:
                            if soft_fail:
                                ui.warning(
                                    f"MCP server boot timed out after "
                                    f"{MCP_BOOT_TIMEOUT_SECONDS:.0f}s — "
                                    f"subprocess did not finish initializing."
                                )
                                boot_failed[0] = True
                                ui.boot_step(_stdio_label, failed=True)
                                yield None
                                return
                            raise RuntimeError(
                                f"MCP server boot timed out after "
                                f"{MCP_BOOT_TIMEOUT_SECONDS:.0f}s"
                            )
                        # The boot spinner's ``with`` block encloses ``yield session``
                        # below, so without this the redraw thread would keep printing
                        # ``[STATUS] Booting MCP server (stdio)... X.Xs`` for the
                        # ENTIRE session. The server has finished booting now — stop
                        # the heartbeat. The ``with`` block's own exit tail line (the
                        # static ``[SUCCESS]`` message) still fires on exit; this only
                        # stops the recurring elapsed-seconds redraw. See
                        # ``AttackUi.release_active_spinner``.
                        ui.release_active_spinner()
                        try:
                            yield session
                        except _EXC_GROUP_CATCH as exc:
                            if soft_fail:
                                ui.warning(f"MCP session closed mid-recon: {exc}")
                                if _is_exception_group(exc):
                                    _log_nested_exceptions(exc)
                                boot_failed[0] = True
                                return
                            raise RuntimeError(f"MCP session closed due to error: {exc}") from exc
            except _EXC_GROUP_CATCH as exc:
                # Log the exact error before re-raising so the user always sees it.
                # anyio's task groups (used by ``stdio_client``) raise
                # ``BaseExceptionGroup`` on subprocess failure — that is *not* an
                # ``Exception`` subclass, so we MUST catch the group explicitly.
                if soft_fail:
                    ui.warning(f"MCP stdio session failed: {exc}")
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)
                    # Fall out of the ``with ui.spinner(...)`` and the function
                    # to give the caller a ``None`` session.
                    boot_failed[0] = True
                    ui.boot_step(_stdio_label, failed=True)
                    yield None
                    return
                ui.error(f"MCP stdio session failed: {exc}")
                if _is_exception_group(exc):
                    ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
                    _log_nested_exceptions(exc)
                raise
        return

    _http_start_label = f"Starting MCP HTTP server on port {exploit_port}"
    ui.boot_step(_http_start_label, ok=False)
    with ui.spinner(
        f"Starting MCP HTTP server on port {exploit_port}...",
        soft_fail=soft_fail,
        soft_fail_flag=boot_failed,
    ):
        try:
            process, log_handle = start_exploit_http_server(
                server_path=server_path,
                config_path=config_path,
                port=exploit_port,
                workspace=workspace,
                env=env,
            )
        except (OSError, RuntimeError) as exc:
            # The HTTP server failed to start — ``port_is_open`` raised
            # ``RuntimeError`` (port already in use, e.g. an orphaned server
            # from a previous run) or ``Popen`` raised ``OSError`` (bad env,
            # ENOEXEC, OOM). The spinner's own ``except BaseException``
            # branch prints a tail line and re-raises, so without this guard
            # the exception propagates out of the async generator BEFORE any
            # ``yield`` — the caller's ``async with`` sees it directly and
            # the recon-first path crashes instead of degrading to a ``None``
            # session (M19: an asynccontextmanager must yield before
            # returning). Mirror the stdio soft-fail contract.
            if soft_fail:
                ui.warning(f"MCP HTTP server failed to start on port {exploit_port}: {exc}")
                boot_failed[0] = True
                ui.boot_step(_http_start_label, failed=True)
                yield None
                return
            ui.error(f"MCP HTTP server failed to start on port {exploit_port}: {exc}")
            raise
    ui.boot_step(_http_start_label, ok=not boot_failed[0], failed=boot_failed[0])
    try:
        _http_port_label = f"Waiting for MCP HTTP port {exploit_port}"
        ui.boot_step(_http_port_label, ok=False)
        try:
            with ui.spinner(
                f"Waiting for MCP HTTP port {exploit_port}...",
                soft_fail=soft_fail,
                soft_fail_flag=boot_failed,
            ):
                # Use the same cold-start budget as stdio. Both transports
                # construct the identical (and import-heavy) exploit server;
                # limiting HTTP to 15 seconds made healthy cold boots fail
                # while stdio was allowed the full 30 seconds. Pass the child
                # and its log so an early subprocess crash is reported
                # immediately with the real cause instead of masquerading as
                # a generic port timeout.
                await wait_for_port(
                    "127.0.0.1",
                    exploit_port,
                    timeout_seconds=MCP_BOOT_TIMEOUT_SECONDS,
                    process=process,
                    log_path=Path(log_handle.name),
                )
            ui.boot_step(_http_port_label, ok=True)
        except (OSError, asyncio.TimeoutError, RuntimeError) as exc:
            if soft_fail:
                ui.warning(f"MCP HTTP server did not start on port {exploit_port}: {exc}")
                # M19: an asynccontextmanager MUST yield before returning. The
                # stdio soft-fail branches (281/307) already yield None; the HTTP
                # branches here and below used to ``return`` without yielding,
                # which raised ``RuntimeError: async generator didn't yield``
                # instead of degrading to a None session for the recon-first
                # path. Mirror the stdio behaviour.
                boot_failed[0] = True
                ui.boot_step(_http_port_label, failed=True)
                yield None
                return
            raise
        from mcp.client.streamable_http import streamable_http_client

        async with streamable_http_client(f"http://127.0.0.1:{exploit_port}/mcp") as (
            read_stream,
            write_stream,
            _,
        ):
            _http_init_label = "Initializing MCP session"
            ui.boot_step(_http_init_label, ok=False)
            with ui.spinner(
                "Initializing MCP session...",
                soft_fail=soft_fail,
                heartbeat_seconds=1.0,
                format_message=lambda t: f"Initializing MCP session... {t:.1f}s",
                soft_fail_flag=boot_failed,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    # Cap HTTP ``initialize()`` the same way as the stdio
                    # branch — see the matching comment above for the
                    # rationale. The HTTP path is usually faster (the
                    # server process is already up and listening) but a
                    # network glitch or stalled handshake can still hang
                    # the spinner without a timeout.
                    try:
                        await asyncio.wait_for(
                            session.initialize(),
                            timeout=MCP_BOOT_TIMEOUT_SECONDS,
                        )
                        ui.boot_step(_http_init_label, ok=True)
                    except asyncio.TimeoutError:
                        if soft_fail:
                            ui.warning(
                                f"MCP HTTP session init timed out after "
                                f"{MCP_BOOT_TIMEOUT_SECONDS:.0f}s."
                            )
                            # M19: yield before returning (see the matching
                            # comment on the HTTP-start soft-fail branch above).
                            boot_failed[0] = True
                            ui.boot_step(_http_init_label, failed=True)
                            yield None
                            return
                        raise RuntimeError(
                            f"MCP HTTP session init timed out after "
                            f"{MCP_BOOT_TIMEOUT_SECONDS:.0f}s"
                        )
                    except _EXC_GROUP_CATCH as exc:
                        # The server died mid-handshake. anyio's task group
                        # raises ``BaseExceptionGroup`` — which is NOT an
                        # ``Exception`` subclass and NOT a ``TimeoutError`` —
                        # so the ``except asyncio.TimeoutError`` above
                        # silently misses it. This is the exact bug class
                        # CLAUDE.md warns about for ``ClientSession.initialize()``:
                        # bare ``except Exception`` (or ``except TimeoutError``)
                        # lets the group propagate past ``soft_fail`` and
                        # crashes recon-first. Mirror the stdio branch's
                        # ``_EXC_GROUP_CATCH`` handling.
                        if soft_fail:
                            ui.warning(f"MCP HTTP session init failed: {exc}")
                            if _is_exception_group(exc):
                                _log_nested_exceptions(exc)
                            boot_failed[0] = True
                            ui.boot_step(_http_init_label, failed=True)
                            yield None
                            return
                        ui.error(f"MCP HTTP session init failed: {exc}")
                        if _is_exception_group(exc):
                            ui.error(
                                "Detected ExceptionGroup / BaseExceptionGroup. "
                                "Unpacking nested exceptions:"
                            )
                            _log_nested_exceptions(exc)
                        raise
                    # Stop the heartbeat redraw thread now that the session is
                    # initialized — see the matching comment in the stdio branch.
                    # Without this ``[STATUS] Initializing MCP session... X.Xs``
                    # would keep ticking for the whole session.
                    ui.release_active_spinner()
                    try:
                        yield session
                    except _EXC_GROUP_CATCH as exc:
                        if soft_fail:
                            ui.warning(f"MCP session closed mid-recon: {exc}")
                            if _is_exception_group(exc):
                                _log_nested_exceptions(exc)
                            boot_failed[0] = True
                            return
                        raise RuntimeError(f"MCP session closed due to error: {exc}") from exc
    except _EXC_GROUP_CATCH as exc:
        # Transport-level failure: ``streamable_http_client`` or
        # ``ClientSession`` entry raised ``BaseExceptionGroup`` (anyio's task
        # group on a dead/reset connection — ``wait_for_port`` only confirms
        # a listening socket, not that the MCP handler is live, so a crash in
        # the narrow window between the port check and the HTTP upgrade is a
        # real race). The stdio branch wraps its whole ``stdio_client`` /
        # ``ClientSession`` block in ``except _EXC_GROUP_CATCH``; the HTTP
        # branch used to have only a cleanup ``finally`` here, so the group
        # propagated straight out of ``open_exploit_mcp_session`` and bypassed
        # ``soft_fail``. Mirror the stdio handling (the ``finally`` below
        # still runs to tear down the subprocess and close the log handle).
        if soft_fail:
            ui.warning(f"MCP HTTP session failed: {exc}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            boot_failed[0] = True
            yield None
            return
        ui.error(f"MCP HTTP session failed: {exc}")
        if _is_exception_group(exc):
            ui.error(
                "Detected ExceptionGroup / BaseExceptionGroup. "
                "Unpacking nested exceptions:"
            )
            _log_nested_exceptions(exc)
        raise
    finally:
        stop_process(process)
        log_handle.close()


def start_exploit_http_server(
    *,
    server_path: Path,
    config_path: Path,
    port: int,
    workspace: Path,
    env: dict[str, str],
) -> tuple[subprocess.Popen[str], Any]:
    if port_is_open("127.0.0.1", port):
        raise RuntimeError(
            f"Exploit MCP HTTP port {port} is already in use. Stop the process using it."
        )

    workspace.mkdir(parents=True, exist_ok=True)
    log_path = workspace / "mcp_exploit_server.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(server_path),
                "--transport", "http",
                "--host", "127.0.0.1",
                "--port", str(port),
                "--config", str(config_path.resolve()),
                "--workspace", str(workspace.resolve()),
            ],
            cwd=str(server_path.parent),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except BaseException:
        # Bug #20: if Popen raises (e.g. bad env, OOM), the log handle we
        # just opened would leak. Close it before re-raising.
        log_handle.close()
        raise
    return process, log_handle


def _server_log_tail(log_path: Path | None, *, max_lines: int = 20, max_chars: int = 4000) -> str:
    """Return a bounded server-log excerpt suitable for a startup error."""
    if log_path is None:
        return ""
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"\nServer log: {log_path} (could not read: {exc})"
    excerpt = "\n".join(lines[-max_lines:])
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
    if not excerpt:
        excerpt = "(empty)"
    return f"\nServer log: {log_path}\n--- log tail ---\n{excerpt}"


async def wait_for_port(
    host: str,
    port: int,
    timeout_seconds: float,
    *,
    process: subprocess.Popen[str] | None = None,
    log_path: Path | None = None,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process is not None:
            returncode = process.poll()
            if returncode is not None:
                raise RuntimeError(
                    f"MCP HTTP server exited with code {returncode} before "
                    f"opening {host}:{port}."
                    f"{_server_log_tail(log_path)}"
                )
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            await asyncio.sleep(0.2)
    if process is not None:
        returncode = process.poll()
        if returncode is not None:
            raise RuntimeError(
                f"MCP HTTP server exited with code {returncode} before "
                f"opening {host}:{port}."
                f"{_server_log_tail(log_path)}"
            )
    raise TimeoutError(
        f"Timed out after {timeout_seconds:g}s waiting for MCP HTTP server "
        f"on {host}:{port}."
        f"{_server_log_tail(log_path)}"
    )


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

def get_field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def to_plain_data(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return {k: to_plain_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_plain_data(i) for i in value]
    return value


def mcp_tools_to_ollama(tools_response: Any, *, disabled_tools: set[str] | None = None) -> list[dict[str, Any]]:
    tools = get_field(tools_response, "tools", []) or []
    schemas: list[dict[str, Any]] = []
    disabled = disabled_tools or set()
    for tool in tools:
        name = get_field(tool, "name", "")
        if not name:
            continue
        if name in disabled:
            continue
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": get_field(tool, "description", "") or "",
                    "parameters": to_plain_data(
                        get_field(tool, "inputSchema", None)
                        or get_field(tool, "input_schema", None)
                        or {"type": "object", "properties": {}}
                    ),
                },
            }
        )
    return schemas
