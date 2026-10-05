"""MCP exploit server session helpers."""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import subprocess as subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator, Callable

from tools import mcp_process as _mcp_process
from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions, _reraise_if_cancelled
from tools.kernel.mcp_config_snapshot import private_mcp_config_snapshot

# Keep the historical import and monkeypatch seams at ``tools.mcp_session``.
MCP_HTTP_RETRY_INITIAL_SECONDS = _mcp_process.MCP_HTTP_RETRY_INITIAL_SECONDS
_child_exit_error = _mcp_process._child_exit_error
_concise_startup_error = _mcp_process._concise_startup_error
_redact_startup_text = _mcp_process._redact_startup_text
_server_log_tail = _mcp_process._server_log_tail
_streamable_http_transport = _mcp_process._streamable_http_transport
_verify_port_freed = _mcp_process._verify_port_freed
port_is_open = _mcp_process.port_is_open
start_exploit_http_server = _mcp_process.start_exploit_http_server
stop_process = _mcp_process.stop_process
wait_for_mcp_http_ready = _mcp_process.wait_for_mcp_http_ready

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.runtime_context import RuntimeContext

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
# Single total boot budget for the HTTP path: the readiness probe and the
# session initialize() used to stack 30s + 30s (≈60s worst case, ≈90s with the
# transport connect timeout). Both phases now share one deadline so a hung
# boot can never exceed this total.
MCP_BOOT_TOTAL_BUDGET_SECONDS: float = 30.0


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
    ctx: "RuntimeContext | None" = None,
) -> None:
    """Print elapsed-time info lines every `interval` seconds.

    Run as a sibling task alongside a long blocking call (e.g. run_exploit_agent)
    so the user can tell the difference between "stuck" and "just slow".
    When a ``heartbeat`` holder is supplied, each line also shows the current
    round / action count / phase, so a 30-minute run says "round 8, 23 actions,
    service_enumeration" instead of a bare "still running".

    ``ctx`` selects the UI explicitly (see ``RuntimeContext``); omitted means
    the module-global UI (back-compat for existing tests/callers).
    """
    _ui = ctx.ui if ctx is not None else ui
    start = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        m, s = divmod(int(time.monotonic() - start), 60)
        if heartbeat is not None:
            _ui.info(
                f"{label} still running… {m}:{s:02d} elapsed "
                f"(round {heartbeat.round}, {heartbeat.action} actions, {heartbeat.phase})"
            )
        else:
            _ui.info(f"{label} still running… {m}:{s:02d} elapsed")


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


def _sensitive_env_values(env: dict[str, str]) -> tuple[str, ...]:
    """Return non-trivial secret values for exact-match log redaction."""
    values = []
    for key, value in env.items():
        lower = key.lower()
        if len(value) >= 4 and any(
            part in lower for part in ("key", "secret", "token", "password", "passwd", "api", "auth")
        ):
            values.append(value)
    return tuple(values)


def _assign_http_session_token(env: dict[str, str]) -> str:
    """Set a fresh bearer token and private identity key for one HTTP child."""
    token = secrets.token_urlsafe(32)
    env["MCP_HTTP_TOKEN"] = token
    env["MCP_HTTP_IDENTITY_SECRET"] = secrets.token_urlsafe(32)
    return token


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
    fallback_to_stdio: bool = True,
    original_target: str | None = None,
    resolved_ip: str | None = None,
    config_fingerprint: str | None = None,
    config_snapshot: dict[str, Any] | None = None,
    snapshot_excluded_paths: tuple[Path, ...] = (),
    boot_cb: Callable[[str, bool, bool], None] | None = None,
    ctx: "RuntimeContext | None" = None,
) -> AsyncIterator[Any]:
    """Open the requested transport, falling back during HTTP startup only.

    A live HTTP session is never replaced after it has been yielded: doing so
    could repeat a partially completed tool call.  The fallback is limited to
    startup/readiness/initialization failures and keeps the same loopback-only
    server environment and target scope. ``soft_fail=True`` still yields
    ``None`` only when both the requested transport and any fallback fail.

    ``ctx`` (a ``RuntimeContext``) selects the UI and boot timeout explicitly
    so concurrent runs don't share module-global state; omitted means the
    module globals (back-compat for existing tests/callers).
    """
    if config_snapshot is None:
        async with _open_exploit_mcp_session_with_fallback(
            transport=transport,
            config_path=config_path,
            target_ip=target_ip,
            exploit_port=exploit_port,
            workspace=workspace,
            multi_model_enabled=multi_model_enabled,
            active_model_alias=active_model_alias,
            soft_fail=soft_fail,
            fallback_to_stdio=fallback_to_stdio,
            original_target=original_target,
            resolved_ip=resolved_ip,
            config_fingerprint=config_fingerprint,
            boot_cb=boot_cb,
            ctx=ctx,
        ) as session:
            yield session
        return

    if config_fingerprint is None:
        raise RuntimeError("Accepted MCP config snapshot has no identity digest; refusing to start tools.")

    # API snapshots can carry provider credentials in the child environment.
    # Keep those children on their private stdio pipe; an HTTP listener on a
    # reusable loopback port would reintroduce a bind race between identity
    # proof and the connection carrying the bearer token.
    snapshot_transport = "stdio"

    with private_mcp_config_snapshot(
        config_snapshot,
        excluded_paths=(workspace, *snapshot_excluded_paths),
    ) as private_config:
        async with _open_exploit_mcp_session_with_fallback(
            transport=snapshot_transport,
            config_path=private_config.config_path,
            target_ip=target_ip,
            exploit_port=exploit_port,
            workspace=workspace,
            multi_model_enabled=multi_model_enabled,
            active_model_alias=active_model_alias,
            soft_fail=soft_fail,
            fallback_to_stdio=False,
            original_target=original_target,
            resolved_ip=resolved_ip,
            config_fingerprint=config_fingerprint,
            snapshot_secret_env=private_config.secret_env,
            private_config_snapshot=True,
            boot_cb=boot_cb,
            ctx=ctx,
        ) as session:
            yield session


@contextlib.asynccontextmanager
async def _open_exploit_mcp_session_with_fallback(
    *,
    transport: str,
    config_path: Path,
    target_ip: str,
    exploit_port: int,
    workspace: Path,
    multi_model_enabled: bool | None = None,
    active_model_alias: str = "",
    soft_fail: bool = False,
    fallback_to_stdio: bool = True,
    original_target: str | None = None,
    resolved_ip: str | None = None,
    config_fingerprint: str | None = None,
    snapshot_secret_env: dict[str, str] | None = None,
    private_config_snapshot: bool = False,
    boot_cb: Callable[[str, bool, bool], None] | None = None,
    ctx: "RuntimeContext | None" = None,
) -> AsyncIterator[Any]:
    """Coordinate one accepted config path across requested transport/fallback."""
    common: dict[str, Any] = {
        "config_path": config_path,
        "target_ip": target_ip,
        "exploit_port": exploit_port,
        "workspace": workspace,
        "multi_model_enabled": multi_model_enabled,
        "active_model_alias": active_model_alias,
        "soft_fail": soft_fail,
        "original_target": original_target,
        "resolved_ip": resolved_ip,
        "config_fingerprint": config_fingerprint,
        "snapshot_secret_env": snapshot_secret_env,
        "private_config_snapshot": private_config_snapshot,
        "boot_cb": boot_cb,
        "ctx": ctx,
    }
    if transport != "http" or not fallback_to_stdio:
        async with _open_exploit_mcp_session_once(
            transport=transport,
            startup_soft_fail=soft_fail,
            **common,
        ) as session:
            yield session
        return

    http_session_started = False
    http_startup_errors: list[BaseException] = []
    async with _open_exploit_mcp_session_once(
        transport="http",
        # An HTTP startup error is recoverable until stdio has also failed.
        # Keep it a warning even for attack mode; post-yield failures still use
        # the caller's real soft_fail setting inside the one-shot context.
        startup_soft_fail=True,
        startup_errors=http_startup_errors,
        **common,
    ) as session:
        if session is not None:
            http_session_started = True
            yield session
    if http_session_started:
        return

    (ctx.ui if ctx is not None else ui).warning("Local MCP HTTP startup failed; falling back to stdio transport.")
    stdio_session_started = False
    try:
        async with _open_exploit_mcp_session_once(
            transport="stdio",
            startup_soft_fail=soft_fail,
            **common,
        ) as session:
            if session is not None:
                stdio_session_started = True
            yield session
    except _EXC_GROUP_CATCH as exc:
        _reraise_if_cancelled(exc)
        if stdio_session_started or not http_startup_errors:
            raise
        http_detail = _concise_startup_error(http_startup_errors[-1])
        raise RuntimeError(
            f"MCP HTTP startup failed ({http_detail}); stdio fallback also failed ({_concise_startup_error(exc)})."
        ) from exc


@contextlib.asynccontextmanager
async def _open_exploit_mcp_session_once(
    *,
    transport: str,
    config_path: Path,
    target_ip: str,
    exploit_port: int,
    workspace: Path,
    multi_model_enabled: bool | None = None,
    active_model_alias: str = "",
    soft_fail: bool = False,
    startup_soft_fail: bool | None = None,
    startup_errors: list[BaseException] | None = None,
    original_target: str | None = None,
    resolved_ip: str | None = None,
    config_fingerprint: str | None = None,
    snapshot_secret_env: dict[str, str] | None = None,
    private_config_snapshot: bool = False,
    boot_cb: Callable[[str, bool, bool], None] | None = None,
    ctx: "RuntimeContext | None" = None,
) -> AsyncIterator[Any]:
    """Open one MCP client session without transport fallback.

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
    if startup_soft_fail is None:
        startup_soft_fail = soft_fail
    if startup_errors is None:
        startup_errors = []
    # Explicit per-run dependencies (see ``tools.runtime_context``): the
    # context's UI/timeout are bound to function locals so concurrent runs
    # stay isolated; omitted ``ctx`` falls back to the module globals
    # (back-compat for existing tests/callers).
    _ui = ctx.ui if ctx is not None else ui
    _boot_timeout = ctx.mcp_boot_timeout_seconds if ctx is not None else MCP_BOOT_TIMEOUT_SECONDS
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        startup_errors.append(exc)
        if startup_soft_fail:
            # The recon-first path explicitly tolerates MCP being unavailable;
            # surface a single WARN line and yield None so the caller can
            # degrade. We do NOT yield when the import itself failed (a real
            # environment problem) because there is no point continuing.
            _ui.warning("MCP Python SDK is not installed; recon skipped.")
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
    if snapshot_secret_env:
        env.update(snapshot_secret_env)
    env["EXPLOIT_TARGET"] = target_ip
    env["EXPLOIT_WORKSPACE"] = str(workspace.resolve())
    # Domain targeting: when the operator gave a domain, set the resolved IP
    # and the domain string as extra env vars so the allowlist union
    # (``_allowed_target_list``) authorizes both forms. ``EXPLOIT_TARGET``
    # stays the operator's literal ``--target`` (domain or IP) so it is the
    # primary lock identity; ``EXPLOIT_TARGET_IP`` lets IP-based tools
    # (nmap/metasploit) target the resolved host; ``EXPLOIT_TARGET_DOMAIN``
    # lets web tools use the domain for Host headers / TLS SNI.
    # Drop stale per-run keys inherited from the daemon environment so one
    # run's resolved/discovered targets can't leak into the next boot.
    env.pop("EXPLOIT_TARGET_IP", None)
    env.pop("EXPLOIT_TARGET_DOMAIN", None)
    env.pop("EXPLOIT_DISCOVERED_TARGETS", None)
    if original_target and resolved_ip:
        env["EXPLOIT_TARGET_IP"] = resolved_ip
        env["EXPLOIT_TARGET_DOMAIN"] = original_target
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
    _ui.boot_section("MCP exploit session boot sequence")

    def _boot_step(label: str, *, ok: bool = True, failed: bool = False) -> None:
        """Emit a boot checklist step to the terminal UI and, when a ``boot_cb``
        is supplied (the API path), forward it so the WebUI can render a live
        boot checklist. ``boot_cb`` receives ``(label, ok, failed)``."""
        _ui.boot_step(label, ok=ok, failed=failed)  # terminal UI only — do not recurse
        if boot_cb is not None:
            boot_cb(label, ok, failed)

    if transport == "stdio":
        stdio_yielded = False
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[
                str(server_path),
                "--transport",
                "stdio",
                *(["--private-config-snapshot"] if private_config_snapshot else []),
                "--config",
                str(config_path.resolve()),
                *(["--expected-config-sha256", config_fingerprint] if config_fingerprint is not None else []),
                "--workspace",
                str(workspace.resolve()),
            ],
            env=env,
        )

        _stdio_label = "Booting MCP server (stdio)"
        _boot_step(_stdio_label, ok=False)
        with _ui.spinner(
            "Booting MCP server (stdio)...",
            soft_fail=startup_soft_fail,
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
                                timeout=_boot_timeout,
                            )
                            _boot_step(_stdio_label, ok=True)
                        except asyncio.TimeoutError as exc:
                            startup_errors.append(exc)
                            if startup_soft_fail:
                                _ui.warning(
                                    f"MCP server boot timed out after "
                                    f"{_boot_timeout:.0f}s — "
                                    f"subprocess did not finish initializing."
                                )
                                boot_failed[0] = True
                                _boot_step(_stdio_label, failed=True)
                                stdio_yielded = True
                                yield None
                                return
                            raise RuntimeError(f"MCP server boot timed out after {_boot_timeout:.0f}s")
                        # The boot spinner's ``with`` block encloses ``yield session``
                        # below, so without this the redraw thread would keep printing
                        # ``[STATUS] Booting MCP server (stdio)... X.Xs`` for the
                        # ENTIRE session. The server has finished booting now — stop
                        # the heartbeat. The ``with`` block's own exit tail line (the
                        # static ``[SUCCESS]`` message) still fires on exit; this only
                        # stops the recurring elapsed-seconds redraw. See
                        # ``AttackUi.release_active_spinner``.
                        _ui.release_active_spinner()
                        try:
                            stdio_yielded = True
                            yield session
                        except _EXC_GROUP_CATCH as exc:
                            _reraise_if_cancelled(exc)
                            if soft_fail:
                                _ui.warning(f"MCP session closed mid-recon: {exc}")
                                if _is_exception_group(exc):
                                    _log_nested_exceptions(exc)
                                boot_failed[0] = True
                                return
                            raise RuntimeError(f"MCP session closed due to error: {exc}") from exc
            except _EXC_GROUP_CATCH as exc:
                _reraise_if_cancelled(exc)
                startup_errors.append(exc)
                # Log the exact error before re-raising so the user always sees it.
                # anyio's task groups (used by ``stdio_client``) raise
                # ``BaseExceptionGroup`` on subprocess failure — that is *not* an
                # ``Exception`` subclass, so we MUST catch the group explicitly.
                if startup_soft_fail:
                    _ui.warning(f"MCP stdio session failed: {exc}")
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)
                    # Fall out of the ``with _ui.spinner(...)`` and the function
                    # to give the caller a ``None`` session.
                    boot_failed[0] = True
                    _boot_step(_stdio_label, failed=True)
                    if not stdio_yielded:
                        stdio_yielded = True
                        yield None
                    return
                _ui.error(f"MCP stdio session failed: {exc}")
                if _is_exception_group(exc):
                    _ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
                    _log_nested_exceptions(exc)
                raise
        return

    # Multiple API runs share the configured TCP port. A fresh child token
    # authenticates MCP requests, while a separate identity key lets the
    # parent verify the listener before sending that bearer token.
    _assign_http_session_token(env)
    _http_start_label = f"Starting MCP HTTP server on port {exploit_port}"
    _boot_step(_http_start_label, ok=False)
    # The readiness probe + initialize() below share this single deadline (see
    # MCP_BOOT_TOTAL_BUDGET_SECONDS) instead of each taking a full 30s.
    _boot_deadline = time.monotonic() + MCP_BOOT_TOTAL_BUDGET_SECONDS

    def _boot_remaining() -> float:
        return max(1.0, min(_boot_timeout, _boot_deadline - time.monotonic()))

    with _ui.spinner(
        f"Starting MCP HTTP server on port {exploit_port}...",
        soft_fail=startup_soft_fail,
        soft_fail_flag=boot_failed,
    ):
        try:
            process, log_handle = start_exploit_http_server(
                server_path=server_path,
                config_path=config_path,
                config_fingerprint=config_fingerprint,
                private_config_snapshot=private_config_snapshot,
                port=exploit_port,
                workspace=workspace,
                env=env,
            )
        except (OSError, RuntimeError) as exc:
            startup_errors.append(exc)
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
            if startup_soft_fail:
                _ui.warning(f"MCP HTTP server failed to start on port {exploit_port}: {exc}")
                boot_failed[0] = True
                _boot_step(_http_start_label, failed=True)
                yield None
                return
            _ui.error(f"MCP HTTP server failed to start on port {exploit_port}: {exc}")
            raise
    _boot_step(_http_start_label, ok=not boot_failed[0], failed=boot_failed[0])
    http_log_path = Path(log_handle.name)
    http_log_secrets = _sensitive_env_values(env)
    http_initialized = False
    try:
        _http_port_label = f"Waiting for MCP HTTP readiness on port {exploit_port}"
        _boot_step(_http_port_label, ok=False)
        try:
            with _ui.spinner(
                f"Waiting for MCP HTTP readiness on port {exploit_port}...",
                soft_fail=startup_soft_fail,
                soft_fail_flag=boot_failed,
            ):
                # The live session below performs the authoritative MCP
                # handshake. Readiness only needs the owned child to listen;
                # a disposable preflight session can hang independently and
                # incorrectly reject an otherwise healthy server.
                await wait_for_mcp_http_ready(
                    f"http://127.0.0.1:{exploit_port}/mcp",
                    timeout_seconds=_boot_remaining(),
                    process=process,
                    log_path=http_log_path,
                    secret_values=http_log_secrets,
                    identity_secret=env.get("MCP_HTTP_IDENTITY_SECRET", ""),
                )
            _boot_step(_http_port_label, ok=True)
        except (OSError, asyncio.TimeoutError, RuntimeError) as exc:
            startup_errors.append(exc)
            if startup_soft_fail:
                _ui.warning(f"MCP HTTP server did not start on port {exploit_port}: {exc}")
                # M19: an asynccontextmanager MUST yield before returning. The
                # stdio soft-fail branches (281/307) already yield None; the HTTP
                # branches here and below used to ``return`` without yielding,
                # which raised ``RuntimeError: async generator didn't yield``
                # instead of degrading to a None session for the recon-first
                # path. Mirror the stdio behaviour.
                boot_failed[0] = True
                _boot_step(_http_port_label, failed=True)
                yield None
                return
            raise
        async with _streamable_http_transport(
            f"http://127.0.0.1:{exploit_port}/mcp",
            token=env.get("MCP_HTTP_TOKEN", "").strip(),
        ) as (
            read_stream,
            write_stream,
            _,
        ):
            _http_init_label = "Initializing MCP session"
            _boot_step(_http_init_label, ok=False)
            with _ui.spinner(
                "Initializing MCP session...",
                soft_fail=startup_soft_fail,
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
                            timeout=_boot_remaining(),
                        )
                        _boot_step(_http_init_label, ok=True)
                    except asyncio.TimeoutError as exc:
                        startup_errors.append(exc)
                        if startup_soft_fail:
                            _ui.warning(
                                f"MCP HTTP session init timed out after "
                                f"{_boot_timeout:.0f}s."
                                f"{_server_log_tail(http_log_path, secret_values=http_log_secrets)}"
                            )
                            # M19: yield before returning (see the matching
                            # comment on the HTTP-start soft-fail branch above).
                            boot_failed[0] = True
                            _boot_step(_http_init_label, failed=True)
                            yield None
                            return
                        raise RuntimeError(
                            f"MCP HTTP session init timed out after "
                            f"{_boot_timeout:.0f}s"
                            f"{_server_log_tail(http_log_path, secret_values=http_log_secrets)}"
                        )
                    except _EXC_GROUP_CATCH as exc:
                        _reraise_if_cancelled(exc)
                        startup_errors.append(exc)
                        # The server died mid-handshake. anyio's task group
                        # raises ``BaseExceptionGroup`` — which is NOT an
                        # ``Exception`` subclass and NOT a ``TimeoutError`` —
                        # so the ``except asyncio.TimeoutError`` above
                        # silently misses it. This is the exact bug class
                        # CLAUDE.md warns about for ``ClientSession.initialize()``:
                        # bare ``except Exception`` (or ``except TimeoutError``)  # ponytail: bare except intentional
                        # lets the group propagate past ``soft_fail`` and
                        # crashes recon-first. Mirror the stdio branch's
                        # ``_EXC_GROUP_CATCH`` handling.
                        if startup_soft_fail:
                            _ui.warning(
                                f"MCP HTTP session init failed: {exc}"
                                f"{_server_log_tail(http_log_path, secret_values=http_log_secrets)}"
                            )
                            if _is_exception_group(exc):
                                _log_nested_exceptions(exc)
                            boot_failed[0] = True
                            _boot_step(_http_init_label, failed=True)
                            yield None
                            return
                        _ui.error(
                            f"MCP HTTP session init failed: {exc}"
                            f"{_server_log_tail(http_log_path, secret_values=http_log_secrets)}"
                        )
                        if _is_exception_group(exc):
                            _ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
                            _log_nested_exceptions(exc)
                        raise
                    http_initialized = True
                    # Stop the heartbeat redraw thread now that the session is
                    # initialized — see the matching comment in the stdio branch.
                    # Without this ``[STATUS] Initializing MCP session... X.Xs``
                    # would keep ticking for the whole session.
                    _ui.release_active_spinner()
                    try:
                        yield session
                    except _EXC_GROUP_CATCH as exc:
                        _reraise_if_cancelled(exc)
                        if soft_fail:
                            _ui.warning(f"MCP session closed mid-recon: {exc}")
                            if _is_exception_group(exc):
                                _log_nested_exceptions(exc)
                            boot_failed[0] = True
                            return
                        raise RuntimeError(f"MCP session closed due to error: {exc}") from exc
    except _EXC_GROUP_CATCH as exc:
        _reraise_if_cancelled(exc)
        # Transport-level failure: ``streamable_http_client`` or
        # ``ClientSession`` entry raised ``BaseExceptionGroup`` (anyio's task
        # group on a dead/reset connection. Even after a successful MCP
        # readiness probe, the child can crash in the narrow window before the
        # live HTTP session connects. The stdio branch wraps its whole client /
        # ``ClientSession`` block in ``except _EXC_GROUP_CATCH``; the HTTP
        # branch used to have only a cleanup ``finally`` here, so the group
        # propagated straight out of ``open_exploit_mcp_session`` and bypassed
        # ``soft_fail``. Mirror the stdio handling (the ``finally`` below
        # still runs to tear down the subprocess and close the log handle).
        failure_is_soft = soft_fail if http_initialized else startup_soft_fail
        if not http_initialized:
            startup_errors.append(exc)
        startup_log_tail = "" if http_initialized else _server_log_tail(http_log_path, secret_values=http_log_secrets)
        if failure_is_soft:
            _ui.warning(f"MCP HTTP session failed: {exc}{startup_log_tail}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            boot_failed[0] = True
            yield None
            return
        _ui.error(f"MCP HTTP session failed: {exc}{startup_log_tail}")
        if _is_exception_group(exc):
            _ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
            _log_nested_exceptions(exc)
        raise
    finally:
        try:
            # ponytail: pass the port so stop_process can verify the socket
            # is actually freed (Windows taskkill /T sometimes misses uvicorn
            # descendants). Without this, the recon-phase orphan holds port
            # 8001 and the attack-phase probe times out (30s × 2 = ~60s/run).
            stop_process(process, host="127.0.0.1", port=exploit_port)
        finally:
            log_handle.close()


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
