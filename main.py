"""AI Target Exploitation Engine — autonomous penetration testing AI.

Usage:
    python main.py                          # WebUI daemon (default; opens a browser)
    python main.py --menu                   # legacy interactive terminal menu
    python main.py --target 10.0.0.50 --mode attack --goal backdoor
    python main.py --target 10.0.0.50 --mode recon --goal initial_access
"""

# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import os
import shutil  # noqa: F401 -- retained so tests can patch main.shutil
import subprocess  # noqa: F401 -- retained so tests can patch main.subprocess
import sys
import traceback
from inspect import getattr_static
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from tools import daemon_lifecycle as _daemon_lifecycle
from tools import webui_boot as _webui_boot
from tools.attack_ui import get_ui
from tools.cli_args import __version__, parse_args  # noqa: F401 -- __version__ re-exported for lazy consumers
from tools.daemon_lifecycle import (  # noqa: F401 -- back-compat re-exports; canonical home is tools.daemon_lifecycle
    _api_daemon_ready,
    _copy_to_clipboard,
    _find_port_listener_pid,
    _offer_daemon_kill,
    _stop_running_daemon,
)
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group
from tools.exploit_agent import (
    ExploitSettings,
    run_exploit_agent,
)
from tools.goal_engine import AttackGoal, GoalEngine
from tools.goal_suggester import ReconAssessment
from tools.model_router import build_router
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.safety_reviewer import SafetyReview
from tools.swarm_bridge import SwarmMcpBridge as SwarmMcpBridge  # noqa: F401 - re-export for tests/back-compat
from tools.webui_boot import (  # noqa: F401 -- back-compat re-exports; canonical home is tools.webui_boot
    _ensure_webui_build,
    _install_bun,
    _open_browser_when_ready,
)

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

ui = get_ui()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

from tools import config_cli as _config_cli
from tools.config_cli import load_config


def bootstrap_startup_api_keys(args: argparse.Namespace, *, prompt: bool = False) -> None:
    _config_cli.ui = ui
    _config_cli.bootstrap_startup_api_keys(args, prompt=prompt)


from tools.cli_exploit_settings import (
    _compute_swarm_timeout as _compute_swarm_timeout,  # noqa: F401 - re-export for tests/back-compat
)
from tools.cli_exploit_settings import (
    build_cli_exploit_settings as build_cli_exploit_settings,  # noqa: F401 - re-export for tests/back-compat
)
from tools.resume_state import _load_resume_state as _load_resume_state  # noqa: F401 - re-export for tests/back-compat
from tools.skills_cli import (
    _apply_runtime_skill_selection as _apply_runtime_skill_selection,  # noqa: F401 - re-export for tests/back-compat
)
from tools.skills_cli import (
    apply_skills_cli_overrides,
    print_skills_catalog,
)


def _log_nested_exceptions(exc: BaseException, *, prefix: str = "") -> None:
    """Recursively log every exception inside an ExceptionGroup / BaseExceptionGroup."""
    if _is_exception_group(exc):
        group = exc  # type: ignore[union-attr]
        for i, nested in enumerate(group.exceptions):
            _log_nested_exceptions(nested, prefix=f"{prefix}  [{i}] ")
    else:
        try:
            lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        except Exception as fmt_exc:  # pragma: no cover - defensive
            # Last-ditch fallback: a misbehaving exception's __traceback__ or
            # __str__ can itself raise. Don't let the *logging* of the failure
            # become a second failure.
            ui.error(f"{prefix}<unformattable exception {type(exc).__name__}: {fmt_exc!r}>")
            return
        for line in lines:
            ui.error(f"{prefix}{line.rstrip()}")


# ---------------------------------------------------------------------------
# MCP Exploit Session
# ---------------------------------------------------------------------------

from tools import mcp_session as _mcp_session
from tools.mcp_session import (
    MCP_BOOT_TIMEOUT_SECONDS as _DEFAULT_MCP_BOOT_TIMEOUT_SECONDS,
)
from tools.runtime_context import RuntimeContext

MCP_BOOT_TIMEOUT_SECONDS: float = _DEFAULT_MCP_BOOT_TIMEOUT_SECONDS


def get_runtime_context() -> RuntimeContext:
    """Build this process's runtime context from main.py's locals.

    The single place where CLI runtime dependencies are bundled — passed
    explicitly into ``tools.*`` via ``ctx=`` instead of mutating imported
    module globals per call (which broke concurrent runs sharing the
    process). Tests keep patching ``main.*`` symbols; the context reads
    them lazily here so patched values flow through.
    """
    return RuntimeContext(
        ui=ui,
        config_loader=load_config,
        mcp_boot_timeout_seconds=MCP_BOOT_TIMEOUT_SECONDS,
        open_mcp_session=open_exploit_mcp_session,
        run_exploit_agent_fn=run_exploit_agent,
        build_router_fn=build_router,
    )


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
    original_target: str | None = None,
    resolved_ip: str | None = None,
) -> AsyncIterator[Any]:
    async with _mcp_session.open_exploit_mcp_session(
        transport=transport,
        config_path=config_path,
        target_ip=target_ip,
        exploit_port=exploit_port,
        workspace=workspace,
        multi_model_enabled=multi_model_enabled,
        active_model_alias=active_model_alias,
        soft_fail=soft_fail,
        original_target=original_target,
        resolved_ip=resolved_ip,
        ctx=get_runtime_context(),
    ) as session:
        yield session


async def _elapsed_ticker(
    label: str,
    *,
    interval: float = 15.0,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
) -> None:
    await _mcp_session._elapsed_ticker(label, interval=interval, heartbeat=heartbeat, ctx=get_runtime_context())


# ---------------------------------------------------------------------------
# Single-model exploit session (legacy compatible)
# ---------------------------------------------------------------------------

from tools import exploit_session as _exploit_session


async def run_exploit_session(
    *,
    client: Any,
    model: str,
    target_ip: str,
    mode: str,
    goal: AttackGoal,
    exploit_settings: ExploitSettings,
    config_path: Path,
    mcp_transport: str,
    exploit_port: int,
    reports_dir: Path,
    assessment: ReconAssessment | None = None,
    approval_prompt: Callable[[str], str] | None = None,
    approval_provider: Any = None,
    swarm_attach: Callable[..., None] | None = None,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
    original_target: str | None = None,
    resolved_ip: str | None = None,
) -> dict[str, Any]:
    return await _exploit_session.run_exploit_session(
        client=client,
        model=model,
        target_ip=target_ip,
        mode=mode,
        goal=goal,
        exploit_settings=exploit_settings,
        config_path=config_path,
        mcp_transport=mcp_transport,
        exploit_port=exploit_port,
        reports_dir=reports_dir,
        assessment=assessment,
        approval_prompt=approval_prompt,
        approval_provider=approval_provider,
        swarm_attach=swarm_attach,
        heartbeat=heartbeat,
        original_target=original_target,
        resolved_ip=resolved_ip,
        ctx=get_runtime_context(),
    )


# ---------------------------------------------------------------------------
# Safety review phase for recon mode
# ---------------------------------------------------------------------------

from tools import safety_review_cli as _safety_review_cli


async def run_safety_review(
    client: Any,
    model: str,
    result: dict[str, Any],
    target_ip: str,
    goal: AttackGoal,
) -> SafetyReview:
    return await _safety_review_cli.run_safety_review(client, model, result, target_ip, goal, ctx=get_runtime_context())


from tools import recon_assessment_cli as _recon_assessment_cli


def _llm_usage_line_count() -> int:
    """Line count of the shared llm_usage.jsonl, or 0 if absent.

    Used to snapshot the offset before a run so end-of-run telemetry reports
    only THIS run's model calls (model_router appends every chat to one
    cumulative file).
    """
    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _read_swarm_snapshot(swarm_workspace: Path) -> str:
    """One-line live progress string from swarm_state.json, or "" if unavailable.

    Counts agents by status (complete/running/blocked/failed) so the swarm
    wait loop can show live progress instead of a frozen "elapsed 0s" label.
    This is a tiny inline json.loads reader for the snapshot shape written by
    ``tools/swarm/orchestrator.py:_persist_state``.
    """
    import json as _json

    path = swarm_workspace / "swarm_state.json"
    try:
        if not path.exists():
            return ""
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, _json.JSONDecodeError):
        return ""
    agents = data.get("agents", []) if isinstance(data, dict) else []
    counts: dict[str, int] = {}
    for agent in agents:
        if isinstance(agent, dict):
            status = str(agent.get("status", ""))
            counts[status] = counts.get(status, 0) + 1
    parts = []
    for key, label in (("complete", "done"), ("running", "running"), ("blocked", "blocked"), ("failed", "failed")):
        n = counts.get(key, 0)
        if n:
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def _run_telemetry(start_lines: int) -> dict[str, Any] | None:
    """Aggregate llm_usage.jsonl records appended after ``start_lines``.

    Returns per-run totals (calls, total_tokens, avg/max context_usage_pct) by
    parsing only the new lines since the snapshot, so the number is this run's
    model usage rather than the all-history cumulative file. None if no new
    records or the log can't be read.
    """
    import itertools as _it
    import json as _json

    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return None
        # ponytail perf: stream from the offset instead of read_text() of the
        # whole cumulative file (was O(file) memory + parse per run).
        calls = 0
        total_tokens = 0
        ctx_sum = 0.0
        ctx_n = 0
        ctx_max: float | None = None
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in _it.islice(handle, max(0, int(start_lines)), None):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                calls += 1
                tok = item.get("total_tokens")
                if isinstance(tok, (int, float)):
                    total_tokens += int(tok)
                ctx = item.get("context_usage_pct")
                if isinstance(ctx, (int, float)):
                    fctx = float(ctx)
                    ctx_sum += fctx
                    ctx_n += 1
                    ctx_max = fctx if ctx_max is None or fctx > ctx_max else ctx_max
    except OSError:
        return None
    if not calls:
        return None
    avg_ctx = (ctx_sum / ctx_n) if ctx_n else None
    return {
        "calls": calls,
        "total_tokens": total_tokens,
        "avg_ctx": avg_ctx,
        "max_ctx": ctx_max,
    }


async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
) -> ReconAssessment:
    return await _recon_assessment_cli.run_recon_assessment(
        session=session,
        target_ip=target_ip,
        reports_dir=reports_dir,
        ctx=get_runtime_context(),
    )


def _extract_tool_text(raw: Any) -> str:
    return _recon_assessment_cli._extract_tool_text(raw)


# ---------------------------------------------------------------------------
# Entry splits (p2-03) — canonical implementations live in tools.cli_args
# (parse_args, re-exported above), tools.daemon_lifecycle, and
# tools.webui_boot. Leaf helpers are plain re-export aliases (top-of-file
# imports); the four wrappers below sync main-namespace monkeypatches into
# the impl modules before delegating, so the existing ``main.*`` patch seams
# keep working (same idea as tools.exploit_agent._sync_patchable_symbols).
# ---------------------------------------------------------------------------

_BOOT_SYNC_TARGETS: tuple[tuple[str, tuple[object, ...]], ...] = (
    ("ui", (_daemon_lifecycle, _webui_boot)),
    ("load_config", (_daemon_lifecycle, _webui_boot)),
    ("_api_daemon_ready", (_daemon_lifecycle,)),
    ("_find_port_listener_pid", (_daemon_lifecycle,)),
    ("_stop_running_daemon", (_daemon_lifecycle,)),
    ("_offer_daemon_kill", (_daemon_lifecycle,)),
    ("_copy_to_clipboard", (_daemon_lifecycle,)),
    ("_ensure_webui_build", (_webui_boot,)),
    ("_rebuild_webui", (_webui_boot,)),
    ("_install_bun", (_webui_boot,)),
    ("_open_browser_when_ready", (_webui_boot,)),
    ("_auto_update_models", (_webui_boot,)),
    ("_ensure_chatgpt_runtime", (_webui_boot,)),
)


@contextlib.contextmanager
def _synced_boot_symbols() -> Any:
    """Temporarily propagate main-namespace overrides into the impl modules.

    The sync mutates impl-module globals; without a restore, a fake synced
    for one call would leak into later calls made after the test's
    ``monkeypatch`` teardown reverted ``main.*``. Every wrapper delegates
    inside this context so impl modules are always left as found.
    """
    public = sys.modules[__name__]
    saved: list[tuple[Any, str, Any]] = []
    try:
        for _name, _modules in _BOOT_SYNC_TARGETS:
            _value = getattr(public, _name, None)
            if _value is None or getattr_static(_value, "_breachpilot_boot_wrapper", False):
                continue
            for _mod in _modules:
                if hasattr(_mod, _name):
                    saved.append((_mod, _name, getattr(_mod, _name)))
                    setattr(_mod, _name, _value)
        yield
    finally:
        for _mod, _name, _old in reversed(saved):
            setattr(_mod, _name, _old)


def _run_daemon(args: argparse.Namespace) -> int:
    """Start the local WebUI API server. Canonical implementation: tools.daemon_lifecycle."""
    with _synced_boot_symbols():
        return _daemon_lifecycle._run_daemon(args)


_run_daemon._breachpilot_boot_wrapper = True


def _rebuild_webui(ui: Any) -> int:
    """Force a clean rebuild of the WebUI. Canonical implementation: tools.webui_boot."""
    with _synced_boot_symbols():
        return _webui_boot._rebuild_webui(ui)


_rebuild_webui._breachpilot_boot_wrapper = True


def _auto_update_models(config: dict[str, Any], config_path: str) -> None:
    """Best-effort models.registry sync. Canonical implementation: tools.webui_boot."""
    with _synced_boot_symbols():
        return _webui_boot._auto_update_models(config, config_path)


_auto_update_models._breachpilot_boot_wrapper = True


def _ensure_chatgpt_runtime(args: argparse.Namespace) -> int:
    """Ensure the ChatGPT provider is runnable. Canonical implementation: tools.webui_boot."""
    with _synced_boot_symbols():
        return _webui_boot._ensure_chatgpt_runtime(args)


_ensure_chatgpt_runtime._breachpilot_boot_wrapper = True


async def async_main(args: argparse.Namespace) -> int:
    """CLI adapter over ``AssessmentService``.

    Builds a ``RunRequest`` from CLI args, calls ``AssessmentService.prepare``
    to get a preview, renders it via ``AttackUi``, asks the ready-to-begin
    confirmation via ``TerminalDecisionProvider``, then calls
    ``AssessmentService.execute`` with terminal event/approval adapters.

    The ``Callables`` bundle passes ``main``'s module-level symbols
    (``open_exploit_mcp_session``, ``run_exploit_session``, ``build_router``,
    ``GoalEngine``) into the service so existing tests that monkeypatch
    ``main_mod.*`` continue to drive the service through the patched symbols.
    """
    from tools.run_service import (
        AssessmentService,
        Callables,
        CancellationToken,
        RunRequest,
        TerminalDecisionProvider,
        TerminalEventSink,
    )

    # --debug / --ultrathink signals.
    if getattr(args, "debug", False):
        os.environ["AI_NMAP_DEBUG"] = "1"
        ui.info("Debug mode enabled (verbose logging; tracebacks will be printed to stderr on error).")
    if getattr(args, "ultrathink", False):
        ui.info("ULTRATHINK mode enabled: verbose chain-of-thought and frequent reflection.")

    config_path = args.config
    config = load_config(config_path)
    config = apply_skills_cli_overrides(config, args)
    # Load plugins before the MCP exploit server is created.
    try:
        from tools.plugins import load_plugins

        load_plugins(config)
    except Exception as exc:  # noqa: BLE001 -- plugin load must not block boot
        ui.info(f"Plugin load skipped: {type(exc).__name__}: {exc}")
        if getattr(args, "debug", False):
            ui.info(traceback.format_exc().strip())

    multi_model_cfg = config.get("multi_model", {}) or {}
    if getattr(args, "multi_model_consult", None) is None:
        args.multi_model_consult = bool(multi_model_cfg.get("enabled", False))

    ui.banner()
    ui.info(f"Config: {config_path} ({'found' if config_path.exists() else 'not found; using defaults'})")

    # Interactive session: ask advanced settings.
    interactive_session = not getattr(args, "target", "").strip()
    if interactive_session:
        try:
            args = await ui.ask_advanced_settings(None, args)
            ui.plain = bool(
                getattr(args, "plain", False) or getattr(args, "quiet", False) or getattr(args, "json", False)
            )
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # Build the RunRequest from args. ponytail: default recon — attack needs explicit --mode attack.
    request = RunRequest(
        target=args.target.strip(),
        mode=getattr(args, "mode", "").strip().lower() or "recon",
        goal_name=getattr(args, "goal", "").strip().lower(),
        custom_goal=getattr(args, "custom_goal", "").strip(),
        recon_first=getattr(args, "recon_first", None),
        model_alias=getattr(args, "model", None) or "",
        config_path=config_path,
        reports_dir=getattr(args, "reports_dir", Path("reports")),
        swarm=bool(getattr(args, "swarm", False)),
        parallel_swarm=bool(getattr(args, "parallel_swarm", False)),
        critic=bool(getattr(args, "critic", False)),
        reflection=bool(getattr(args, "reflection", False)),
        adaptive_exploits=bool(getattr(args, "adaptive_exploits", False)),
        long_session=bool(getattr(args, "long_session", False)),
        multi_model_consult=getattr(args, "multi_model_consult", None),
        observer_mode=getattr(args, "observer_mode", "hybrid"),
        ultrathink=bool(getattr(args, "ultrathink", False)),
        debug=bool(getattr(args, "debug", False)),
        plain=bool(getattr(args, "plain", False)),
        json_output=bool(getattr(args, "json", False)),
        yes=bool(getattr(args, "yes", False)),
        skills_mode=getattr(args, "skills", None),
        skills_include=list(getattr(args, "skills_include", None) or []),
        skills_exclude=list(getattr(args, "skills_exclude", None) or []),
        skills_no_reselect=bool(getattr(args, "no_skills_reselect", False)),
        resume_source=(getattr(args, "resume", "") or "").strip(),
        interactive=interactive_session,
    )

    # If no target, ask interactively (preserves the existing menu flow).
    if not request.target:
        try:
            request.target = ui.ask_target()
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1
    if not request.target:
        ui.error("No target provided.")
        return 1

    # Construct the service with CLI-patchable callables.
    callables = Callables(
        build_router=build_router,
        open_session=open_exploit_mcp_session,
        run_session=run_exploit_session,
        goal_engine_cls=GoalEngine,
        run_recon_assessment=run_recon_assessment,
        run_safety_review=run_safety_review,
    )
    service = AssessmentService(config=config, callables=callables)

    # Prepare (resolve target/goal/settings without I/O side effects).
    try:
        preview = await service.prepare(request)
    except ValueError as exc:
        ui.error(str(exc))
        return 1

    # Interactive target entered via menu: persist to allowlist.
    if interactive_session:
        try:
            from tools import config_cli as _config_cli

            added = _config_cli.add_target_to_allowlist(config_path, preview.original_target)
            if added:
                ui.status(f"Saved {preview.original_target} to {config_path} exploit.allowed_targets.")
        except (OSError, ValueError) as exc:
            ui.error(f"Could not save {preview.original_target} to the config allowlist: {exc}")
            return 1

    # Warn on public targets.
    _privacy_ip = preview.resolved_ip or preview.target_ip
    try:
        if not ipaddress.ip_address(_privacy_ip).is_private:
            ui.status("WARNING: Target is a PUBLIC IP. Ensure you OWN this infrastructure.")
    except ValueError:
        pass
    if preview.resolved_domain:
        ui.status(f"Domain target {preview.resolved_domain} resolved to {preview.resolved_ip}.")

    # Render run summary.
    if not request.resume_source:
        ui.info(f"Reports root: {args.reports_dir}")
        ui.info(f"This run will write to: {preview.reports_dir}  (run_id={preview.run_id})")
    ui.status(f"Target: {preview.target_ip}")
    ui.status(f"Mode: {preview.mode}")
    ui.status(f"Goal: {preview.goal_name}")
    ui.divider()
    ui.status("Run summary:")
    ui.status(f"  Config:      {config_path}")
    ui.status(f"  Reports root:{args.reports_dir}")
    ui.status(f"  Run ID:      {preview.run_id}")
    ui.status(f"  Target:      {preview.target_ip}")
    ui.status(f"  Mode:        {preview.mode}")
    ui.status(f"  Goal:        {preview.goal_name}")
    ui.status(f"  Model:       {preview.model_label}")
    ui.status(f"  Transport:   {preview.transport_summary}")
    ui.status(f"  Reports:     {preview.reports_dir}")
    if preview.destructive:
        ui.status(
            f"  {ui._c('red')}[!] DESTRUCTIVE: permission=full_access, attack_mode={preview.attack_mode}{ui._c('reset')}"
        )
    ui.status(f"  Permission:  {preview.permission}")
    ui.status(f"  Attack mode: {preview.attack_mode}")
    ui.status(f"  Swarm:       {preview.swarm}")
    if preview.swarm or preview.parallel_swarm:
        ui.status(f"  Parallel:   {preview.parallel_swarm}")
    ui.status(f"  Peer models: {preview.multi_model}")
    try:
        ui.status(
            f"  Budget:      {preview.budgets.get('commands', 'n/a')} commands, "
            f"{preview.budgets.get('rounds', 'n/a')} rounds, "
            f"{preview.budgets.get('duration_minutes', 'n/a')} min."
        )
    except Exception:
        pass
    ui.skills([f"{a['name']} - {a['reason']}" for a in preview.skill_activations])
    if preview.skill_errors:
        ui.warning(f"Skill registry loaded with {len(preview.skill_errors)} warning(s):")
        for err in preview.skill_errors:
            ui.warning(f"  - {err}")
    ui.divider()

    # Ready-to-begin gate. ponytail: --yes never skips typed ALLOW on destructive runs.
    if (not getattr(args, "yes", False)) or preview.destructive:
        decision_provider = TerminalDecisionProvider(ui)
        from tools.run_service.models import Decision, DecisionKind

        confirm_decision = Decision(
            id="",
            run_id=preview.run_id,
            kind=DecisionKind.START_CONFIRM,
            prompt_text="Proceed? [Y/n]",
            required_text=preview.required_confirmation_text,
        )
        answer = await decision_provider.request(confirm_decision)
        if preview.destructive:
            if answer != preview.required_confirmation_text:
                ui.info("Aborted by user.")
                return 0
        else:
            if not answer:
                ui.info("Aborted by user.")
                return 0

    # Execute.
    cancellation = CancellationToken()
    event_sink = TerminalEventSink()
    try:
        result = await service.execute(
            request,
            preview,
            decision_provider=TerminalDecisionProvider(ui),
            event_sink=event_sink,
            cancellation=cancellation,
            config=config,
        )
    except RuntimeError as exc:
        ui.error(f"Exploitation session failed: {exc}")
        return 1
    except _EXC_GROUP_CATCH as exc:
        log_path = preview.reports_dir / "session_error.log"
        try:
            log_path.write_text(
                "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                encoding="utf-8",
            )
        except OSError:
            pass
        ui.error(f"Exploitation session failed unexpectedly: {exc}")
        ui.error(f"  See {log_path} for the full traceback.")
        if _is_exception_group(exc):
            ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
            _log_nested_exceptions(exc)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return 1

    if result.error:
        ui.error(f"Run failed: {result.error}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv if argv is not None else sys.argv[1:])

        # Apply output flags to the shared UI instance. --quiet and --json both
        # suppress ANSI color (so logs/JSON pipelines stay clean); --plain does
        # the same explicitly. Done once here so every downstream call site
        # (ui.status, ui.error, ui.spinner, etc.) honors them.
        ui.plain = bool(args.plain or args.quiet or args.json)
        raw_argv = argv if argv is not None else sys.argv[1:]
        # ponytail: --eval is nargs="*" (default None), so a bare "--eval" is an
        # empty list — falsy. Every gate below that used to truthy-test --eval
        # now goes through _eval_active instead.
        _eval_active = getattr(args, "eval", None) is not None or getattr(args, "eval_list", False)
        _benchmark_active = getattr(args, "benchmark", None) is not None or getattr(args, "benchmark_list", False)
        # ponytail: prompt only in the terminal menu (--menu). The no-args
        # default now launches the WebUI daemon, not the terminal menu, so the
        # interactive key prompt should not fire there. --setup-api-keys still
        # forces the prompt via force_prompt below.
        interactive_startup = bool(args.menu)
        bootstrap_startup_api_keys(
            args,
            prompt=interactive_startup
            and not args.doctor
            and not getattr(args, "self_test", False)
            and not _eval_active
            and not _benchmark_active,
        )
        setup_only = bool(args.setup_api_keys) and not any(
            [
                args.target.strip(),
                args.mode.strip(),
                args.goal.strip(),
                args.custom_goal.strip(),
                args.menu,
                args.doctor,
                getattr(args, "self_test", False),
                _eval_active,
                args.demo,
                getattr(args, "daemon", False),
                getattr(args, "web", False),
                getattr(args, "rebuild", False),
            ]
        )
        if setup_only:
            return 0

        # ChatGPT provider: ensure bun + the vendored openai-oauth checkout +
        # `bun install` are all in place before any runtime path can hit the
        # proxy. Surfaces the fix (install/clone/install-deps) up front instead
        # of letting the proxy's own RuntimeError fire mid-run. Skipped for
        # --doctor/--self-test/--eval/--benchmark, which intentionally probe a partial state.
        if (
            not _eval_active
            and not _benchmark_active
            and not any(getattr(args, flag, False) for flag in ("doctor", "self_test", "skills_list", "list_plugins"))
        ):
            rc = _ensure_chatgpt_runtime(args)
            if rc != 0:
                return rc

        # --rebuild: force a clean rebuild of the WebUI for updates and exit.
        # With --daemon/--web it rebuilds before serving instead (handled in
        # _run_daemon via the mutual-exclusion gate below falling through).
        if getattr(args, "rebuild", False) and not getattr(args, "daemon", False) and not getattr(args, "web", False):
            _conflicting = []
            for flag in ("target", "mode", "goal", "custom_goal"):
                if getattr(args, flag, "").strip():
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            for flag in (
                "menu",
                "doctor",
                "demo",
                "self_test",
                "skills_list",
                "list_plugins",
                "setup_api_keys",
            ):
                if getattr(args, flag, False):
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            if _eval_active:
                _conflicting.append("--eval")
            if _benchmark_active:
                _conflicting.append("--benchmark")
            if _conflicting:
                ui.error("--rebuild cannot be combined with: " + ", ".join(_conflicting))
                return 2
            return _rebuild_webui(ui)

        # --demon / --daemon / --web: start the local WebUI API server and exit.
        # Checked BEFORE --doctor/--self-test/etc. so the mutual-exclusion
        # gate fires even when one of those flags is also set. --web implies
        # daemon mode and additionally builds/serves/opens the WebUI.
        if getattr(args, "daemon", False) or getattr(args, "web", False):
            _conflicting = []
            for flag in ("target", "mode", "goal", "custom_goal"):
                if getattr(args, flag, "").strip():
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            for flag in (
                "menu",
                "doctor",
                "demo",
                "self_test",
                "skills_list",
                "list_plugins",
                "setup_api_keys",
            ):
                if getattr(args, flag, False):
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            if _eval_active:
                _conflicting.append("--eval")
            if _benchmark_active:
                _conflicting.append("--benchmark")
            if _conflicting:
                ui.error(
                    (
                        "--demon/--daemon/--web cannot be combined with: "
                        if getattr(args, "web", False)
                        else "--demon/--daemon cannot be combined with: "
                    )
                    + ", ".join(_conflicting)
                )
                return 2
            return _run_daemon(args)

        # --doctor: run a self-check and exit. No exploit session starts.
        if args.doctor:
            from tools.doctor import run_doctor

            return run_doctor(args.config, json_output=bool(getattr(args, "json", False)))

        # --export-run: bundle reports/<RUN_ID>/ + run_manifest.json and exit.
        if getattr(args, "export_run", ""):
            from tools.kernel.run_manifest import export_run_bundle

            bundle = export_run_bundle(Path("reports"), str(args.export_run), Path(f"{args.export_run}.zip"))
            print(f"exported {args.export_run} -> {bundle}")
            return 0

        # --self-test: run a safe localhost smoke test and exit.
        if getattr(args, "self_test", False):
            from tools.self_test import run_self_test

            return asyncio.run(run_self_test(args))

        # --eval-list: print the graded-eval oracle targets (id + flag count) and exit.
        if getattr(args, "eval_list", False):
            import json as _json

            for oracle_path in sorted(Path("eval_targets").glob("*.oracle.json")):
                target_id = oracle_path.name.removesuffix(".oracle.json")
                flag_count = 0
                try:
                    oracle = _json.loads(oracle_path.read_text(encoding="utf-8"))
                    target_id = str(oracle.get("target_id") or target_id)
                    flag_count = len(oracle.get("flags") or [])
                except (OSError, ValueError):
                    pass
                print(f"{target_id}\t{flag_count} flags")
            return 0

        # --save-baseline/--check-regression compose with --eval or --benchmark.
        if (
            (getattr(args, "save_baseline", False) or getattr(args, "check_regression", False))
            and getattr(args, "eval", None) is None
            and getattr(args, "benchmark", None) is None
        ):
            ui.error("--save-baseline/--check-regression require --eval or --benchmark.")
            return 2

        # --benchmark / --benchmark-list: the reproducible benchmark suite
        # (tools/benchmark/). A bare --benchmark defaults to the xben suite.
        if getattr(args, "benchmark", None) is not None or getattr(args, "benchmark_list", False):
            from tools.benchmark_cli import run_benchmark_cli

            return run_benchmark_cli(args)

        # --eval: with --target, the legacy single-target benchmark harness;
        # without, the graded eval suite (oracle v2) across all/specified targets.
        if getattr(args, "eval", None) is not None:
            if args.target.strip():
                from tools.eval_harness import run_eval

                return asyncio.run(run_eval(args))
            from tools.eval_harness import check_regression, run_graded_eval, save_baseline

            config = load_config(args.config)
            eval_cfg = (config.get("eval", {}) or {}) if isinstance(config, dict) else {}
            baseline_path = Path(str(eval_cfg.get("baseline_path", "reports/eval/baseline.json")))
            report = asyncio.run(run_graded_eval(list(args.eval) or None, config))
            print(report.render_markdown())
            exit_code = 0
            if getattr(args, "check_regression", False):
                passed, messages = check_regression(
                    report, baseline_path, float(eval_cfg.get("regression_tolerance", 0.05) or 0.05)
                )
                for message in messages:
                    print(message)
                if not passed:
                    exit_code = 1
            if getattr(args, "save_baseline", False):
                save_baseline(report, baseline_path)
            return exit_code

        # --ctf: CTF autopilot with goal-completion detection.
        if getattr(args, "ctf", False):
            from tools.ctf_mode import run_ctf

            return run_ctf(args)

        # --demo: run against a local sandbox target (DVWA-style).
        if args.demo:
            from tools.demo_mode import run_demo

            return run_demo(args)

        # --skills-list: print the read-only runtime-skill catalog and exit.
        if getattr(args, "skills_list", False):
            config = load_config(args.config)
            return print_skills_catalog(config)

        # --list-plugins: print discovered plugins and exit.
        if getattr(args, "list_plugins", False):
            from tools.plugins import list_discovered_plugins

            config = load_config(args.config)
            try:
                from tools.plugins import load_plugins

                load_plugins(config, entry_point_loader=lambda group: [])
            except Exception:  # noqa: BLE001 -- listing must not crash boot
                pass
            plugins = list_discovered_plugins()
            if not plugins:
                ui.info("No plugins discovered.")
                return 0
            ui.info(f"Discovered {len(plugins)} plugin(s):")
            for p in plugins:
                state = "loaded" if p.get("loaded") else "discovered"
                caps = ",".join(p.get("capabilities", []) or []) or "-"
                print(f"  {p['name']} v{p.get('version', '?')} [{state}] caps={caps} - {p.get('description', '')}")
            return 0

        # --menu flag: explicitly force the terminal interactive menu.
        if args.menu:
            from tools.interactive_menu import run_interactive_menu

            return run_interactive_menu()

        # No arguments: launch the WebUI daemon (default interface). --menu
        # still forces the terminal menu; --demon/--daemon give the API alone.
        if len(raw_argv) == 0 and not args.target.strip():
            args.web = True
            return _run_daemon(args)

        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        ui.error("Aborted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
