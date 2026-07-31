"""AI Target Exploitation Engine — autonomous penetration testing AI.

Usage:
    python main.py                          # Interactive mode
    python main.py --target 10.0.0.50 --mode attack --goal backdoor
    python main.py --target 10.0.0.50 --mode recon --goal initial_access
"""

from __future__ import annotations

__version__ = "0.49.12"

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from tools.activity_log import ActivityLog
from tools.attack_ui import get_ui
from tools.goal_engine import GoalEngine, AttackGoal
from tools.goal_suggester import ReconAssessment
from tools.safety_reviewer import SafetyReview
from tools.exploit_agent import (
    ExploitSettings,
    run_exploit_agent,
)
from tools.model_router import build_router, format_model_choice
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.api_key_store import DEFAULT_API_KEY_FILE
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group


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


from tools.skills_cli import (
    _apply_runtime_skill_selection,
    _build_runtime_skill_selection,
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
    mcp_tools_to_ollama,
)

MCP_BOOT_TIMEOUT_SECONDS: float = _DEFAULT_MCP_BOOT_TIMEOUT_SECONDS


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
    _mcp_session.MCP_BOOT_TIMEOUT_SECONDS = MCP_BOOT_TIMEOUT_SECONDS
    _mcp_session.ui = ui
    async with _mcp_session.open_exploit_mcp_session(
        transport=transport,
        config_path=config_path,
        target_ip=target_ip,
        exploit_port=exploit_port,
        workspace=workspace,
        multi_model_enabled=multi_model_enabled,
        active_model_alias=active_model_alias,
        soft_fail=soft_fail,
    ) as session:
        yield session


async def _elapsed_ticker(
    label: str,
    *,
    interval: float = 15.0,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
) -> None:
    _mcp_session.ui = ui
    await _mcp_session._elapsed_ticker(label, interval=interval, heartbeat=heartbeat)


# ---------------------------------------------------------------------------
# Single-model exploit session (legacy compatible)
# ---------------------------------------------------------------------------

from tools import exploit_session as _exploit_session
from tools.swarm_bridge import SwarmMcpBridge


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
    swarm_attach: Callable[[Any, list[dict[str, Any]], Any], None] | None = None,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
) -> dict[str, Any]:
    _exploit_session.ui = ui
    _exploit_session.load_config = load_config
    _exploit_session.open_exploit_mcp_session = open_exploit_mcp_session
    _exploit_session.mcp_tools_to_ollama = mcp_tools_to_ollama
    _exploit_session.run_exploit_agent = run_exploit_agent
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
        swarm_attach=swarm_attach,
        heartbeat=heartbeat,
    )




from tools.cli_exploit_settings import (
    _compute_swarm_timeout,
    build_cli_exploit_settings,
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
    _safety_review_cli.ui = ui
    return await _safety_review_cli.run_safety_review(client, model, result, target_ip, goal)


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
    import json as _json
    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    new_lines = lines[start_lines:] if start_lines <= len(lines) else lines
    calls = 0
    total_tokens = 0
    ctx_values: list[float] = []
    for line in new_lines:
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
            ctx_values.append(float(ctx))
    if not calls:
        return None
    avg_ctx = (sum(ctx_values) / len(ctx_values)) if ctx_values else None
    max_ctx = max(ctx_values) if ctx_values else None
    return {
        "calls": calls,
        "total_tokens": total_tokens,
        "avg_ctx": avg_ctx,
        "max_ctx": max_ctx,
    }


async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
) -> ReconAssessment:
    _recon_assessment_cli.ui = ui
    return await _recon_assessment_cli.run_recon_assessment(
        session=session,
        target_ip=target_ip,
        reports_dir=reports_dir,
    )


def _extract_tool_text(raw: Any) -> str:
    return _recon_assessment_cli._extract_tool_text(raw)



def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"NetAttackAI {__version__}")
    parser.add_argument("--target", default="", help="Target IP address to attack or recon")
    parser.add_argument("--mode", choices=("recon", "attack"), default="", help="recon = gather intel, attack = full exploitation")
    parser.add_argument("--goal", default="", help="Preset goal name (e.g. backdoor, initial_access, privilege_escalation)")
    parser.add_argument("--custom-goal", default="", help="Custom goal description")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--model", default=None, help="Override default model alias (glm/kimi/deepseek/deepseek_flash/minimax)")
    parser.add_argument("--model-strategy", choices=("default", "round-robin", "random", "specific"), default="default",
                        help="How to pick model across targets")
    parser.add_argument("--mcp-transport", choices=("stdio", "http"), default=None,
                        help="MCP transport (ignored on the run path: always forced to http so the target-IP lock reaches the server)")
    parser.add_argument("--http-port", type=int, default=None)
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    parser.add_argument("--setup-api-keys", action="store_true", help="Prompt for provider API keys and save them to secr.json")
    parser.add_argument("--api-key-file", type=Path, default=DEFAULT_API_KEY_FILE, help="Local JSON file for saved provider API keys")
    parser.add_argument("--no-api-key-prompt", action="store_true", help="Skip the interactive startup API-key prompt")
    parser.add_argument("--plain", action="store_true", help="Disable color output")
    parser.add_argument("--menu", action="store_true", help="Force interactive menu mode even with other args")
    # Swarm / reasoning / adaptive exploit flags
    parser.add_argument("--swarm", action="store_true", help="Enable multi-agent swarm mode")
    parser.add_argument("--critic", action="store_true", help="Enable critic agent pre-approval (requires --swarm)")
    parser.add_argument("--reflection", action="store_true", help="Enable reflection agent (requires --swarm)")
    parser.add_argument("--adaptive-exploits", action="store_true", help="Enable adaptive exploit generation with mutation")
    parser.add_argument("--long-session", dest="long_session", action="store_true",
                        help="Raise context window (num_ctx), LLM call timeout, round/command/duration budgets, "
                             "and the swarm cap for a multi-hour attack run; checkpoints compacted messages for crash-safe resume")
    parser.add_argument("--multi-model-consult", dest="multi_model_consult", action="store_true", default=None,
                        help="Allow the agent to ask configured peer models for advisory help")
    parser.add_argument("--no-multi-model-consult", dest="multi_model_consult", action="store_false",
                        help="Disable peer-model consultation for this run")
    parser.add_argument("--observer-mode", choices=("heuristic", "llm", "hybrid"), default="hybrid", help="Observer mode for fact extraction")
    parser.add_argument("--recon-first", action="store_true", default=None,
                        help="Force recon-first mode: scan target, suggest rated goals, then ask for goal selection")
    parser.add_argument("--no-recon-first", action="store_false", dest="recon_first",
                        help="Skip recon-first mode; go directly to goal selection")
    # Phase 2 power-ups: operational flags
    parser.add_argument("--doctor", action="store_true",
                        help="Run a self-check (Python, nmap, Ollama, config) and exit")
    parser.add_argument("--demo", action="store_true",
                        help="Run against a local sandbox target (DVWA-style)")
    parser.add_argument("--resume", type=str, default="",
                        help="Resume a prior run by run_id or session_id")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON to stdout where supported")
    parser.add_argument("--quiet", action="store_true",
                        help="Reduce output to warnings/errors only")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose debug output")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the ready-to-begin confirmation gate (use with caution)")
    parser.add_argument("--self-test", action="store_true",
                        help="Run a safe localhost smoke test against 127.0.0.1 and exit")
    parser.add_argument("--eval", action="store_true",
                        help="Run the eval/benchmark harness against --target and write reports/eval/<run_id>/")
    parser.add_argument("--ultrathink", action="store_true",
                        help="Enable deep reasoning mode: verbose chain-of-thought and frequent reflection")
    # ── Runtime skills flags (advisory prompt-context layer) ──
    parser.add_argument("--skills", choices=("on", "off", "hints", "lookup"), default=None,
                        help="Override runtime-skills behavior for this run: on=startup context injected, "
                             "hints=hints only (default), lookup=MCP tools only, off=skills disabled")
    parser.add_argument("--skills-list", action="store_true",
                        help="Print the runtime-skill catalog and exit (read-only)")
    parser.add_argument("--skills-include", action="append", default=None, metavar="NAME",
                        help="Force-include a skill by name for this run (sticky across re-selection). Repeatable.")
    parser.add_argument("--skills-exclude", action="append", default=None, metavar="NAME",
                        help="Exclude a skill by name for this run. Repeatable.")
    parser.add_argument("--no-skills-reselect", action="store_true",
                        help="Disable mid-run skill re-selection for this run")
    # ── Plugin ecosystem flags ──
    parser.add_argument("--list-plugins", dest="list_plugins", action="store_true",
                        help="Print discovered plugins (name/version/capabilities/loaded) and exit")
    parsed = parser.parse_args(argv)
    return parsed


from tools.resume_state import _load_resume_state




async def async_main(args: argparse.Namespace) -> int:
    # --debug: surface a visible signal and flip the env var that downstream
    # modules already check. Belt-and-suspenders: the env var is what most code
    # consumes; the info line is for the operator running the session.
    if getattr(args, "debug", False):
        os.environ["AI_NMAP_DEBUG"] = "1"
        ui.info("Debug mode enabled (verbose logging; tracebacks will be printed to stderr on error).")

    if getattr(args, "ultrathink", False):
        ui.info("ULTRATHINK mode enabled: verbose chain-of-thought and frequent reflection.")

    config_path = args.config
    config = load_config(config_path)
    # Apply --skills* CLI overrides to the in-memory skills config before any
    # skill selection is built. Advisory only (hints/selection, never
    # permission/scope/audit).
    config = apply_skills_cli_overrides(config, args)
    # Load plugins once during boot, BEFORE the MCP exploit server is created
    # so plugin-contributed attack modules + MCP tool factories are registered
    # before create_mcp_server runs. Best-effort: a plugin load failure never
    # blocks boot.
    try:
        from tools.plugins import load_plugins
        load_plugins(config)
    except Exception as exc:  # noqa: BLE001 -- plugin load must not block boot
        ui.info(f"Plugin load skipped: {type(exc).__name__}: {exc}")
        if getattr(args, "debug", False):
            ui.info(traceback.format_exc().strip())
    # T1.8: API-key bootstrap runs ONCE, in main() before this coroutine is
    # dispatched (prompt=True for the interactive menu path, prompt=False for
    # the async run path). The second prompt=False call that used to live here
    # just reloaded the same store and double-printed "Loaded provider API
    # key(s) ...". main() reaches async_main only after that call, so the env
    # is already populated; tests that invoke async_main directly use an empty
    # temp key store + no_api_key_prompt=True, so dropping this call is a
    # no-op for them.
    multi_model_cfg = config.get("multi_model", {}) or {}
    if getattr(args, "multi_model_consult", None) is None:
        args.multi_model_consult = bool(multi_model_cfg.get("enabled", False))

    ui.banner()
    ui.info(f"Config: {config_path} ({'found' if config_path.exists() else 'not found; using defaults'})")

    # Build router and pick active client
    ollama_host = config.get("ollama", {}).get("host", "http://localhost:11434")
    _long_cfg = config.get("long_session", {}) or {}
    _ls_active = bool(getattr(args, "long_session", False) or _long_cfg.get("enabled", False))
    _req_timeout = float(_long_cfg.get("request_timeout_seconds")) if (_ls_active and _long_cfg.get("request_timeout_seconds")) else None
    router = build_router(
        config.get("models", {}).get("registry"),
        host=ollama_host,
        request_timeout_seconds=_req_timeout,
    )

    interactive_session = not args.target.strip()
    if interactive_session:
        try:
            args = await ui.ask_advanced_settings(router, args)
            ui.plain = bool(getattr(args, "plain", False) or getattr(args, "quiet", False) or getattr(args, "json", False))
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # Determine model alias
    model_alias = args.model or config.get("models", {}).get("default_alias", "glm")
    if model_alias not in router._clients:
        # If user passed a raw model name that is not an alias, treat it as a custom alias
        # pointing to itself
        try:
            model_client = router.get_client(model_alias)
        except KeyError:
            ui.warning(
                f"Unknown model alias {model_alias!r}; registering it as a custom "
                f"alias pointing at itself."
            )
            from tools.model_router import _build_model_client
            router.register(model_alias, _build_model_client(
                model_alias, host=ollama_host, request_timeout_seconds=_req_timeout,
            ))
            model_client = router.get_client(model_alias)
    else:
        model_client = router.get_client(model_alias)

    # Always use the local HTTP MCP server. This is fixed even for
    # non-interactive invocations or callers that provide --mcp-transport.
    if args.mcp_transport == "stdio":
        ui.warning(
            "--mcp-transport stdio requested; forcing http so the target-IP "
            "lock reaches the server."
        )
    args.mcp_transport = "http"
    mcp_transport = args.mcp_transport
    http_port = int(args.http_port or config.get("mcp", {}).get("http_port", 8001))
    exploit_port = http_port

    reports_dir = args.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    resume_key = (getattr(args, "resume", "") or "").strip()
    # M21: restored assessment + chosen goal for the --resume path. Stays
    # ``None`` for fresh runs and resume-misses; consumed later to override
    # ``recon_first`` / ``assessment`` / ``goal`` so the resumed run reuses the
    # saved state instead of re-running recon and re-asking for a goal.
    _resume_state: tuple[ReconAssessment, str, str] | None = None
    match: Path | None = None
    if resume_key:
        # --resume: find the existing run subdir and append to it instead of
        # minting a new timestamped directory. Match either the subdir name
        # (typical run_id) or the `session_id` field inside session_state.json.
        # Tier 1.3: the historical matcher read `session.json`, but NOTHING in
        # the codebase ever wrote that file, so the session_id branch was dead
        # and only the subdir-name match ever worked. We now write
        # `session_state.json` at run start (below), so the session_id match is
        # real. Legacy `session.json` is still read for back-compat with any
        # pre-1.3 run dir that happened to have one.
        match: Path | None = None
        for child in sorted(reports_dir.iterdir(), reverse=True):
            if not child.is_dir():
                continue
            if child.name == resume_key:
                match = child
                break
            for sj_name in ("session_state.json", "session.json"):
                sj = child / sj_name
                if sj.exists():
                    try:
                        if json.loads(sj.read_text(encoding="utf-8")).get("session_id") == resume_key:
                            match = child
                            break
                    except (OSError, ValueError, KeyError):
                        continue
            if match is not None:
                break
        if match is not None:
            run_id = match.name
            reports_dir = match
            ui.info(f"Resuming run_id={run_id} at {reports_dir}")
            # M21: reload the saved recon assessment + chosen goal (if any) so
            # the resumed run reuses them and skips recon-first.
            _resume_state = _load_resume_state(reports_dir, args)
            if _resume_state is not None:
                ui.info(
                    "Resuming with saved recon assessment and chosen goal "
                    f"('{_resume_state[1] or 'unchanged'}')."
                )
        else:
            ui.warning(f"--resume key '{resume_key}' not found under {reports_dir}; minting a fresh run_id.")
            run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            reports_dir = reports_dir / run_id
            reports_dir.mkdir(parents=True, exist_ok=True)
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        reports_dir = reports_dir / run_id
        reports_dir.mkdir(parents=True, exist_ok=True)

    # Tier 1.3: write session_state.json at run start so a future
    # `--resume <session_id>` can re-find THIS run by its session_id even after
    # the timestamped dir name is forgotten. On a successful resume we DON'T
    # overwrite the existing file (it already records the session we're
    # reattaching to); we only mint one for fresh runs and for resume-misses
    # that fell back to a fresh run_id.
    if not (resume_key and match is not None):
        try:
            (reports_dir / "session_state.json").write_text(
                json.dumps(
                    {
                        "session_id": run_id,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    # --json: announce that a structured artifact will be written at session end.
    if getattr(args, "json", False):
        ui.info(f"JSON output mode enabled. A structured run.json will be written to {reports_dir / 'run.json'}.")

    # Determine target
    target_ip = args.target.strip()
    if not target_ip:
        try:
            target_ip = ui.ask_target()
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # Validate IP
    try:
        target_addr = ipaddress.ip_address(target_ip)
    except ValueError:
        ui.error(f"Invalid IP address: {target_ip}")
        return 1

    # A target entered through Start New Session is an operator-approved asset.
    # Persist it before any assessment work begins so the current and future
    # sessions both enforce the same explicit allowlist.
    if interactive_session:
        try:
            added_to_allowlist = _config_cli.add_target_to_allowlist(config_path, target_ip)
        except (OSError, ValueError) as exc:
            ui.error(f"Could not save {target_ip} to the config allowlist: {exc}")
            return 1

        # Keep the in-memory config synchronized with the persisted allowlist
        # too. This matters for equivalent IPv6 spellings, where a string
        # comparison alone would otherwise make this session see a duplicate.
        persisted_config = _config_cli.load_config(config_path)
        persisted_exploit = persisted_config.get("exploit", {})
        persisted_allowed_targets = persisted_exploit.get("allowed_targets", [])
        exploit_config = config.setdefault("exploit", {})
        exploit_config["allowed_targets"] = list(persisted_allowed_targets)
        normalized_target = str(target_addr)
        if added_to_allowlist:
            ui.status(f"Saved {normalized_target} to {config_path} exploit.allowed_targets.")

    if not target_addr.is_private:
        ui.status("WARNING: Target is a PUBLIC IP. Ensure you OWN this infrastructure.")

    # Determine mode
    mode = args.mode.strip().lower()
    if mode not in ("recon", "attack"):
        try:
            mode = ui.ask_mode()
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # Determine goal
    goal_engine = GoalEngine()
    goal_name = args.goal.strip().lower()
    custom_text = args.custom_goal.strip()

    # Decide whether to run recon-first
    # recon-first if: explicitly requested, OR no goal provided and not explicitly disabled
    recon_first = args.recon_first
    if recon_first is None:
        recon_first = not goal_name and not custom_text

    # M21: a resumed run with a saved assessment reuses it — skip recon-first
    # so the recon-first block (which would re-scan and re-ask for a goal) is
    # bypassed and the saved assessment is reused.
    if _resume_state is not None:
        recon_first = False

    # ``assessment`` is referenced by the post-recon path (``run_exploit_session``)
    # regardless of whether we entered the recon-first branch, so it must be
    # bound unconditionally. The recon-first block rebinds it to a real value;
    # all other branches leave it ``None`` and the post-recon code passes
    # ``None`` through to ``run_exploit_session``. On a resumed run the saved
    # assessment is pre-loaded here.
    assessment: ReconAssessment | None = None
    if _resume_state is not None:
        assessment = _resume_state[0]

    # Determine risk profile for goal compatibility filtering
    risk_profile = "high_authorized_testing" if mode == "attack" else "standard_authorized"

    if recon_first:
        # ── Recon-First Mode: scan target, suggest rated goals, let user pick ──
        ui.status("RECON-FIRST MODE: Scanning target before goal selection...")
        ui.divider()

        # Open a temporary MCP session for recon only
        workspace = Path("exploit_workspace")
        workspace.mkdir(parents=True, exist_ok=True)

        # The recon-first block used to be unwrapped: any MCP stdio death or
        # ``BaseExceptionGroup`` from a recon tool (e.g. ``check_os``) would
        # propagate out of ``async_main`` and surface as a bare
        # ``Session aborted.`` from the interactive menu. Now we open the
        # session with ``soft_fail=True``: the context manager returns
        # ``None`` instead of raising if the MCP server fails to boot or the
        # session dies mid-recon, and the inner spinners print ``[WARN]``
        # (yellow) instead of ``[ERROR]`` (red). The outer ``try/except``
        # below is kept as defence-in-depth in case ``run_recon_assessment``
        # itself raises something unexpected.
        try:
            async with open_exploit_mcp_session(
                transport=mcp_transport,
                config_path=args.config,
                target_ip=target_ip,
                exploit_port=exploit_port,
                workspace=workspace,
                multi_model_enabled=bool(getattr(args, "multi_model_consult", False)),
                active_model_alias=model_alias,
                soft_fail=True,
            ) as recon_session:
                if recon_session is None:
                    # ``open_exploit_mcp_session`` already emitted a single
                    # ``[WARN]`` line explaining the failure. Build a
                    # minimal UNKNOWN assessment so the operator can still
                    # select a goal. The goal engine degrades gracefully
                    # when the recon payload is empty.
                    ui.info(
                        "MCP recon unavailable — falling back to UNKNOWN OS verdict; "
                        "goal selection will be limited."
                    )
                    assessment = ReconAssessment(
                        target_ip=target_ip,
                        os_verdict="UNKNOWN",
                        services=[],
                        cve_findings=[],
                    )
                else:
                    # NOTE: ``open_exploit_mcp_session`` already calls
                    # ``session.initialize()`` inside the context manager. Calling
                    # it again here used to send a duplicate ``InitializeRequest``
                    # and was the seed of the cascade: a subsequent tool failure
                    # would unwind both spinners (Booting + Probing OS), escape
                    # this block, and abort the whole session.
                    assessment = await run_recon_assessment(
                        session=recon_session,
                        target_ip=target_ip,
                        reports_dir=reports_dir,
                    )
        except _EXC_GROUP_CATCH as exc:
            # Defence-in-depth: ``run_recon_assessment`` catches per-tool
            # failures itself, but a bug or unexpected exception class
            # (e.g. ``asyncio.CancelledError``) could still escape. The
            # soft-fail path above already handles the common case; this
            # branch is only for surprises. Write a post-mortem and fall
            # back so the operator can still pick a goal.
            log_path = reports_dir / "recon_first_error.log"
            try:
                log_path.write_text(
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                    encoding="utf-8",
                )
            except OSError:
                pass
            ui.warning(f"Recon-first session hit an unexpected error: {exc}")
            ui.info(f"  See {log_path} for the full traceback.")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            assessment = ReconAssessment(
                target_ip=target_ip,
                os_verdict="UNKNOWN",
                services=[],
                cve_findings=[],
            )
        # Defensive: assessment is always set above, but be explicit.
        if assessment is None:
            assessment = ReconAssessment(
                target_ip=target_ip,
                os_verdict="UNKNOWN",
                services=[],
                cve_findings=[],
            )

        # ── Display recon summary ──
        ui.display_recon_assessment(assessment)

        # ── Generate goal suggestions ──
        suggestions = goal_engine.suggest_goals(assessment, risk_profile)

        # ── Persist suggestions ──
        suggestions_path = reports_dir / "goal_suggestions.json"
        suggestions_path.write_text(
            json.dumps([s.to_dict() for s in suggestions], indent=2),
            encoding="utf-8",
        )
        ui.info(f"Goal suggestions saved to: {suggestions_path}")

        # ── Display and let user pick ──
        ui.display_goal_suggestions(suggestions)

        try:
            selected_name, selected_custom = ui.ask_goal_from_suggestions(suggestions)
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

        if selected_custom:
            goal = goal_engine.get("custom", selected_custom, risk_profile=risk_profile)
        else:
            # Check if selected goal is AI-generated (not in presets)
            selected_sg = next((s for s in suggestions if s.name == selected_name), None)
            if selected_sg and getattr(selected_sg, 'is_ai_generated', False):
                goal = goal_engine.get("custom", selected_sg.description, risk_profile=risk_profile)
                goal.name = selected_sg.name  # Override name for reporting
            else:
                goal = goal_engine.get(selected_name, risk_profile=risk_profile)

        # Save chosen goal to assessment
        assessment_path = reports_dir / "recon_assessment.json"
        if assessment_path.exists():
            data = json.loads(assessment_path.read_text(encoding="utf-8"))
            data["chosen_goal"] = goal.name
            data["chosen_goal_description"] = goal.description
            assessment_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    elif custom_text:
        goal = goal_engine.get("custom", custom_text, risk_profile=risk_profile)
    elif goal_name and goal_engine.is_preset(goal_name):
        goal = goal_engine.get(goal_name, risk_profile=risk_profile)
    else:
        # Interactive selection (no recon-first)
        presets = goal_engine.list_presets()
        try:
            selected = ui.ask_preset_goal(presets)
            if selected == "custom":
                custom_text = ui.ask_custom_goal()
                goal = goal_engine.get("custom", custom_text or "No custom goal provided.", risk_profile=risk_profile)
            else:
                goal = goal_engine.get(selected, risk_profile=risk_profile)
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # M21: on a resumed run, the operator's previously chosen goal (saved into
    # recon_assessment.json by the recon-first block) takes precedence over a
    # freshly resolved one — it's the commitment they made on the prior run.
    # Falls back to args.goal/args.custom_goal when no chosen_goal was saved
    # (e.g. a run that was started without recon-first).
    if _resume_state is not None:
        _rg_name, _rg_desc = _resume_state[1], _resume_state[2]
        if _rg_name:
            _rg_risk = "high_authorized_testing" if mode == "attack" else "standard_authorized"
            goal = goal_engine.get(_rg_name, _rg_desc, risk_profile=_rg_risk)

    # Surface the resolved reports paths so the user can find their session later.
    # The parent is whatever they passed via --reports-dir; the subdir is the
    # per-run timestamp (or the resumed run_id). Print before the gate so they
    # can see exactly where output is going before confirming.
    if not getattr(args, "resume", ""):
        ui.info(f"Reports root: {args.reports_dir}")
        ui.info(f"This run will write to: {reports_dir}  (run_id={run_id})")

    ui.status(f"Target: {target_ip}")
    ui.status(f"Mode: {mode}")
    ui.status(f"Goal: {goal.name}")
    ui.divider()

    # -----------------------------------------------------------------------
    # Ready-to-begin gate: print a one-screen summary of every setting that
    # will be used, then ask the operator to confirm. In this lab build the
    # attack path is unrestricted-but-target-locked (config.yaml defaults
    # exploit.permission: full_access + attack_mode: true; the target-IP lock
    # is enforced at the MCP tool layer), so this gate is the last operator
    # confirmation before the agent starts hammering the wire. `--yes` skips
    # the gate for scripted/CI runs.
    # -----------------------------------------------------------------------
    # Peek at the config blocks we'll consume below so the summary reflects
    # the *effective* settings (config + CLI overrides). Kept local so the
    # original "Build exploit settings" block can still re-read them.
    _gate_exploit_cfg = config.get("exploit", {}) or {}
    _gate_swarm_cfg = config.get("swarm", {}) or {}
    transport_summary = mcp_transport
    if mcp_transport == "http":
        transport_summary = f"http on port {http_port}"
    skill_selection = _build_runtime_skill_selection(
        config=config,
        goal=goal,
        mode=mode,
        assessment=assessment if (recon_first or _resume_state is not None) else None,
    )

    # Build exploit settings BEFORE the ready-to-begin gate so the action
    # budget can be shown in the run summary — the operator should confirm
    # with the upper bound (commands/rounds/duration) visible, not learn it
    # only after committing. This is a pure data build (no I/O, no MCP), so
    # constructing it pre-gate is free even if the operator aborts.
    exploit_settings = build_cli_exploit_settings(
        mode=mode,
        target_ip=target_ip,
        goal=goal,
        config=config,
        adaptive_exploits=bool(args.adaptive_exploits),
        swarm=bool(args.swarm),
        critic=bool(args.critic),
        reflection=bool(args.reflection),
        multi_model_enabled=bool(getattr(args, "multi_model_consult", False)),
        observer_mode=args.observer_mode,
        ultrathink=bool(getattr(args, "ultrathink", False)),
        debug=bool(getattr(args, "debug", False)),
        long_session=bool(getattr(args, "long_session", False)),
    )
    _apply_runtime_skill_selection(exploit_settings, skill_selection, config=config, goal=goal, mode=mode)

    ui.divider()
    ui.status("Run summary:")
    ui.status(f"  Config:      {config_path}")
    ui.status(f"  Reports root:{args.reports_dir}")
    ui.status(f"  Run ID:      {run_id}")
    ui.status(f"  Target:      {target_ip}")
    ui.status(f"  Mode:        {mode}")
    ui.status(f"  Goal:        {goal.name}")
    _models_cfg = config.get("models", {}) if isinstance(config, dict) else {}
    ui.status(
        f"  Model:       {format_model_choice(model_alias, registry=_models_cfg.get('registry', {}), registry_info=_models_cfg.get('info', {}))}"
    )
    ui.status(f"  Transport:   {transport_summary}")
    ui.status(f"  Reports:     {reports_dir}")
    permission_effective = str(_gate_exploit_cfg.get("permission", "read_only"))
    attack_mode_effective = mode == "attack"
    swarm_effective = bool(args.swarm or _gate_swarm_cfg.get("enabled", False))
    multi_model_effective = bool(getattr(args, "multi_model_consult", False))
    destructive_run = permission_effective == "full_access" and mode == "attack"
    if destructive_run:
        ui.status(
            f"  {ui._c('red')}[!] DESTRUCTIVE: permission=full_access, attack_mode={attack_mode_effective}{ui._c('reset')}"
        )
    ui.status(f"  Permission:  {permission_effective}")
    ui.status(f"  Attack mode: {attack_mode_effective}")
    ui.status(f"  Swarm:       {swarm_effective}")
    ui.status(f"  Peer models: {multi_model_effective}")
    # Action budget: show the upper bound before the operator commits.
    try:
        ui.status(
            f"  Budget:      {getattr(exploit_settings, 'attack_max_commands', 'n/a')} commands, "
            f"{getattr(exploit_settings, 'attack_max_rounds', 'n/a')} rounds, "
            f"{getattr(exploit_settings, 'attack_max_duration_minutes', 'n/a')} min."
        )
    except Exception:
        pass
    ui.skills([
        f"{activation.name} - {activation.reason}"
        for activation in skill_selection.activations
    ])
    if skill_selection.errors:
        ui.warning(f"Skill registry loaded with {len(skill_selection.errors)} warning(s):")
        for err in skill_selection.errors:
            ui.warning(f"  - {err}")
    ui.divider()

    if not getattr(args, "yes", False):
        try:
            if destructive_run:
                proceed = await ui.ask_destructive_confirm(str(target_ip))
            else:
                proceed = await ui.ask_confirm("Proceed? [Y/n]", default=True)
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1
        if not proceed:
            ui.info("Aborted by user.")
            return 0

    # exploit_settings was built before the gate so the budget could be shown
    # in the run summary. Only exploit_cfg (used below for max_rounds) is
    # re-read here; swarm_cfg was dead and removed.
    exploit_cfg = config.get("exploit", {}) or {}

    # Activity log
    activity = ActivityLog(reports_dir, plain=args.plain)
    activity.log("info", f"Session started: {mode} against {target_ip} with goal {goal.name}")

    # -----------------------------------------------------------------------
    # Phase 1.2: optionally run the AgentLoop swarm alongside the exploit
    # session. The swarm brings in the 6 specialist agents (recon, vuln,
    # exploit, post_exploit, critic, reflection), the shared blackboard,
    # and structured reasoning. It runs in a background task so the
    # main exploit session is unaffected if the swarm hits an error.
    # -----------------------------------------------------------------------
    swarm_task: asyncio.Task[Any] | None = None
    # Tier 5: the swarm shares run_exploit_session's single MCP ClientSession
    # via this bridge (constructed unconditionally; attach() is a no-op until
    # run_exploit_session calls swarm_attach with the live session). When
    # --swarm is off, the bridge stays unattached and is never used.
    swarm_bridge = SwarmMcpBridge()
    swarm_loop: Any = None
    if args.swarm:
        try:
            from agent_loop import AgentLoop

            swarm_mission_config = {
                "program_name": f"Swarm: {target_ip}",
                "objective": goal.description or f"Swarm against {target_ip}",
                "risk_profile": "high_authorized_testing" if mode == "attack" else "standard_authorized",
                "allowed_assets": [str(target_ip)],
                "disallowed_assets": [],
                "forbidden_actions": [
                    "denial_of_service", "social_engineering", "physical_attack"
                ],
                "testing_modes": ["recon", "test", "exploit", "report"] if mode == "attack" else ["recon", "analysis", "report"],
                "rate_limits": {"default_requests_per_second": 2, "max_concurrent_requests": 3},
                "accounts": [],
                "use_swarm": True,
                "critic_enabled": bool(args.critic),
                "reflection_enabled": bool(args.reflection),
                "adaptive_exploits_enabled": bool(args.adaptive_exploits),
                "reflection_every_n_actions": 10,
                "attack_max_rounds": int(exploit_cfg.get("max_rounds", 30)),
            }
            swarm_workspace = reports_dir.parent / "swarm_workspace"
            swarm_workspace.mkdir(parents=True, exist_ok=True)
            swarm_loop = AgentLoop(
                mission_config=swarm_mission_config,
                workspace_root=swarm_workspace,
                # Tier 5: real dispatch. tool_executor is SwarmMcpBridge.dispatch
                # -- it gates through ExploitPolicy.approve_action and then calls
                # session.call_tool on the live MCP ClientSession that
                # run_exploit_session opens (the bridge is attached from there
                # via the swarm_attach callback). Recon-mode tool_router calls
                # now actually execute; until attach() runs, dispatch returns a
                # "BLOCKED: bridge not attached" marker (the session is not yet
                # open), which the agent loop treats as a denied tool call.
                tool_executor=swarm_bridge.dispatch,
                console_ui=ui,
                state_dir=swarm_workspace,
            )
            # Tier 5: populate the swarm context's model_client (previously always
            # None, which kept ExploitAgent Path A disabled). The bridge's
            # mcp_session / exploit_tools_schemas / main_loop are set later by
            # the swarm_attach callback (they are not available until
            # run_exploit_session opens the MCP session).
            try:
                swarm_loop.set_model_client(model_client, model_alias)
            except Exception as exc:  # noqa: BLE001
                ui.warning(f"swarm set_model_client failed: {exc}")

            async def _run_swarm() -> dict[str, Any]:
                try:
                    # M20: dispatch on mode. Attack mode runs the autonomous
                    # campaign (async, deep recon → chained exploit paths) via
                    # ``run_autonomous_campaign``; recon mode runs the
                    # synchronous research loop in a worker thread as before.
                    if mode == "attack":
                        return await swarm_loop.run_autonomous_campaign([target_ip])
                    max_cycles = int(exploit_cfg.get("max_rounds", 30))
                    return await asyncio.to_thread(swarm_loop.run, max_cycles)
                except _EXC_GROUP_CATCH as exc:
                    ui.error(f"Swarm campaign error: {exc}")
                    return {"error": str(exc)}

            swarm_task = asyncio.create_task(_run_swarm())
            ui.info(
                f"Swarm mode ENABLED "
                f"(critic={bool(args.critic)}, "
                f"reflection={bool(args.reflection)}, "
                f"adaptive_exploits={bool(args.adaptive_exploits)})."
            )
        except _EXC_GROUP_CATCH as exc:
            ui.error(f"Failed to start swarm: {exc}")
            swarm_task = None

    # -----------------------------------------------------------------------
    # Run session
    # -----------------------------------------------------------------------
    try:
        # The action budget was already shown in the ready-to-begin gate above
        # (before the operator confirmed), so it is not re-printed here.
        # Snapshot the LLM-usage log line count so the end-of-run telemetry line
        # reports THIS run's model calls, not the cumulative all-history file
        # (model_router appends every chat to one shared llm_usage.jsonl).
        _telemetry_start_lines = _llm_usage_line_count()
        # Tier 5: closure run_exploit_session calls right after it opens the MCP
        # session, to attach the live session + tool schemas + exploit policy to
        # the swarm bridge AND populate the swarm context (mcp_session /
        # exploit_tools_schemas / main_loop) so ExploitAgent Path A can run its
        # run_exploit_agent coroutine on the main loop instead of a fresh one.
        def _swarm_attach(session: Any, schemas: list[dict[str, Any]], policy: Any) -> None:
            main_loop = asyncio.get_running_loop()
            swarm_bridge.attach(session, schemas, policy, loop=main_loop)
            if swarm_loop is not None:
                ctx = getattr(getattr(swarm_loop, "_swarm", None), "_context", None)
                if isinstance(ctx, dict):
                    ctx["mcp_session"] = session
                    ctx["exploit_tools_schemas"] = schemas
                    ctx["main_loop"] = main_loop

        # Shared heartbeat so the sibling ticker reports round/action/phase,
        # not just elapsed time. One holder, passed to both the ticker and the
        # session; the loop updates it each round (single event loop, no lock).
        _heartbeat = _mcp_session._RunHeartbeat()
        ticker = asyncio.create_task(_elapsed_ticker("Exploit agent", heartbeat=_heartbeat))
        try:
            result = await run_exploit_session(
                client=model_client,
                model=model_alias,
                target_ip=target_ip,
                mode=mode,
                goal=goal,
                exploit_settings=exploit_settings,
                config_path=args.config,
                mcp_transport=mcp_transport,
                exploit_port=exploit_port,
                reports_dir=reports_dir,
                # M21: pass the restored assessment on the resume path too, not
                # just on recon-first, so run_exploit_session can reuse it.
                assessment=assessment if (recon_first or _resume_state is not None) else None,
                # Tier 5: hand the live MCP session to the --swarm bridge.
                swarm_attach=_swarm_attach if args.swarm else None,
                heartbeat=_heartbeat,
            )
        finally:
            ticker.cancel()
            try:
                await asyncio.wait_for(ticker, timeout=0.1)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        ui.divider()
        ui.success(f"Session complete. {result.get('total_actions', 0)} actions executed.")
        # T1.10: on-screen recap reusing keys already in the result dict. The
        # workspace/audit paths used to be printed here too — they move to the
        # consolidated "Artifacts written:" block at the end of the session.
        ui.status(f"Goal:    {goal.name}")
        ui.status(f"Target:  {target_ip}")
        ui.status(f"Mode:    {mode}")
        ui.status(f"Actions: {result.get('total_actions', 0)}")
        _outcome = result.get("outcome_summary") if isinstance(result, dict) else None
        if _outcome:
            ui.status(f"Blocked/thrash: {_outcome}")
        _tel = _run_telemetry(_telemetry_start_lines)
        if _tel:
            _ctx_part = ""
            if _tel["avg_ctx"] is not None:
                _ctx_part = f" (avg ctx {_tel['avg_ctx']:.0f}%, max {_tel['max_ctx']:.0f}%)" if _tel["max_ctx"] is not None else f" (avg ctx {_tel['avg_ctx']:.0f}%)"
            ui.info(f"Model usage: {_tel['total_tokens']:,} tokens across {_tel['calls']} calls{_ctx_part}")
        final_skills = result.get("active_skills") or exploit_settings.target_context.get("active_skills", [])
        if final_skills:
            ui.skills([
                f"{item.get('name', 'unknown')} - {item.get('reason', 'selected')}"
                for item in final_skills
                if isinstance(item, dict)
            ])

        # Safety review after recon
        if mode == "recon":
            try:
                review = await run_safety_review(model_client, model_alias, result, target_ip, goal)
                # Render the structured concerns / recommended-next-steps (the
                # bare "passed/flagged" lines dropped that detail). The reviewer
                # module itself is untouched — we only consume its return value
                # via the already-built AttackUi.display_safety_review renderer.
                ui.display_safety_review(review)
                if review.safe_to_proceed:
                    ui.status("You can run again with --mode attack to exploit this target.")
                else:
                    ui.status("Safety review flagged concerns. Review before attacking.")
            except _EXC_GROUP_CATCH as exc:
                log_path = reports_dir / "safety_review_error.log"
                try:
                    log_path.write_text(
                        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                ui.error(f"Safety review failed: {exc}")
                ui.error(f"  See {log_path} for the full traceback.")
                if getattr(args, "debug", False):
                    traceback.print_exc()

        # Write simple summary report
        summary_path = reports_dir / "session_summary.md"
        summary_lines = [
            f"# Session Summary — {target_ip}",
            "",
            f"- **Date**: {datetime.now(timezone.utc).isoformat()}",
            f"- **Target**: {target_ip}",
            f"- **Mode**: {mode}",
            f"- **Goal**: {goal.name}",
            f"- **Goal Description**: {goal.description}",
            f"- **Actions Executed**: {result.get('total_actions', 0)}",
            f"- **Workspace**: {result.get('workspace', 'unknown')}",
            f"- **Audit trail**: {result.get('audit_path', 'unknown')}",
        ]
        # Per-run model usage (tokens/calls/context%) — same delta math as the
        # console telemetry line, persisted for the record.
        _summary_tel = _run_telemetry(_telemetry_start_lines)
        if _summary_tel:
            _ctx = ""
            if _summary_tel["avg_ctx"] is not None:
                _ctx = f", avg ctx {_summary_tel['avg_ctx']:.0f}%"
            summary_lines.append(
                f"- **Model usage**: {_summary_tel['total_tokens']:,} tokens across {_summary_tel['calls']} calls{_ctx}"
            )
        _summary_skills = result.get("active_skills") or []
        if _summary_skills:
            _skill_names = ", ".join(
                str(s.get("name", "unknown")) for s in _summary_skills if isinstance(s, dict)
            )
            summary_lines.append(f"- **Active skills**: {_skill_names}")
        _summary_outcome = result.get("outcome_summary")
        if _summary_outcome:
            summary_lines.append(f"- **Blocked/thrash summary**: {_summary_outcome}")
        # Swarm campaign tallies (only present for --swarm runs).
        _sw = result.get("swarm_result")
        if isinstance(_sw, dict) and _sw.get("tasks_completed") is not None:
            summary_lines.extend([
                "",
                "## Swarm",
                "",
                f"- **Completed**: {_sw.get('tasks_completed', 0)}",
                f"- **Blocked**: {_sw.get('tasks_blocked', 0)}",
                f"- **Failed**: {_sw.get('tasks_failed', 0)}",
                f"- **Report-ready findings**: {_sw.get('findings_report_ready', 0)}",
            ])
        summary_lines.extend([
            "",
            "## Results",
            "",
            "See the exploit workspace for full logs, scripts, and audit trails.",
            "",
        ])
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
        # T1.11: the "Summary written to:" line used to print here; it now
        # appears once in the consolidated "Artifacts written:" block at the
        # end of the session (alongside the other artifact paths).

        # Structured JSON artifact: makes the session consumable by downstream
        # tooling. v1 just dumps the result dict; richer schema can come later.
        # Skip silently if the session didn't produce a result dict.
        if isinstance(result, dict):
            run_json_path = reports_dir / "run.json"
            try:
                run_json_path.write_text(
                    json.dumps(result, indent=2, default=str),
                    encoding="utf-8",
                )
                # T1.11: the "Run JSON written to:" line used to print here
                # (only under --json); it now appears once in the consolidated
                # "Artifacts written:" block at the end of the session.
            except OSError as exc:
                ui.warning(f"Could not write run.json: {exc}")

        # Phase 1.2: if a swarm task is running, wait for it to finish
        # (with a hard timeout so a hung swarm can't block the main loop)
        # and merge its result into the session output. We poll every 2s and
        # show elapsed time so the user sees life even on a 5-minute campaign.
        if swarm_task is not None:
            swarm_start = time.monotonic()
            swarm_timeout = _compute_swarm_timeout(config, args)
            # Bug #7: ``swarm_result`` must be bound before the loop — if the
            # swarm finished before polling starts, the while body never runs
            # and the later ``result["swarm_result"] = swarm_result`` would
            # raise UnboundLocalError and discard a completed campaign.
            swarm_result = None
            try:
                # Live progress, not a frozen spinner. The spinner's label is
                # fixed at construction so it can't show elapsed time (a 30-min
                # swarm showed "elapsed 0s" forever — actively misleading).
                # Instead poll every 2s (prompt completion) and print a
                # progress line every 15s reading swarm_state.json for live
                # agent-status counts. Bug #8 still holds: each wait_for is
                # bounded by the remaining deadline so a hung swarm actually
                # times out and cancels instead of looping forever.
                _last_progress = 0.0
                while not swarm_task.done():
                    remaining = swarm_timeout - (time.monotonic() - swarm_start)
                    if remaining <= 0:
                        raise asyncio.TimeoutError()
                    try:
                        swarm_result = await asyncio.wait_for(
                            asyncio.shield(swarm_task),
                            timeout=min(2.0, remaining),
                        )
                        break
                    except asyncio.TimeoutError:
                        elapsed = int(time.monotonic() - swarm_start)
                        if elapsed - _last_progress >= 15:
                            _last_progress = elapsed
                            snap = _read_swarm_snapshot(swarm_workspace)
                            detail = f" — {snap}" if snap else ""
                            ui.info(f"Swarm running {elapsed}s elapsed (timeout {int(swarm_timeout)}s){detail}")
                        continue
                # The while body is skipped entirely when the task finished
                # before the first poll — retrieve the result explicitly here
                # (this re-raises if the task errored, handled below).
                if swarm_result is None and not swarm_task.cancelled():
                    swarm_result = swarm_task.result()
                result["swarm_result"] = swarm_result
                elapsed = int(time.monotonic() - swarm_start)
                # Tier 5: the swarm now dispatches through the live MCP session
                # via SwarmMcpBridge (recon-mode tool calls go through
                # ExploitPolicy.approve_action -> session.call_tool; attack-mode
                # ExploitAgent Path A runs run_exploit_agent on the main loop).
                # Report the real dispatched-tool-call count from the bridge so
                # the summary reflects actions actually executed against the
                # target, not simulated counts.
                dispatched = getattr(swarm_bridge, "dispatched", 0)
                ui.info(
                    f"Swarm campaign complete in {elapsed}s "
                    f"(dispatched {dispatched} tool call(s) through the MCP exploit session): "
                    f"{swarm_result.get('tasks_completed', 0)} completed, "
                    f"{swarm_result.get('tasks_blocked', 0)} blocked, "
                    f"{swarm_result.get('tasks_failed', 0)} failed, "
                    f"{swarm_result.get('findings_report_ready', 0)} report-ready findings."
                )
                if dispatched == 0:
                    ui.info("Swarm dispatched 0 tool calls (recon-only or denied by policy).")
                ui.info(f"Swarm live state: {swarm_workspace / 'swarm_state.json'}")
            except asyncio.TimeoutError:
                ui.error(f"Swarm task timed out ({int(swarm_timeout)}s). Cancelling.")
                swarm_task.cancel()
                result["swarm_result"] = {"error": "timeout"}
            except _EXC_GROUP_CATCH as exc:
                ui.error(f"Swarm task error: {exc}")
                result["swarm_result"] = {"error": str(exc)}

        # T1.11: consolidated "Artifacts written:" block — one place listing
        # every artifact the operator may want to inspect, replacing the
        # scattered ui.info path lines that used to appear mid-run.
        _audit_path = result.get("audit_path", "unknown") if isinstance(result, dict) else "unknown"
        _workspace = result.get("workspace", "unknown") if isinstance(result, dict) else "unknown"
        ui.status("Artifacts written:")
        ui.info(f"  reports dir:        {reports_dir}")
        ui.info(f"  session summary:    {summary_path}")
        ui.info(f"  run json:           {reports_dir / 'run.json'}")
        ui.info(f"  audit trail:        {_audit_path}")
        ui.info(f"  exploit workspace:  {_workspace}")

        # T1.12: attack-mode next-steps hint. Recon mode already gets its
        # next-steps from the safety reviewer above; attack mode used to end
        # with nothing. Advisory only.
        if mode != "recon":
            ui.status(f"Review findings in: {summary_path}")
            ui.status(f"Continue with: python main.py --resume {run_id} --mode attack")
    except RuntimeError as exc:
        ui.error(f"Exploitation session failed: {exc}")
        return 1
    except _EXC_GROUP_CATCH as exc:
        # ``BaseExceptionGroup`` is *not* an ``Exception`` subclass — an MCP
        # stdio crash during the session would otherwise bypass this handler
        # and surface as a bare ``Session aborted.`` from the interactive menu.
        log_path = reports_dir / "session_error.log"
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
    finally:
        if swarm_task is not None and not swarm_task.done():
            swarm_task.cancel()
            try:
                await swarm_task
            except asyncio.CancelledError:
                pass

    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv or sys.argv[1:])

        # Apply output flags to the shared UI instance. --quiet and --json both
        # suppress ANSI color (so logs/JSON pipelines stay clean); --plain does
        # the same explicitly. Done once here so every downstream call site
        # (ui.status, ui.error, ui.spinner, etc.) honors them.
        ui.plain = bool(args.plain or args.quiet or args.json)
        raw_argv = argv or sys.argv[1:]
        interactive_startup = args.menu or (len(raw_argv) == 0 and not args.target.strip())
        bootstrap_startup_api_keys(
            args,
            prompt=interactive_startup and not args.doctor and not getattr(args, "self_test", False)
            and not getattr(args, "eval", False),
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
                getattr(args, "eval", False),
                args.demo,
            ]
        )
        if setup_only:
            return 0

        # --doctor: run a self-check and exit. No exploit session starts.
        if args.doctor:
            from tools.doctor import run_doctor
            return run_doctor(args.config)

        # --self-test: run a safe localhost smoke test and exit.
        if getattr(args, "self_test", False):
            from tools.self_test import run_self_test
            return asyncio.run(run_self_test(args))

        # --eval: run the eval/benchmark harness against --target and exit.
        if getattr(args, "eval", False):
            from tools.eval_harness import run_eval
            return asyncio.run(run_eval(args))

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

        # --menu flag or no arguments: launch interactive menu
        if args.menu or (len(sys.argv) == 1 and not args.target.strip()):
            from tools.interactive_menu import run_interactive_menu
            return run_interactive_menu()

        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        ui.error("Aborted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
