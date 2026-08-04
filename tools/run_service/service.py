"""AssessmentService: transport-neutral preparation and execution of runs.

Split from ``main.async_main`` so the CLI and the WebUI API daemon both drive
assessments through one code path. ``prepare`` resolves target/goal/settings
and returns a ``RunPreview`` (no I/O side effects beyond config reads);
``execute`` opens the MCP session, runs the agent loop, handles swarm, writes
reports, and returns a ``RunResult``.

The CLI supplies ``TerminalDecisionProvider`` / ``TerminalEventSink`` /
``TerminalApprovalProvider`` (backed by ``AttackUi``); the API supplies the
async adapters backed by persisted decisions + WebSocket events. The service
never calls ``AttackUi`` directly -- it emits events and requests decisions
through the provider/sink interfaces.
"""

from __future__ import annotations

import asyncio
import copy
import contextlib
import ipaddress
import json
import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.activity_log import ActivityLog
from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.exploit_agent import ExploitPolicy, ExploitSettings, run_exploit_agent
from tools.goal_engine import GoalEngine, AttackGoal
from tools.goal_suggester import ReconAssessment
from tools.mcp_session import (
    MCP_BOOT_TIMEOUT_SECONDS,
    _RunHeartbeat,
    mcp_tools_to_ollama,
    open_exploit_mcp_session,
)
from tools.model_router import build_router, format_model_choice
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.run_service.models import (
    EVENT_ARTIFACT,
    EVENT_BOOT,
    EVENT_COMPLETION,
    EVENT_ERROR,
    EVENT_PROGRESS,
    EVENT_RECON,
    EVENT_STATE,
    EVENT_SWARM,
    Decision,
    DecisionKind,
    DecisionStatus,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.providers import (
    ApprovalProvider,
    CancellationToken,
    DecisionProvider,
    EventSink,
    TerminalApprovalProvider,
)
from tools.safety_reviewer import SafetyReview
from tools.swarm_bridge import SwarmMcpBridge


# Exploit-action tool names that count toward ``successful_exploits`` in the
# derived campaign_result. Recon/research tools with exit_code==0 are NOT
# exploits. Mirrors the _EXPLOIT_ACTIONS set used by the loop's outcome tracker.
_EXPLOIT_TOOL_ACTIONS = frozenset({
    "run_exploit_terminal", "run_python_file", "run_msf_module",
    "msf_run_exploit", "run_attack_module", "lateral_exec",
    "generate_payload", "msf_generate_payload", "craft_exploit",
})


def _build_campaign_result_from_records(
    result: dict[str, Any], target_ip: str,
) -> dict[str, Any] | None:
    """Build a minimal ``campaign_result`` for EnhancedReportGenerator.

    Flow A's run_exploit_agent does not run an AutonomousOrchestrator campaign,
    so it never produced the ``{states: {target: AttackState.to_dict()}}`` shape
    EnhancedReportGenerator consumes. This folds the per-target audit records
    into that shape so the WebUI attack-graph has data to render.

    Returns None when there are no records (e.g. a recon-only run).
    """
    records = result.get("records") or []
    if not records:
        return None
    successful: list[str] = []
    failed: dict[str, list[str]] = {}
    timeline: list[dict[str, Any]] = []
    privilege_level = "none"
    for rec in records:
        if not isinstance(rec, dict):
            continue
        action = str(rec.get("action", "") or "")
        status = str(rec.get("status", "") or "")
        exit_code = rec.get("exit_code")
        ts = str(rec.get("timestamp", "") or "")
        detail = str(rec.get("detail", "") or rec.get("command", "") or "")
        is_exploit = action in _EXPLOIT_TOOL_ACTIONS
        if status in {"blocked", "analyzer_error", "SCOPE_DENIED"} or (exit_code is not None and int(exit_code) != 0):
            failed.setdefault(action, []).append(detail[:200] or status)
            timeline.append({"timestamp": ts, "event_type": "failure", "description": detail[:200] or status, "metadata": {"module": action}})
        elif status == "completed" and is_exploit:
            successful.append(action)
            timeline.append({"timestamp": ts, "event_type": "success", "description": detail[:200] or action, "metadata": {"module": action}})
        else:
            timeline.append({"timestamp": ts, "event_type": status or "observation", "description": detail[:200] or action, "metadata": {"module": action}})
    # Heuristic privilege level from the outcome summary string if present.
    summary = str(result.get("outcome_summary", "") or "")
    for label in ("root", "SYSTEM", "system", "admin", "NT AUTHORITY"):
        if label.lower() in summary.lower():
            privilege_level = label.lower() if label != "NT AUTHORITY" else "system"
            break
    return {
        "states": {
            target_ip: {
                "successful_exploits": successful,
                "failed_attempts": failed,
                "privilege_level": privilege_level,
                "timeline": timeline,
                "recon_result": {"services": []},
                "credentials_found": [],
            },
        },
    }

ui = get_ui()


def _llm_usage_line_count() -> int:
    """Line count of the shared llm_usage.jsonl, or 0 if absent."""
    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _run_telemetry(start_lines: int) -> dict[str, Any] | None:
    """Aggregate llm_usage.jsonl records appended after ``start_lines``."""
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
    last_ctx_pct: float | None = None
    last_ctx_window: int | None = None
    last_est_ctx: int | None = None
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
            last_ctx_pct = float(ctx)
        win = item.get("context_window_tokens")
        if isinstance(win, int):
            last_ctx_window = win
        est = item.get("estimated_context_tokens")
        if isinstance(est, int):
            last_est_ctx = est
    if not calls:
        return None
    avg_ctx = (sum(ctx_values) / len(ctx_values)) if ctx_values else None
    max_ctx = max(ctx_values) if ctx_values else None
    return {
        "calls": calls,
        "total_tokens": total_tokens,
        "avg_ctx": avg_ctx,
        "max_ctx": max_ctx,
        "context_window_tokens": last_ctx_window,
        "last_ctx_pct": last_ctx_pct,
        "last_estimated_context_tokens": last_est_ctx,
    }


def _read_swarm_snapshot(swarm_workspace: Path) -> str:
    """One-line live progress string from swarm_state.json, or ""."""
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


# ---------------------------------------------------------------------------
# Callable injection — lets the CLI pass its monkeypatchable module-level
# symbols so existing tests that patch ``main.open_exploit_mcp_session`` etc.
# keep working. The API path leaves these as the direct-import defaults.
# ---------------------------------------------------------------------------

def _run_session_default(**kwargs: Any) -> Any:
    """Default run_exploit_session — imports lazily to avoid cycles."""
    from tools.exploit_session import run_exploit_session
    return run_exploit_session(**kwargs)


def _run_recon_default(**kwargs: Any) -> Any:
    """Default run_recon_assessment — imports lazily."""
    from tools.recon_assessment_cli import run_recon_assessment
    return run_recon_assessment(**kwargs)


def _run_safety_default(*args: Any, **kwargs: Any) -> Any:
    """Default run_safety_review — imports lazily."""
    from tools.safety_review_cli import run_safety_review
    return run_safety_review(*args, **kwargs)


@dataclass
class Callables:
    """Bundle of callables the service uses, overridable by the CLI path."""
    build_router: Callable[..., Any] = field(default=build_router)
    open_session: Callable[..., Any] = field(default=open_exploit_mcp_session)
    run_session: Callable[..., Any] = field(default=_run_session_default)
    goal_engine_cls: type = field(default=GoalEngine)
    run_recon_assessment: Callable[..., Any] = field(default=_run_recon_default)
    run_safety_review: Callable[..., Any] = field(default=_run_safety_default)


_DEFAULT_CALLABLES = Callables()


class AssessmentService:
    """Transport-neutral run preparation and execution.

    The CLI constructs this once per ``async_main`` call; the API constructs one
    per run (the ``RunManager`` owns the single active instance). The service
    holds no run-specific mutable state between ``prepare`` and ``execute`` --
    ``prepare`` returns a ``RunPreview`` that ``execute`` consumes.

    ``callables`` is an optional injection point for the CLI path so existing
    tests that monkeypatch ``main.open_exploit_mcp_session`` /
    ``main.run_exploit_session`` / ``main.build_router`` / ``main.GoalEngine``
    continue to work: ``async_main`` passes its own module-level symbols here,
    and the service uses them instead of its direct imports. The API path
    leaves this None and uses the direct imports from the source modules.
    """

    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        callables: "Callables | None" = None,
    ) -> None:
        self._config = config
        self._c = callables or _DEFAULT_CALLABLES

    # ------------------------------------------------------------------
    # Prepare: resolve target/goal/settings without I/O side effects
    # ------------------------------------------------------------------

    async def prepare(self, request: RunRequest) -> RunPreview:
        """Resolve the target, goal, and effective settings; return a preview.

        Does NOT open the MCP session, does NOT write session_state.json, does
        NOT start any subprocess. The caller (CLI or API) shows the preview to
        the operator and asks for confirmation before calling ``execute``.
        """
        from tools import config_cli as _config_cli
        from tools.cli_exploit_settings import build_cli_exploit_settings
        from tools.skills_cli import _build_runtime_skill_selection, apply_skills_cli_overrides
        from tools.validation_utils import validate_target as _validate_target, resolve_target as _resolve_target

        config_path = request.config_path
        config = copy.deepcopy(
            self._config if self._config is not None else _config_cli.load_config(config_path)
        )
        # Apply skills CLI overrides to the in-memory config.
        config = apply_skills_cli_overrides(config, _request_to_args(request))

        # Load plugins (best-effort; failure never blocks boot).
        try:
            from tools.plugins import load_plugins
            load_plugins(config)
        except Exception:  # noqa: BLE001
            pass

        # Build router + resolve model alias.
        ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
        _long_cfg = config.get("long_session", {}) or {}
        _ls_active = bool(request.long_session or _long_cfg.get("enabled", False))
        _req_timeout = (
            float(_long_cfg["request_timeout_seconds"])
            if (_ls_active and _long_cfg.get("request_timeout_seconds"))
            else None
        )
        router = self._c.build_router(
            config.get("models", {}).get("registry"),
            host=ollama_host,
            request_timeout_seconds=_req_timeout,
        )
        model_alias = request.model_alias or config.get("models", {}).get("default_alias", "glm")
        if model_alias not in router._clients:
            try:
                router.get_client(model_alias)
            except KeyError:
                from tools.model_router import _build_model_client
                router.register(
                    model_alias,
                    _build_model_client(model_alias, host=ollama_host, request_timeout_seconds=_req_timeout),
                )
        model_client = router.get_client(model_alias)

        # Resolve target (IP or domain).
        original_target = request.target.strip()
        if not original_target:
            raise ValueError("Target is required.")
        if not _validate_target(original_target):
            raise ValueError(f"Invalid target (must be an IP or domain): {original_target}")
        resolved_ip, resolved_domain = _resolve_target(original_target)
        if resolved_domain and resolved_ip is None:
            raise ValueError(f"Could not resolve domain: {original_target}")
        target_ip = resolved_ip if resolved_ip is not None else original_target

        # Determine mode.
        mode = request.mode
        if mode not in ("recon", "attack"):
            raise ValueError(f"Invalid mode: {mode!r}")

        # Determine goal (preset/custom). Recon-first and goal selection via
        # decision provider happen in ``execute``; here we resolve what we can
        # without I/O.
        goal_engine = self._c.goal_engine_cls()
        goal_name = request.goal_name.strip().lower()
        custom_text = request.custom_goal.strip()
        risk_profile = "high_authorized_testing" if mode == "attack" else "standard_authorized"

        recon_first = request.recon_first
        if recon_first is None:
            recon_first = not goal_name and not custom_text

        # If we already have enough to resolve a goal, do it now.
        if custom_text:
            goal = goal_engine.get("custom", custom_text, risk_profile=risk_profile)
        elif goal_name and goal_engine.is_preset(goal_name):
            goal = goal_engine.get(goal_name, risk_profile=risk_profile)
        else:
            # No goal yet -- will be resolved during execute (recon-first or
            # interactive). Use a placeholder for preview purposes.
            goal = goal_engine.get("custom", goal_name or "recon-first goal selection", risk_profile=risk_profile)

        # Build exploit settings (pure data; no I/O).
        multi_model_consult = request.multi_model_consult
        if multi_model_consult is None:
            multi_model_consult = bool((config.get("multi_model", {}) or {}).get("enabled", False))
        exploit_settings = build_cli_exploit_settings(
            mode=mode,
            target_ip=target_ip,
            goal=goal,
            config=config,
            adaptive_exploits=request.adaptive_exploits,
            swarm=request.swarm,
            critic=request.critic,
            reflection=request.reflection,
            multi_model_enabled=bool(multi_model_consult),
            observer_mode=request.observer_mode,
            ultrathink=request.ultrathink,
            debug=request.debug,
            long_session=request.long_session,
        )

        # Skill selection (pure data; no I/O).
        skill_selection = _build_runtime_skill_selection(
            config=config,
            goal=goal,
            mode=mode,
            assessment=None,
            is_domain=bool(resolved_domain),
        )

        # Run ID + reports dir.
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        reports_dir = request.reports_dir / run_id
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Effective settings for preview.
        exploit_cfg = config.get("exploit", {}) or {}
        permission_effective = str(exploit_cfg.get("permission", "read_only"))
        attack_mode_effective = mode == "attack"
        swarm_effective = request.swarm or bool((config.get("swarm", {}) or {}).get("enabled", False))
        parallel_swarm_effective = request.parallel_swarm or bool(
            (config.get("swarm", {}) or {}).get("parallel_enabled", False)
        )
        destructive = permission_effective == "full_access" and mode == "attack"
        _models_cfg = config.get("models", {}) if isinstance(config, dict) else {}
        model_label = format_model_choice(
            model_alias, registry=_models_cfg.get("registry", {}), registry_info=_models_cfg.get("info", {})
        )
        http_port = int(config.get("mcp", {}).get("http_port", 8001))

        required_text = ""
        if destructive:
            required_text = f"ALLOW {target_ip}"

        budgets = {
            "commands": getattr(exploit_settings, "attack_max_commands" if attack_mode_effective else "max_commands_per_session", "n/a"),
            "rounds": getattr(exploit_settings, "attack_max_rounds" if attack_mode_effective else "max_rounds", "n/a"),
            "duration_minutes": getattr(exploit_settings, "attack_max_duration_minutes", "n/a") if attack_mode_effective else None,
        }

        return RunPreview(
            run_id=run_id,
            reports_dir=reports_dir,
            config_path=config_path,
            target_ip=target_ip,
            original_target=original_target,
            resolved_ip=resolved_ip,
            resolved_domain=resolved_domain,
            mode=mode,
            goal_name=goal.name,
            goal_description=goal.description,
            model_alias=model_alias,
            model_label=model_label,
            transport_summary=f"http on port {http_port}",
            permission=permission_effective,
            attack_mode=attack_mode_effective,
            swarm=swarm_effective,
            parallel_swarm=parallel_swarm_effective,
            multi_model=bool(multi_model_consult),
            destructive=destructive,
            required_confirmation_text=required_text,
            budgets=budgets,
            skill_activations=[
                {"name": a.name, "reason": a.reason} for a in skill_selection.activations
            ],
            skill_errors=list(skill_selection.errors),
            resumed_from=request.resume_source,
        )

    # ------------------------------------------------------------------
    # Execute: open MCP session, run agent, handle swarm, write reports
    # ------------------------------------------------------------------

    async def execute(
        self,
        request: RunRequest,
        preview: RunPreview,
        *,
        decision_provider: DecisionProvider,
        event_sink: EventSink,
        cancellation: CancellationToken,
        model_client: Any | None = None,
        config: dict[str, Any] | None = None,
        approval_provider: Any | None = None,
        session_attach: Callable[[Any, list[dict[str, Any]], Any], None] | None = None,
    ) -> RunResult:
        """Execute the assessment described by ``request`` / ``preview``.

        ``model_client`` may be None (the service builds a fresh router); when
        the CLI passes its already-built client it avoids a second router
        construction. ``config`` may be None (loaded from ``request.config_path``).
        """
        from tools import config_cli as _config_cli
        from tools.cli_exploit_settings import _compute_swarm_timeout, build_cli_exploit_settings
        from tools.resume_state import _load_resume_state
        from tools.skills_cli import (
            _apply_runtime_skill_selection,
            _build_runtime_skill_selection,
            apply_skills_cli_overrides,
        )
        from tools.validation_utils import resolve_target as _resolve_target

        config_path = request.config_path
        config = copy.deepcopy(
            config if config is not None else _config_cli.load_config(config_path)
        )
        config = apply_skills_cli_overrides(config, _request_to_args(request))
        reports_dir = preview.reports_dir
        run_id = preview.run_id
        target_ip = preview.target_ip
        original_target = preview.original_target
        resolved_ip = preview.resolved_ip
        resolved_domain = preview.resolved_domain
        mode = preview.mode

        await event_sink.emit(EVENT_STATE, {"state": RunState.RUNNING.value})

        # Write session_state.json for --resume.
        try:
            (reports_dir / "session_state.json").write_text(
                json.dumps({"session_id": run_id, "started_at": datetime.now(timezone.utc).isoformat()}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

        # Build/refresh model client if not supplied.
        if model_client is None:
            ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
            _long_cfg = config.get("long_session", {}) or {}
            _ls_active = bool(request.long_session or _long_cfg.get("enabled", False))
            _req_timeout = (
                float(_long_cfg["request_timeout_seconds"])
                if (_ls_active and _long_cfg.get("request_timeout_seconds"))
                else None
            )
            router = self._c.build_router(
                config.get("models", {}).get("registry"), host=ollama_host, request_timeout_seconds=_req_timeout
            )
            model_alias = request.model_alias or config.get("models", {}).get("default_alias", "glm")
            model_client = router.get_client(model_alias)
        else:
            model_alias = request.model_alias or config.get("models", {}).get("default_alias", "glm")

        # Resolve goal (recon-first / interactive / preset / custom).
        goal_engine = self._c.goal_engine_cls()
        risk_profile = "high_authorized_testing" if mode == "attack" else "standard_authorized"
        assessment: ReconAssessment | None = None

        # Resume state.
        _resume_state: tuple[ReconAssessment, str, str] | None = None
        if request.resume_source:
            match = self._find_resume_match(request.reports_dir, request.resume_source)
            if match is not None:
                _resume_state = _load_resume_state(match, _request_to_args(request))
                if _resume_state is not None:
                    assessment = _resume_state[0]

        # Determine recon-first.
        recon_first = request.recon_first
        if recon_first is None:
            recon_first = not request.goal_name and not request.custom_goal
        if _resume_state is not None:
            recon_first = False

        if recon_first:
            assessment, goal = await self._recon_first(
                request=request,
                config=config,
                config_path=config_path,
                target_ip=target_ip,
                original_target=original_target,
                resolved_ip=resolved_ip,
                resolved_domain=resolved_domain,
                reports_dir=reports_dir,
                model_client=model_client,
                model_alias=model_alias,
                risk_profile=risk_profile,
                goal_engine=goal_engine,
                decision_provider=decision_provider,
                event_sink=event_sink,
                cancellation=cancellation,
            )
        elif request.custom_goal.strip():
            goal = goal_engine.get("custom", request.custom_goal.strip(), risk_profile=risk_profile)
        elif request.goal_name.strip().lower() and goal_engine.is_preset(request.goal_name.strip().lower()):
            goal = goal_engine.get(request.goal_name.strip().lower(), risk_profile=risk_profile)
        else:
            # Interactive goal selection via decision provider.
            presets = goal_engine.list_presets()
            decision = Decision(
                id="", run_id=run_id, kind=DecisionKind.GOAL_SELECT,
                prompt_text="Select mission goal:",
                options=[{"name": k, "description": d} for k, d in presets] + [{"name": "custom", "description": "Type your own goal"}],
            )
            answer = await decision_provider.request(decision)
            if answer == "custom":
                custom_decision = Decision(
                    id="", run_id=run_id, kind=DecisionKind.GOAL_SELECT,
                    prompt_text="Describe your custom goal:",
                )
                custom_text = await decision_provider.request(custom_decision)
                goal = goal_engine.get("custom", custom_text or "No custom goal provided.", risk_profile=risk_profile)
            else:
                goal = goal_engine.get(answer, risk_profile=risk_profile)

        # Resume goal override.
        if _resume_state is not None:
            _rg_name, _rg_desc = _resume_state[1], _resume_state[2]
            if _rg_name:
                _rg_risk = "high_authorized_testing" if mode == "attack" else "standard_authorized"
                goal = goal_engine.get(_rg_name, _rg_desc, risk_profile=_rg_risk)

        # Build exploit settings.
        multi_model_consult = request.multi_model_consult
        if multi_model_consult is None:
            multi_model_consult = bool((config.get("multi_model", {}) or {}).get("enabled", False))
        exploit_settings = build_cli_exploit_settings(
            mode=mode, target_ip=target_ip, goal=goal, config=config,
            adaptive_exploits=request.adaptive_exploits, swarm=request.swarm,
            critic=request.critic, reflection=request.reflection,
            multi_model_enabled=bool(multi_model_consult),
            observer_mode=request.observer_mode, ultrathink=request.ultrathink,
            debug=request.debug, long_session=request.long_session,
        )
        skill_selection = _build_runtime_skill_selection(
            config=config, goal=goal, mode=mode,
            assessment=assessment if (recon_first or _resume_state is not None) else None,
            is_domain=bool(resolved_domain),
        )
        _apply_runtime_skill_selection(exploit_settings, skill_selection, config=config, goal=goal, mode=mode)

        # Swarm bridge + loop setup.
        swarm_bridge = SwarmMcpBridge()
        swarm_loop: Any = None
        swarm_task: asyncio.Task[Any] | None = None
        swarm_workspace: Path | None = None
        if request.swarm:
            swarm_loop, swarm_task, swarm_workspace = await self._setup_swarm(
                request=request, config=config, target_ip=target_ip, goal=goal, mode=mode,
                exploit_settings=exploit_settings, model_client=model_client,
                model_alias=model_alias, swarm_bridge=swarm_bridge,
                original_target=original_target, resolved_ip=resolved_ip,
                resolved_domain=resolved_domain, event_sink=event_sink,
                reports_dir=reports_dir,
            )

        # Activity log.
        activity = ActivityLog(reports_dir, plain=request.plain)
        activity.log("info", f"Session started: {mode} against {target_ip} with goal {goal.name}")

        # Telemetry snapshot.
        _telemetry_start = _llm_usage_line_count()

        # Heartbeat + ticker.
        _heartbeat = _RunHeartbeat()

        async def _ticker() -> None:
            start = time.monotonic()
            while True:
                await asyncio.sleep(15.0)
                if cancellation.cancelled:
                    return
                m, s = divmod(int(time.monotonic() - start), 60)
                _live_tel = _run_telemetry(_telemetry_start) or {}
                await event_sink.emit(EVENT_PROGRESS, {
                    "elapsed_seconds": int(time.monotonic() - start),
                    "round": _heartbeat.round,
                    "actions": _heartbeat.action,
                    "phase": _heartbeat.phase,
                    "telemetry": _live_tel,
                })
                ui.info(f"Exploit agent still running... {m}:{s:02d} elapsed (round {_heartbeat.round}, {_heartbeat.action} actions, {_heartbeat.phase})")

        ticker_task = asyncio.create_task(_ticker())

        result: dict[str, Any] = {}
        try:
            # Swarm attach callback.
            def _swarm_attach(session: Any, schemas: list[dict[str, Any]], policy: Any) -> None:
                if session_attach is not None:
                    session_attach(session, schemas, policy)
                if not request.swarm:
                    return
                main_loop = asyncio.get_running_loop()
                swarm_bridge.attach(session, schemas, policy, loop=main_loop)
                if swarm_loop is not None:
                    ctx = getattr(getattr(swarm_loop, "_swarm", None), "_context", None)
                    if isinstance(ctx, dict):
                        ctx["mcp_session"] = session
                        ctx["exploit_tools_schemas"] = schemas
                        ctx["main_loop"] = main_loop

            # Run the exploit session.
            try:
                result = await self._run_session(
                    model_client=model_client, model_alias=model_alias,
                    target_ip=target_ip, mode=mode, goal=goal,
                    exploit_settings=exploit_settings, config_path=config_path,
                    reports_dir=reports_dir, assessment=assessment,
                    approval_prompt=None, approval_provider=approval_provider,
                    swarm_attach=_swarm_attach if (request.swarm or session_attach is not None) else None,
                    heartbeat=_heartbeat,
                    original_target=original_target if resolved_domain else None,
                    resolved_ip=resolved_ip if resolved_domain else None,
                    recon_first=recon_first, resume_state=_resume_state,
                    event_sink=event_sink, cancellation=cancellation,
                )
            finally:
                if session_attach is not None:
                    session_attach(None, [], None)
        except _EXC_GROUP_CATCH as exc:
            log_path = reports_dir / "session_error.log"
            try:
                log_path.write_text(
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                    encoding="utf-8",
                )
            except OSError:
                pass
            ui.error(f"Exploitation session failed unexpectedly: {exc}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            await event_sink.emit(EVENT_ERROR, {"message": str(exc), "log_path": str(log_path)})
            return RunResult(
                run_id=run_id, target_ip=target_ip, mode=mode,
                goal_name=goal.name, goal_description=goal.description,
                error=str(exc), reports_dir=str(reports_dir),
            )
        finally:
            ticker_task.cancel()
            try:
                await asyncio.wait_for(ticker_task, timeout=0.1)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        # Swarm wait.
        if swarm_task is not None and swarm_workspace is not None:
            result = await self._wait_swarm(
                swarm_task=swarm_task, swarm_bridge=swarm_bridge,
                swarm_workspace=swarm_workspace, config=config,
                request=request, result=result, event_sink=event_sink,
            )

        # Telemetry.
        _tel = _run_telemetry(_telemetry_start)
        if _tel:
            result.setdefault("_telemetry", _tel)

        # Safety review (recon mode).
        safety_review_data: dict[str, Any] | None = None
        if mode == "recon":
            try:
                review = await self._c.run_safety_review(model_client, model_alias, result, target_ip, goal)
                ui.display_safety_review(review)
                safety_review_data = {
                    "safe_to_proceed": review.safe_to_proceed,
                    "concerns": getattr(review, "concerns", []),
                    "recommendations": getattr(review, "recommendations", []),
                }
            except _EXC_GROUP_CATCH as exc:
                ui.error(f"Safety review failed: {exc}")

        # Write session summary + run.json.
        summary_path = reports_dir / "session_summary.md"
        summary_lines = [
            f"# Session Summary — {target_ip}", "",
            f"- **Date**: {datetime.now(timezone.utc).isoformat()}",
            f"- **Target**: {target_ip}",
            f"- **Mode**: {mode}",
            f"- **Goal**: {goal.name}",
            f"- **Goal Description**: {goal.description}",
            f"- **Actions Executed**: {result.get('total_actions', 0)}",
            f"- **Workspace**: {result.get('workspace', 'unknown')}",
            f"- **Audit trail**: {result.get('audit_path', 'unknown')}",
        ]
        if _tel:
            _ctx = ""
            if _tel["avg_ctx"] is not None:
                _ctx = f", avg ctx {_tel['avg_ctx']:.0f}%"
            summary_lines.append(f"- **Model usage**: {_tel['total_tokens']:,} tokens across {_tel['calls']} calls{_ctx}")
        _summary_skills = result.get("active_skills") or []
        if _summary_skills:
            _skill_names = ", ".join(str(s.get("name", "unknown")) for s in _summary_skills if isinstance(s, dict))
            summary_lines.append(f"- **Active skills**: {_skill_names}")
        _summary_outcome = result.get("outcome_summary")
        if _summary_outcome:
            summary_lines.append(f"- **Blocked/thrash summary**: {_summary_outcome}")
        _sw = result.get("swarm_result")
        if isinstance(_sw, dict) and _sw.get("tasks_completed") is not None:
            summary_lines.extend(["", "## Swarm", "",
                f"- **Completed**: {_sw.get('tasks_completed', 0)}",
                f"- **Blocked**: {_sw.get('tasks_blocked', 0)}",
                f"- **Failed**: {_sw.get('tasks_failed', 0)}",
                f"- **Report-ready findings**: {_sw.get('findings_report_ready', 0)}",
            ])
        summary_lines.extend(["", "## Results", "", "See the exploit workspace for full logs, scripts, and audit trails.", ""])
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")

        run_json_path = reports_dir / "run.json"
        if isinstance(result, dict):
            try:
                run_json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            except OSError as exc:
                ui.warning(f"Could not write run.json: {exc}")

        # Flow A enhanced report (Phase B1). Flow A's run_exploit_agent does
        # not run an AutonomousOrchestrator campaign, so EnhancedReportGenerator
        # was Flow B-only. Build a minimal campaign_result["states"] from the
        # audit records: each completed exit_code==0 record is a successful
        # action; failed/blocked records populate failed_attempts. This feeds
        # ExploitationChain + TechnicalFinding so the WebUI can render the
        # attack graph. Best-effort — never fatal to the run.
        try:
            campaign_result = _build_campaign_result_from_records(result, target_ip)
            if campaign_result is not None:
                from tools.enhanced_reporting import EnhancedReportGenerator
                generator = EnhancedReportGenerator(
                    db=None, mission_id=run_id, workspace=reports_dir,
                )
                paths = generator.generate_full_report(campaign_result, output_format="json")
                json_src = paths.get("json")
                if json_src is not None and json_src.exists():
                    # Stable name so the WebUI can fetch /artifacts/enhanced/enhanced_report.json
                    stable = reports_dir / "enhanced" / "enhanced_report.json"
                    stable.write_bytes(json_src.read_bytes())
        except Exception as exc:  # noqa: BLE001 -- reporting is best-effort
            ui.warning(f"Could not write enhanced report: {exc}")

        await event_sink.emit(EVENT_ARTIFACT, {
            "reports_dir": str(reports_dir),
            "session_summary": str(summary_path),
            "run_json": str(run_json_path),
            "audit_path": result.get("audit_path", ""),
            "workspace": result.get("workspace", ""),
        })

        await event_sink.emit(EVENT_COMPLETION, {
            "total_actions": result.get("total_actions", 0),
            "goal": goal.name,
            "target": target_ip,
            "mode": mode,
        })

        return RunResult(
            run_id=run_id, target_ip=target_ip, mode=mode,
            goal_name=goal.name, goal_description=goal.description,
            total_actions=result.get("total_actions", 0),
            workspace=result.get("workspace", ""),
            audit_path=result.get("audit_path", ""),
            records=result.get("records", []),
            messages=result.get("messages", []),
            error=result.get("error", ""),
            swarm_result=result.get("swarm_result"),
            active_skills=result.get("active_skills", []),
            outcome_summary=result.get("outcome_summary", ""),
            telemetry=_tel,
            safety_review=safety_review_data,
            reports_dir=str(reports_dir),
            summary_path=str(summary_path),
            run_json_path=str(run_json_path),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_resume_match(reports_dir: Path, resume_key: str) -> Path | None:
        """Find a run subdir matching ``resume_key`` (name or session_id)."""
        for child in sorted(reports_dir.iterdir(), reverse=True):
            if not child.is_dir():
                continue
            if child.name == resume_key:
                return child
            for sj_name in ("session_state.json", "session.json"):
                sj = child / sj_name
                if sj.exists():
                    try:
                        if json.loads(sj.read_text(encoding="utf-8")).get("session_id") == resume_key:
                            return child
                    except (OSError, ValueError, KeyError):
                        continue
        return None

    async def _recon_first(
        self, *, request: RunRequest, config: dict[str, Any], config_path: Path,
        target_ip: str, original_target: str, resolved_ip: str | None,
        resolved_domain: str | None, reports_dir: Path, model_client: Any,
        model_alias: str, risk_profile: str, goal_engine: GoalEngine,
        decision_provider: DecisionProvider, event_sink: EventSink,
        cancellation: CancellationToken,
    ) -> tuple[ReconAssessment, AttackGoal]:
        """Recon-first: scan target, suggest goals, let operator pick."""
        ui.status("RECON-FIRST MODE: Scanning target before goal selection...")
        ui.divider()

        workspace = Path("exploit_workspace")
        workspace.mkdir(parents=True, exist_ok=True)

        http_port = int(config.get("mcp", {}).get("http_port", 8001))
        assessment: ReconAssessment | None = None
        try:
            async with self._c.open_session(
                transport="http", config_path=config_path, target_ip=target_ip,
                exploit_port=http_port, workspace=workspace,
                multi_model_enabled=bool(request.multi_model_consult),
                active_model_alias=model_alias, soft_fail=True,
                original_target=original_target if resolved_domain else None,
                resolved_ip=resolved_ip if resolved_domain else None,
            ) as recon_session:
                if recon_session is None:
                    ui.info("MCP recon unavailable — falling back to UNKNOWN OS verdict.")
                    assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])
                else:
                    assessment = await self._c.run_recon_assessment(
                        session=recon_session, target_ip=target_ip, reports_dir=reports_dir,
                    )
        except _EXC_GROUP_CATCH as exc:
            log_path = reports_dir / "recon_first_error.log"
            try:
                log_path.write_text("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)), encoding="utf-8")
            except OSError:
                pass
            ui.warning(f"Recon-first session hit an unexpected error: {exc}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])
        if assessment is None:
            assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])

        ui.display_recon_assessment(assessment)

        await event_sink.emit(EVENT_RECON, {"assessment": assessment.to_dict()})

        suggestions = goal_engine.suggest_goals(assessment, risk_profile)
        suggestions_path = reports_dir / "goal_suggestions.json"
        suggestions_path.write_text(json.dumps([s.to_dict() for s in suggestions], indent=2), encoding="utf-8")
        ui.info(f"Goal suggestions saved to: {suggestions_path}")
        ui.display_goal_suggestions(suggestions)

        await event_sink.emit(EVENT_GOAL_SUGGESTIONS := "goal_suggestions", {
            "suggestions": [s.to_dict() for s in suggestions],
        })

        # Ask operator to pick a goal via decision provider.
        decision = Decision(
            id="", run_id="", kind=DecisionKind.GOAL_SELECT,
            prompt_text="Select a goal from the suggestions:",
            options=[s.to_dict() for s in suggestions],
        )
        answer = await decision_provider.request(decision)

        selected_sg = next((s for s in suggestions if s.name == answer), None)
        if selected_sg and getattr(selected_sg, "is_ai_generated", False):
            goal = goal_engine.get("custom", selected_sg.description, risk_profile=risk_profile)
            goal.name = selected_sg.name
        elif answer:
            goal = goal_engine.get(answer, risk_profile=risk_profile)
        else:
            goal = goal_engine.get("custom", "No goal selected", risk_profile=risk_profile)

        assessment_path = reports_dir / "recon_assessment.json"
        if assessment_path.exists():
            data = json.loads(assessment_path.read_text(encoding="utf-8"))
            data["chosen_goal"] = goal.name
            data["chosen_goal_description"] = goal.description
            assessment_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        return assessment, goal

    async def _setup_swarm(
        self, *, request: RunRequest, config: dict[str, Any], target_ip: str,
        goal: AttackGoal, mode: str, exploit_settings: ExploitSettings,
        model_client: Any, model_alias: str, swarm_bridge: SwarmMcpBridge,
        original_target: str, resolved_ip: str | None, resolved_domain: str | None,
        event_sink: EventSink, reports_dir: Path,
    ) -> tuple[Any, asyncio.Task[Any] | None, Path]:
        from agent_loop import AgentLoop

        exploit_cfg = config.get("exploit", {}) or {}
        swarm_mission_config = {
            "program_name": f"Swarm: {target_ip}",
            "objective": goal.description or f"Swarm against {target_ip}",
            "risk_profile": "high_authorized_testing" if mode == "attack" else "standard_authorized",
            "allowed_assets": [str(target_ip)],
            "disallowed_assets": [],
            "forbidden_actions": ["denial_of_service", "social_engineering", "physical_attack"],
            "testing_modes": ["recon", "test", "exploit", "report"] if mode == "attack" else ["recon", "analysis", "report"],
            "rate_limits": {"default_requests_per_second": 2, "max_concurrent_requests": 3},
            "accounts": [],
            "use_swarm": True,
            "critic_enabled": bool(getattr(exploit_settings, "target_context", {}).get("critic_enabled", False)),
            "reflection_enabled": bool(getattr(exploit_settings, "target_context", {}).get("reflection_enabled", False)),
            "adaptive_exploits_enabled": bool(getattr(exploit_settings, "adaptive_exploits_enabled", False)),
            "reflection_every_n_actions": 10,
            "attack_max_rounds": int(exploit_cfg.get("max_rounds", 30)),
        }
        swarm_workspace = reports_dir / "swarm_workspace"
        swarm_workspace.mkdir(parents=True, exist_ok=True)
        swarm_loop = AgentLoop(
            mission_config=swarm_mission_config, workspace_root=swarm_workspace,
            tool_executor=swarm_bridge.dispatch, console_ui=ui, state_dir=swarm_workspace,
            original_target=original_target if resolved_domain else "",
            resolved_ip=resolved_ip if resolved_domain else "",
        )
        try:
            swarm_loop.set_model_client(model_client, model_alias)
        except Exception as exc:  # noqa: BLE001
            ui.warning(f"swarm set_model_client failed: {exc}")

        async def _run_swarm() -> dict[str, Any]:
            try:
                if mode == "attack":
                    return await swarm_loop.run_autonomous_campaign([target_ip])
                max_cycles = int(exploit_cfg.get("max_rounds", 30))
                return await asyncio.to_thread(swarm_loop.run, max_cycles)
            except _EXC_GROUP_CATCH as exc:
                ui.error(f"Swarm campaign error: {exc}")
                return {"error": str(exc)}

        swarm_task = asyncio.create_task(_run_swarm())
        ui.info(f"Swarm mode ENABLED (critic={request.critic}, reflection={request.reflection}, adaptive_exploits={request.adaptive_exploits}).")
        await event_sink.emit(EVENT_SWARM, {"status": "started", "workspace": str(swarm_workspace)})
        return swarm_loop, swarm_task, swarm_workspace

    async def _run_session(
        self, *, model_client: Any, model_alias: str, target_ip: str, mode: str,
        goal: AttackGoal, exploit_settings: ExploitSettings, config_path: Path,
        reports_dir: Path, assessment: ReconAssessment | None,
        approval_prompt: Any, approval_provider: Any, swarm_attach: Any, heartbeat: Any,
        original_target: str | None, resolved_ip: str | None,
        recon_first: bool, resume_state: tuple[Any, str, str] | None,
        event_sink: EventSink, cancellation: CancellationToken,
    ) -> dict[str, Any]:
        config = _config_cli_load(config_path)
        http_port = int(config.get("mcp", {}).get("http_port", 8001))

        result = await self._c.run_session(
            client=model_client, model=model_alias, target_ip=target_ip,
            mode=mode, goal=goal, exploit_settings=exploit_settings,
            config_path=config_path, mcp_transport="http", exploit_port=http_port,
            reports_dir=reports_dir,
            assessment=assessment if (recon_first or resume_state is not None) else None,
            approval_prompt=approval_prompt,
            approval_provider=approval_provider,
            swarm_attach=swarm_attach, heartbeat=heartbeat,
            original_target=original_target, resolved_ip=resolved_ip,
            event_sink=event_sink,
        )
        ui.divider()
        ui.success(f"Session complete. {result.get('total_actions', 0)} actions executed.")
        ui.status(f"Goal:    {goal.name}")
        ui.status(f"Target:  {target_ip}")
        ui.status(f"Mode:    {mode}")
        ui.status(f"Actions: {result.get('total_actions', 0)}")
        _outcome = result.get("outcome_summary")
        if _outcome:
            ui.status(f"Blocked/thrash: {_outcome}")
        _tel = getattr(result, "_telemetry", None)
        if isinstance(result, dict):
            _tel2 = result.get("_telemetry")
            if isinstance(_tel2, dict):
                _ctx_part = ""
                if _tel2.get("avg_ctx") is not None:
                    _ctx_part = f" (avg ctx {_tel2['avg_ctx']:.0f}%, max {_tel2['max_ctx']:.0f}%)" if _tel2.get("max_ctx") is not None else f" (avg ctx {_tel2['avg_ctx']:.0f}%)"
                ui.info(f"Model usage: {_tel2['total_tokens']:,} tokens across {_tel2['calls']} calls{_ctx_part}")
        final_skills = result.get("active_skills") or exploit_settings.target_context.get("active_skills", [])
        if final_skills:
            ui.skills([f"{item.get('name', 'unknown')} - {item.get('reason', 'selected')}" for item in final_skills if isinstance(item, dict)])
        ui.status("Artifacts written:")
        ui.info(f"  reports dir:        {reports_dir}")
        ui.info(f"  audit trail:        {result.get('audit_path', 'unknown')}")
        ui.info(f"  exploit workspace:  {result.get('workspace', 'unknown')}")
        if mode != "recon":
            ui.status(f"Review findings in: {reports_dir / 'session_summary.md'}")
        return result

    async def _wait_swarm(
        self, *, swarm_task: asyncio.Task[Any], swarm_bridge: SwarmMcpBridge,
        swarm_workspace: Path, config: dict[str, Any], request: RunRequest,
        result: dict[str, Any], event_sink: EventSink,
    ) -> dict[str, Any]:
        from tools.cli_exploit_settings import _compute_swarm_timeout
        swarm_start = time.monotonic()
        swarm_timeout = _compute_swarm_timeout(config, _request_to_args(request))
        swarm_result = None
        try:
            _last_progress = 0.0
            while not swarm_task.done():
                remaining = swarm_timeout - (time.monotonic() - swarm_start)
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                try:
                    swarm_result = await asyncio.wait_for(asyncio.shield(swarm_task), timeout=min(2.0, remaining))
                    break
                except asyncio.TimeoutError:
                    elapsed = int(time.monotonic() - swarm_start)
                    if elapsed - _last_progress >= 15:
                        _last_progress = elapsed
                        snap = _read_swarm_snapshot(swarm_workspace)
                        detail = f" — {snap}" if snap else ""
                        ui.info(f"Swarm running {elapsed}s elapsed (timeout {int(swarm_timeout)}s){detail}")
                        await event_sink.emit(EVENT_SWARM, {"elapsed_seconds": elapsed, "timeout_seconds": int(swarm_timeout), "snapshot": snap})
                    continue
            if swarm_result is None and not swarm_task.cancelled():
                swarm_result = swarm_task.result()
            result["swarm_result"] = swarm_result
            elapsed = int(time.monotonic() - swarm_start)
            dispatched = getattr(swarm_bridge, "dispatched", 0)
            ui.info(
                f"Swarm campaign complete in {elapsed}s (dispatched {dispatched} tool call(s)): "
                f"{swarm_result.get('tasks_completed', 0)} completed, "
                f"{swarm_result.get('tasks_blocked', 0)} blocked, "
                f"{swarm_result.get('tasks_failed', 0)} failed, "
                f"{swarm_result.get('findings_report_ready', 0)} report-ready findings."
            )
        except asyncio.TimeoutError:
            ui.error(f"Swarm task timed out ({int(swarm_timeout)}s). Cancelling.")
            swarm_task.cancel()
            result["swarm_result"] = {"error": "timeout"}
        except _EXC_GROUP_CATCH as exc:
            ui.error(f"Swarm task error: {exc}")
            result["swarm_result"] = {"error": str(exc)}
        finally:
            if not swarm_task.done():
                swarm_task.cancel()
                try:
                    await swarm_task
                except asyncio.CancelledError:
                    pass
        return result


def _config_cli_load(path: Path) -> dict[str, Any]:
    from tools import config_cli as _config_cli
    return _config_cli.load_config(path)


def _request_to_args(request: RunRequest) -> Any:
    """Build a lightweight argparse.Namespace stand-in from a RunRequest so the
    existing skills/resume/CLI helpers (which take ``args``) work unchanged."""
    import argparse
    ns = argparse.Namespace()
    ns.config = request.config_path
    ns.model = request.model_alias or None
    ns.target = request.target
    ns.mode = request.mode
    ns.goal = request.goal_name
    ns.custom_goal = request.custom_goal
    ns.recon_first = request.recon_first
    ns.no_recon_first = False
    ns.swarm = request.swarm
    ns.parallel_swarm = request.parallel_swarm
    ns.critic = request.critic
    ns.reflection = request.reflection
    ns.adaptive_exploits = request.adaptive_exploits
    ns.long_session = request.long_session
    ns.multi_model_consult = request.multi_model_consult
    ns.observer_mode = request.observer_mode
    ns.ultrathink = request.ultrathink
    ns.debug = request.debug
    ns.plain = request.plain
    ns.json = request.json_output
    ns.quiet = False
    ns.yes = request.yes
    ns.skills = request.skills_mode
    ns.skills_include = request.skills_include or None
    ns.skills_exclude = request.skills_exclude or None
    ns.no_skills_reselect = request.skills_no_reselect
    ns.reports_dir = request.reports_dir
    ns.resume = request.resume_source
    ns.http_port = None
    ns.mcp_transport = None
    ns.api_key_file = Path("secr.json")
    ns.no_api_key_prompt = True
    ns.setup_api_keys = False
    ns.menu = False
    ns.doctor = False
    ns.self_test = False
    ns.eval = False
    ns.demo = False
    ns.skills_list = False
    ns.list_plugins = False
    ns.daemon = False
    ns.api_host = None
    ns.api_port = None
    ns.model_strategy = "default"
    return ns
