"""Single-target ``--eval`` CLI entry (split from tools.eval_harness)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from tools.config_manager import load_validated_config
from tools.eval.metrics import _mint_run_id, compute_metrics, write_eval_report
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.exploit_agent import ExploitPermission, ExploitSettings
from tools.exploit_session import run_exploit_session
from tools.goal_engine import GoalEngine
from tools.mcp_session import open_exploit_mcp_session
from tools.model_router import build_router


def _eval_shim(name: str, default: Callable[..., Any]) -> Callable[..., Any]:
    """Resolve ``name`` through the ``tools.eval_harness`` compat shim at call time.

    Patch-seam contract (precedent: ``tools/campaign/phases.py`` resolves
    ``find_modules`` through ``tools.autonomous_orchestrator``): the suite
    historically patched ``tools.eval_harness.run_eval`` /
    ``docker_suite_up`` / ``docker_suite_down`` /
    ``open_exploit_mcp_session`` / ``default_check_executor``. Those tests
    keep patching the shim, so the call sites below resolve through it at
    call time instead of binding this module's globals directly.
    """
    try:
        import tools.eval_harness as _shim
    except ImportError:  # pragma: no cover - shim always present in-repo
        return default
    return getattr(_shim, name, default)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


async def run_eval(args: Any) -> int:
    """``--eval`` CLI entry. Returns 0 on success, 1 on error, 2 if no target."""
    target_ip = str(getattr(args, "target", "") or "").strip()
    if not target_ip:
        print("[!] --eval requires --target <ip>")
        return 2

    config_path = Path(getattr(args, "config", "config.yaml"))
    try:
        config = load_validated_config(config_path)
    except Exception as exc:
        print(f"[!] Could not load/validate config: {exc}")
        return 1

    eval_cfg = config.get("eval", {}) or {}
    output_dir = str(eval_cfg.get("output_dir", "reports/eval") or "reports/eval")
    max_rounds = int(eval_cfg.get("max_rounds", 30) or 30)
    write_markdown = bool(eval_cfg.get("write_markdown", True))
    write_html = bool(eval_cfg.get("write_html", True))

    run_id = _mint_run_id()
    eval_reports_dir = Path(output_dir) / run_id
    eval_reports_dir.mkdir(parents=True, exist_ok=True)
    workspace_root = eval_reports_dir / "exploit_workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  BreachPilot — Eval Harness (`--eval`)")
    print(f"  Target: {target_ip}")
    print(f"  Run ID: {run_id}")
    print(f"  Output: {eval_reports_dir}")
    print("=" * 60)

    # Build the model client exactly as main.py does (provider-aware).
    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

    ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
    registry = config.get("models", {}).get("registry")
    provider = get_ai_provider(config)
    if provider == "chatgpt":
        router = build_router(
            registry,
            host=ollama_host,
            provider="chatgpt",
            chatgpt_config=get_chatgpt_config(config),
            config=config,
        )
    elif provider == "opencode_go":
        router = build_router(
            registry,
            host=ollama_host,
            provider="opencode_go",
            opencode_go_config=get_opencode_go_config(config),
            config=config,
        )
    else:
        router = build_router(registry, host=ollama_host)
    model_alias = config.get("models", {}).get("default_alias", "glm")
    if provider == "opencode_go":
        # For opencode_go the alias namespace is the model id itself (like chatgpt)
        # Prefer the configured default_model when the ollama default_alias is stale
        model_alias = str(get_opencode_go_config(config).get("default_model") or "muse-spark-1.2-contributor")
    try:
        model_client = router.get_client(model_alias)
    except KeyError:
        if provider in ("chatgpt", "opencode_go"):
            from tools.model_router import build_model_client_for_provider

            router.register(
                model_alias,
                build_model_client_for_provider(
                    config,
                    model_alias,
                    request_timeout_seconds=None,
                ),
            )
        else:
            from tools.model_router import _build_model_client

            router.register(
                model_alias,
                _build_model_client(
                    model_alias,
                    host=ollama_host,
                    request_timeout_seconds=None,
                ),
            )
        model_client = router.get_client(model_alias)

    exploit_port = int(config.get("mcp", {}).get("http_port", 8001))
    mcp_transport = "stdio"

    # Attack-mode eval settings. ExploitPolicy is constructed INSIDE
    # run_exploit_session from these settings + the mission ScopeGate, so we do
    # not build a standalone policy here (it would be dead and would create a
    # spurious audit log next to the real one).
    exploit_settings = ExploitSettings(
        enabled=True,
        mode="attack",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=max_rounds,
        workspace_root=workspace_root,
        target_ip=target_ip,
    )

    # Pick the simplest attack preset that constructs without extra args.
    # ``initial_access`` is GATED; high_authorized_testing is HIGH (>= GATED),
    # so the goal resolves unblocked.
    goal = GoalEngine().get("initial_access", risk_profile="high_authorized_testing")

    # Probe the MCP exploit server with soft_fail so an unreachable server
    # degrades to an error report instead of raising.
    session_ok = False
    try:
        async with _eval_shim("open_exploit_mcp_session", open_exploit_mcp_session)(
            transport=mcp_transport,
            config_path=config_path,
            target_ip=target_ip,
            exploit_port=exploit_port,
            workspace=workspace_root,
            soft_fail=True,
        ) as session:
            if session is not None:
                session_ok = True
    except _EXC_GROUP_CATCH as exc:
        print(f"[!] MCP probe failed: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
    except Exception as exc:
        print(f"[!] MCP probe failed: {exc}")

    if not session_ok:
        print("[!] MCP exploit server did not boot; writing error metrics.")
        metrics = compute_metrics(
            None,
            run_id=run_id,
            target=target_ip,
            duration_seconds=0.0,
        )
        metrics.verdict = "error"
        metrics.outcome_summary = "MCP exploit server unavailable; eval aborted before session start."
        out_dir = write_eval_report(
            metrics,
            reports_root=output_dir,
            write_markdown=write_markdown,
            write_html=write_html,
        )
        print(f"  [i] verdict=error  out={out_dir}")
        return 1

    # Run the real exploit session. run_exploit_session opens its own MCP
    # session internally (the probe above only verified bootability).
    start = time.monotonic()
    try:
        result = await run_exploit_session(
            client=model_client,
            model=model_alias,
            target_ip=target_ip,
            mode="attack",
            goal=goal,
            exploit_settings=exploit_settings,
            config_path=config_path,
            mcp_transport=mcp_transport,
            exploit_port=exploit_port,
            reports_dir=eval_reports_dir,
        )
    except _EXC_GROUP_CATCH as exc:
        print(f"[!] Exploit session failed: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
        result = {
            "target_ip": target_ip,
            "total_actions": 0,
            "workspace": str(workspace_root),
            "audit_path": "",
            "records": [],
            "messages": [],
            "error": str(exc),
        }
    except Exception as exc:
        print(f"[!] Exploit session failed: {exc}")
        result = {
            "target_ip": target_ip,
            "total_actions": 0,
            "workspace": str(workspace_root),
            "audit_path": "",
            "records": [],
            "messages": [],
            "error": str(exc),
        }
    duration = time.monotonic() - start

    metrics = compute_metrics(
        result,
        run_id=run_id,
        target=target_ip,
        duration_seconds=round(duration, 3),
    )
    out_dir = write_eval_report(
        metrics,
        reports_root=output_dir,
        write_markdown=write_markdown,
        write_html=write_html,
    )

    print(f"  [i] verdict={metrics.verdict}  success_rate={metrics.success_rate:.1%}  out={out_dir}")
    print("=" * 60)
    return 0
