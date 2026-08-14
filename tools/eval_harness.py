"""Evaluation/benchmark harness for the Flow A exploit engine (`--eval`).

Runs a single attack-mode exploit session against ``--target``, then derives
structured :class:`EvalMetrics` from the ``run_exploit_agent`` final-result
dict and writes a JSON / Markdown / HTML report under
``reports/eval/<run_id>/``.

The boot sequence mirrors :func:`tools.self_test.run_self_test` and the attack
flow in ``main.py``: load validated config, build the Ollama model router,
probe the MCP exploit server with ``open_exploit_mcp_session(soft_fail=True)``,
then call :func:`tools.exploit_session.run_exploit_session`. Every MCP-wrapping
call uses ``_EXC_GROUP_CATCH`` from :mod:`tools.exceptions` so an anyio
``BaseExceptionGroup`` (subprocess death) is not silently swallowed.

This is a lab-only build: the operator runs it against infrastructure they own
or are explicitly authorized to test. The attack path is target-locked at the
MCP tool layer (the allowlist unions the runtime ``--target`` via
``EXPLOIT_TARGET``); the eval harness itself does not add any further gate.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.config_manager import load_validated_config
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.exploit_agent import ExploitPermission, ExploitSettings
from tools.exploit_session import run_exploit_session
from tools.goal_engine import GoalEngine
from tools.mcp_session import open_exploit_mcp_session
from tools.model_router import build_router

__all__ = [
    "EvalMetrics",
    "compute_metrics",
    "render_report",
    "render_markdown",
    "render_html",
    "write_eval_report",
    "run_eval",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Current UTC timestamp in ISO-8601 form (used for ``EvalMetrics.timestamp``)."""
    return datetime.now(timezone.utc).isoformat()


def _mint_run_id() -> str:
    """Mint a filesystem-friendly run id matching ``main.py``'s scheme."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _count_outcome(summary: str, label: str) -> int:
    """Extract an integer count from an outcome-summary string.

    The :class:`tools.exploit_agent._ToolOutcomeTracker` summary is a
    semi-structured string such as
    ``"... | compromises: 2; cred dumps: 1; partials: 3; ..."``. We parse it
    case-insensitively and return 0 when the label is absent or malformed.
    """
    match = re.search(rf"{re.escape(label)}\s*:\s*(\d+)", summary, re.IGNORECASE)
    if not match:
        return 0
    try:
        return int(match.group(1))
    except (ValueError, IndexError):
        return 0


_FAILURE_STATUS_EXACT = {"failed", "blocked", "error"}
_FAILURE_STATUS_SUBSTRINGS = ("fail", "error", "block")


def _record_is_failure(record: Any) -> bool:
    """Conservatively classify an audit record dict as a failure."""
    if not isinstance(record, dict):
        return False
    status = str(record.get("status", "") or "").lower()
    if not status:
        return False
    if status in _FAILURE_STATUS_EXACT:
        return True
    return any(kw in status for kw in _FAILURE_STATUS_SUBSTRINGS)


# ---------------------------------------------------------------------------
# EvalMetrics
# ---------------------------------------------------------------------------

@dataclass
class EvalMetrics:
    """Structured metrics derived from one eval run's final-result dict."""

    run_id: str = ""
    target: str = ""
    timestamp: str = ""
    total_actions: int = 0
    compromise_count: int = 0
    cred_dump_count: int = 0
    partial_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    outcome_summary: str = ""
    audit_path: str = ""
    records_count: int = 0
    verdict: str = "no_access"
    duration_seconds: float | None = None
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Emit a JSON-serializable dict (``duration_seconds`` kept as-is)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(
    final_result: dict[str, Any] | None,
    *,
    run_id: str = "",
    target: str = "",
    duration_seconds: float | None = None,
) -> EvalMetrics:
    """Derive :class:`EvalMetrics` from a ``run_exploit_agent`` final-result dict.

    Robust to ``None`` / missing keys / a ``None`` outcome summary: every field
    degrades to a safe default.
    """
    if not isinstance(final_result, dict):
        final_result = {}

    outcome_summary = str(final_result.get("outcome_summary", "") or "")
    compromise_count = _count_outcome(outcome_summary, "compromises")
    cred_dump_count = _count_outcome(outcome_summary, "cred dumps")
    partial_count = _count_outcome(outcome_summary, "partials")

    total_actions = int(final_result.get("total_actions", 0) or 0)
    records = final_result.get("records") or []
    records_count = len(records) if isinstance(records, list) else 0
    audit_path = str(final_result.get("audit_path", "") or "")

    failure_count = 0
    if isinstance(records, list):
        for record in records:
            if _record_is_failure(record):
                failure_count += 1

    evidence_refs: list[str] = []
    for key in ("evidence", "evidence_refs"):
        candidate = final_result.get(key)
        if isinstance(candidate, list):
            for item in candidate:
                evidence_refs.append(str(item))

    if total_actions == 0:
        success_rate = 0.0
    else:
        success_rate = (compromise_count + cred_dump_count) / max(total_actions, 1)
        if success_rate < 0.0:
            success_rate = 0.0
        elif success_rate > 1.0:
            success_rate = 1.0

    if compromise_count > 0:
        verdict = "compromised"
    elif cred_dump_count > 0:
        verdict = "cred_dump"
    elif partial_count > 0:
        verdict = "partial"
    elif total_actions > 0:
        verdict = "no_access"
    else:
        verdict = "error"

    return EvalMetrics(
        run_id=run_id,
        target=target,
        timestamp=_now_iso(),
        total_actions=total_actions,
        compromise_count=compromise_count,
        cred_dump_count=cred_dump_count,
        partial_count=partial_count,
        failure_count=failure_count,
        success_rate=success_rate,
        outcome_summary=outcome_summary,
        audit_path=audit_path,
        records_count=records_count,
        verdict=verdict,
        duration_seconds=duration_seconds,
        evidence_refs=evidence_refs,
    )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_report(metrics: EvalMetrics) -> dict[str, Any]:
    """Return a JSON-serializable dict view of ``metrics``."""
    return metrics.to_dict()


def render_markdown(metrics: EvalMetrics) -> str:
    """Render a readable Markdown report."""
    success_pct = f"{metrics.success_rate * 100:.1f}%"
    duration_str = "n/a" if metrics.duration_seconds is None else str(metrics.duration_seconds)
    lines = [
        "# Eval Report",
        "",
        f"- **Run ID**: {metrics.run_id}",
        f"- **Target**: {metrics.target}",
        f"- **Timestamp**: {metrics.timestamp}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Total actions | {metrics.total_actions} |",
        f"| Compromises | {metrics.compromise_count} |",
        f"| Credential dumps | {metrics.cred_dump_count} |",
        f"| Partials | {metrics.partial_count} |",
        f"| Failures | {metrics.failure_count} |",
        f"| Success rate | {success_pct} |",
        f"| Verdict | {metrics.verdict} |",
        f"| Records | {metrics.records_count} |",
        f"| Duration (s) | {duration_str} |",
        "",
        "## References",
        "",
        f"- Audit path: `{metrics.audit_path or 'n/a'}`",
    ]
    if metrics.evidence_refs:
        lines.append("")
        lines.append("## Evidence")
        lines.append("")
        for ref in metrics.evidence_refs:
            lines.append(f"- {ref}")
    if metrics.outcome_summary:
        lines.append("")
        lines.append("## Outcome Summary")
        lines.append("")
        lines.append(f"``{metrics.outcome_summary}``")
    return "\n".join(lines)


def render_html(metrics: EvalMetrics) -> str:
    """Render a minimal self-contained HTML report (no external dependencies)."""
    success_pct = f"{metrics.success_rate * 100:.1f}%"
    duration_str = "n/a" if metrics.duration_seconds is None else str(metrics.duration_seconds)
    rows = [
        ("Total actions", str(metrics.total_actions)),
        ("Compromises", str(metrics.compromise_count)),
        ("Credential dumps", str(metrics.cred_dump_count)),
        ("Partials", str(metrics.partial_count)),
        ("Failures", str(metrics.failure_count)),
        ("Success rate", success_pct),
        ("Verdict", metrics.verdict),
        ("Records", str(metrics.records_count)),
        ("Duration (s)", duration_str),
    ]
    body_rows = "\n".join(
        f"      <tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows
    )
    evidence_html = ""
    if metrics.evidence_refs:
        evidence_html = (
            "    <h2>Evidence</h2>\n    <ul>\n"
            + "\n".join(f"      <li>{ref}</li>" for ref in metrics.evidence_refs)
            + "\n    </ul>\n"
        )
    outcome_html = ""
    if metrics.outcome_summary:
        # Avoid a raw ``</pre>`` injection from a crafted summary.
        safe = metrics.outcome_summary.replace("<", "&lt;").replace(">", "&gt;")
        outcome_html = (
            "    <h2>Outcome Summary</h2>\n"
            f"    <pre>{safe}</pre>\n"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Eval Report — {metrics.run_id}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 56rem; }}
    h1 {{ border-bottom: 1px solid #ccc; padding-bottom: .3rem; }}
    table {{ border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ddd; padding: .4rem .8rem; text-align: left; }}
    th {{ background: #f5f5f5; }}
    pre {{ background: #f7f7f7; padding: .8rem; border-radius: .3rem; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>Eval Report</h1>
  <p><strong>Run ID:</strong> {metrics.run_id}<br>
     <strong>Target:</strong> {metrics.target}<br>
     <strong>Timestamp:</strong> {metrics.timestamp}</p>
  <h2>Metrics</h2>
  <table>
    <tbody>
{body_rows}
    </tbody>
  </table>
  <h2>References</h2>
  <p>Audit path: <code>{metrics.audit_path or 'n/a'}</code></p>
{evidence_html}{outcome_html}</body>
</html>
"""


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_eval_report(
    metrics: EvalMetrics,
    reports_root: Path | str = "reports/eval",
    *,
    write_markdown: bool = True,
    write_html: bool = True,
) -> Path:
    """Write ``eval_report.json`` (plus optional ``.md`` / ``.html``) and return the run dir.

    If ``metrics.run_id`` is empty, a fresh run id is minted and assigned back
    onto ``metrics`` so the caller can reference it.
    """
    if not metrics.run_id:
        metrics.run_id = _mint_run_id()

    out_dir = Path(reports_root) / metrics.run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "eval_report.json").write_text(
        json.dumps(render_report(metrics), indent=2, default=str),
        encoding="utf-8",
    )
    if write_markdown:
        (out_dir / "eval_report.md").write_text(render_markdown(metrics), encoding="utf-8")
    if write_html:
        (out_dir / "eval_report.html").write_text(render_html(metrics), encoding="utf-8")

    return out_dir


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
    print("  NetAttackAI — Eval Harness (`--eval`)")
    print(f"  Target: {target_ip}")
    print(f"  Run ID: {run_id}")
    print(f"  Output: {eval_reports_dir}")
    print("=" * 60)

    # Build the model client exactly as main.py does (provider-aware).
    from tools.config_manager import get_ai_provider, get_chatgpt_config
    ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
    registry = config.get("models", {}).get("registry")
    provider = get_ai_provider(config)
    if provider == "chatgpt":
        router = build_router(
            registry, host=ollama_host, provider="chatgpt",
            chatgpt_config=get_chatgpt_config(config), config=config,
        )
    else:
        router = build_router(registry, host=ollama_host)
    model_alias = config.get("models", {}).get("default_alias", "glm")
    try:
        model_client = router.get_client(model_alias)
    except KeyError:
        if provider == "chatgpt":
            from tools.model_router import build_model_client_for_provider
            router.register(model_alias, build_model_client_for_provider(
                config, model_alias, request_timeout_seconds=None,
            ))
        else:
            from tools.model_router import _build_model_client
            router.register(model_alias, _build_model_client(
                model_alias, host=ollama_host, request_timeout_seconds=None,
            ))
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
        async with open_exploit_mcp_session(
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
            metrics, reports_root=output_dir,
            write_markdown=write_markdown, write_html=write_html,
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
        metrics, reports_root=output_dir,
        write_markdown=write_markdown, write_html=write_html,
    )

    print(f"  [i] verdict={metrics.verdict}  success_rate={metrics.success_rate:.1%}  out={out_dir}")
    print("=" * 60)
    return 0


if __name__ == "__main__":  # pragma: no cover - manual entry
    import asyncio
    from argparse import Namespace

    class _Args(Namespace):
        target = "127.0.0.1"
        config = Path("config.yaml")

    raise SystemExit(asyncio.run(run_eval(_Args())))
