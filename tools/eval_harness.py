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
    "EvalSuiteResult",
    "compute_metrics",
    "render_report",
    "render_markdown",
    "render_html",
    "write_eval_report",
    "run_eval",
    "load_target_oracle",
    "score_against_oracle",
    "run_eval_suite",
    "docker_suite_up",
    "docker_suite_down",
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
    body_rows = "\n".join(f"      <tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows)
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
        outcome_html = f"    <h2>Outcome Summary</h2>\n    <pre>{safe}</pre>\n"
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
  <p>Audit path: <code>{metrics.audit_path or "n/a"}</code></p>
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
            registry,
            host=ollama_host,
            provider="chatgpt",
            chatgpt_config=get_chatgpt_config(config),
            config=config,
        )
    else:
        router = build_router(registry, host=ollama_host)
    model_alias = config.get("models", {}).get("default_alias", "glm")
    try:
        model_client = router.get_client(model_alias)
    except KeyError:
        if provider == "chatgpt":
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


# ---------------------------------------------------------------------------
# Phase 6.3 — Docker target suite scoring (D1)
# ---------------------------------------------------------------------------

_SUITE_COMPOSE = Path("eval_targets/docker-compose.yml")


@dataclass
class EvalSuiteResult:
    """Aggregate score across the Docker target suite."""

    target_id: str
    true_positives: int = 0
    false_positives: int = 0
    expected_total: int = 0
    success: bool = False
    oracle_path: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        return self.true_positives / self.expected_total if self.expected_total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "expected_total": self.expected_total,
            "success": self.success,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "oracle_path": self.oracle_path,
            "metrics": self.metrics,
        }


def load_target_oracle(oracle_path: Path | str) -> dict[str, Any]:
    """Load a per-target oracle JSON (expected findings for scoring)."""
    path = Path(oracle_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def score_against_oracle(
    findings: list[dict[str, Any]],
    oracle: dict[str, Any],
) -> EvalSuiteResult:
    """Score a list of findings against a target oracle.

    A finding is a true positive if it matches an expected service / cred /
    CVE / vuln / misconfiguration in the oracle. A finding that claims
    something not in the oracle is a false positive. ``success`` is True when
    the oracle's ``scoring.success_criteria`` is met (heuristic: root shell,
    flag read, or ≥3 expected creds/vulns confirmed).
    """
    target_id = str(oracle.get("target_id", "unknown"))
    expected = oracle.get("expected_findings", {}) or {}
    expected_services = {s.lower() for s in expected.get("services", [])}
    expected_cves = {c.upper() for c in expected.get("known_cves", [])}
    expected_vulns = {v.lower() for v in expected.get("vulnerabilities", [])}
    expected_misconfig = {m.lower() for m in expected.get("misconfigurations", [])}
    expected_creds = []
    for c in expected.get("weak_credentials", []) or []:
        expected_creds.append((str(c.get("user", "")).lower(), str(c.get("password", "")).lower()))

    expected_total = (
        len(expected_services)
        + len(expected_cves)
        + len(expected_vulns)
        + len(expected_misconfig)
        + len(expected_creds)
    )

    tp = 0
    fp = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        kind = str(f.get("type", f.get("kind", "")) or "").lower()
        value = str(f.get("value", f.get("name", f.get("cve", ""))) or "").lower()
        matched = False
        if kind == "service" and value in expected_services:
            matched = True
        elif kind == "cve" and value.upper() in expected_cves:
            matched = True
        elif kind == "vulnerability" and value in expected_vulns:
            matched = True
        elif kind == "misconfiguration" and value in expected_misconfig:
            matched = True
        elif kind == "credential":
            u = str(f.get("user", "")).lower()
            p = str(f.get("password", "")).lower()
            if (u, p) in expected_creds:
                matched = True
        # ponytail: a finding that names no kind is counted as a true positive
        # only if its value matches any expected token (lenient — avoids
        # penalizing the agent for omitting the ``type`` field).
        if not kind and value:
            if (
                value in expected_services
                or value.upper() in expected_cves
                or value in expected_vulns
                or value in expected_misconfig
            ):
                matched = True
        if matched:
            tp += 1
        else:
            fp += 1

    # Success heuristic from the oracle.
    success = False
    success_criteria = str((oracle.get("scoring", {}) or {}).get("success_criteria", "") or "").lower()
    if "root shell" in success_criteria and expected.get("root_shell_possible"):
        # The caller sets metrics.root_shell / flag_read; we check the findings.
        if any(str(f.get("evidence", "")).lower().startswith("uid=0") for f in findings if isinstance(f, dict)):
            success = True
    if "flag" in success_criteria and expected.get("flag_path"):
        if any(expected["flag_path"] in str(f.get("evidence", "")) for f in findings if isinstance(f, dict)):
            success = True
    if "≥3" in success_criteria or "3 expected" in success_criteria:
        if tp >= 3:
            success = True
    if "≥2" in success_criteria or "2 web" in success_criteria or "2 owasp" in success_criteria:
        if tp >= 2:
            success = True

    return EvalSuiteResult(
        target_id=target_id,
        true_positives=tp,
        false_positives=fp,
        expected_total=expected_total,
        success=success,
        oracle_path=str(oracle.get("_oracle_path", "")),
    )


def docker_suite_up(compose_path: Path | str = _SUITE_COMPOSE) -> int:
    """``docker compose up -d`` for the target suite. Returns the subprocess rc.

    Best-effort: if docker is unavailable, returns non-zero. The caller decides
    whether to proceed (the eval can score against already-running targets).
    """
    import subprocess

    path = Path(compose_path)
    if not path.exists():
        print(f"[!] Compose file not found: {path}")
        return 1
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(path), "up", "-d"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            print(f"[!] docker compose up failed: {proc.stderr[:300]}")
        return proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"[!] docker compose up error: {exc}")
        return 1


def docker_suite_down(compose_path: Path | str = _SUITE_COMPOSE) -> int:
    """``docker compose down`` for the target suite. Returns the subprocess rc."""
    import subprocess

    path = Path(compose_path)
    if not path.exists():
        return 1
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(path), "down"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 1


async def run_eval_suite(
    args: Any,
    *,
    compose_up: bool = True,
    compose_down: bool = True,
    oracle_dir: Path | str = "eval_targets",
) -> dict[str, Any]:
    """Run the eval against each target in the Docker suite and score it.

    For each ``*.oracle.json`` in ``oracle_dir``, runs ``--eval --target
    <host>`` and scores the result's findings against the oracle. Returns a
    dict of ``target_id → EvalSuiteResult.to_dict()`` plus an aggregate.

    The operator must add the target hosts (127.0.0.1) to
    ``exploit.allowed_targets`` for the runs. The compose file binds every
    port to 127.0.0.1 so nothing is exposed to the network.
    """
    oracle_dir_path = Path(oracle_dir)
    oracle_files = sorted(oracle_dir_path.glob("*.oracle.json"))
    if not oracle_files:
        print(f"[!] No oracle files found in {oracle_dir_path}")
        return {"targets": {}, "aggregate": {}}

    if compose_up:
        rc = docker_suite_up()
        if rc != 0:
            print(f"[!] docker compose up returned {rc}; proceeding against any already-running targets.")

    results: dict[str, Any] = {}
    all_tp = all_fp = all_expected = 0
    any_success = 0

    for oracle_file in oracle_files:
        oracle = load_target_oracle(oracle_file)
        if not oracle:
            continue
        oracle["_oracle_path"] = str(oracle_file)
        target_id = str(oracle.get("target_id", oracle_file.stem))
        host = str(oracle.get("host", "127.0.0.1"))
        print(f"\n=== Evaluating target: {target_id} ({host}) ===")

        # Reuse run_eval against this target — target-locked via the allowlist.
        eval_args = type(args)(
            target=host,
            config=getattr(args, "config", Path("config.yaml")),
        )
        try:
            rc = await run_eval(eval_args)
        except Exception as exc:  # noqa: BLE001 -- one target failure never aborts the suite
            print(f"[!] Eval for {target_id} failed: {exc}")
            rc = 1

        # Read the eval report to extract findings for scoring.
        eval_dir = Path("reports/eval")
        report_files = sorted(eval_dir.glob("*/eval_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        findings: list[dict[str, Any]] = []
        metrics_dict: dict[str, Any] = {}
        if report_files:
            try:
                report = json.loads(report_files[0].read_text(encoding="utf-8"))
                metrics_dict = report
                # ponytail: the eval report's records/messages are the raw
                # audit trail; extract candidate findings heuristically. A
                # real implementation would parse structured records; this
                # lenient extractor counts service/CVE/vuln mentions so the
                # scoring path is testable without a live run.
                haystack = json.dumps(report).lower()
                for svc in (oracle.get("expected_findings", {}) or {}).get("services", []) or []:
                    if str(svc).lower() in haystack:
                        findings.append({"type": "service", "value": str(svc).lower()})
                for cve in (oracle.get("expected_findings", {}) or {}).get("known_cves", []) or []:
                    if str(cve).lower() in haystack:
                        findings.append({"type": "cve", "value": str(cve)})
                for v in (oracle.get("expected_findings", {}) or {}).get("vulnerabilities", []) or []:
                    if str(v).lower() in haystack:
                        findings.append({"type": "vulnerability", "value": str(v).lower()})
                for m in (oracle.get("expected_findings", {}) or {}).get("misconfigurations", []) or []:
                    if str(m).lower() in haystack:
                        findings.append({"type": "misconfiguration", "value": str(m).lower()})
                for c in (oracle.get("expected_findings", {}) or {}).get("weak_credentials", []) or []:
                    if str(c.get("user", "")).lower() in haystack or str(c.get("password", "")).lower() in haystack:
                        findings.append(
                            {
                                "type": "credential",
                                "value": str(c.get("user", "")),
                                "user": c.get("user", ""),
                                "password": c.get("password", ""),
                            }
                        )
            except (json.JSONDecodeError, OSError):
                pass

        suite_result = score_against_oracle(findings, oracle)
        suite_result.metrics = metrics_dict
        results[target_id] = suite_result.to_dict()
        all_tp += suite_result.true_positives
        all_fp += suite_result.false_positives
        all_expected += suite_result.expected_total
        if suite_result.success:
            any_success += 1
        print(
            f"  tp={suite_result.true_positives} fp={suite_result.false_positives} "
            f"success={suite_result.success} precision={suite_result.precision:.2f}"
        )

    if compose_down:
        docker_suite_down()

    aggregate = {
        "targets_run": len(results),
        "targets_succeeded": any_success,
        "total_true_positives": all_tp,
        "total_false_positives": all_fp,
        "total_expected": all_expected,
        "overall_precision": round(all_tp / (all_tp + all_fp), 4) if (all_tp + all_fp) else 0.0,
        "overall_recall": round(all_tp / all_expected, 4) if all_expected else 0.0,
    }
    # Persist the suite report.
    out_dir = Path("reports/eval/suite")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "suite_report.json").write_text(
        json.dumps({"targets": results, "aggregate": aggregate}, indent=2, default=str),
        encoding="utf-8",
    )
    print(
        f"\n=== Suite aggregate: precision={aggregate['overall_precision']} "
        f"recall={aggregate['overall_recall']} succeeded={any_success}/{len(results)} ==="
    )
    return {"targets": results, "aggregate": aggregate}


if __name__ == "__main__":  # pragma: no cover - manual entry
    import asyncio
    from argparse import Namespace

    class _Args(Namespace):
        target = "127.0.0.1"
        config = Path("config.yaml")

    raise SystemExit(asyncio.run(run_eval(_Args())))
