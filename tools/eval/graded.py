"""Graded eval loop: flag-oracle scoring, verify sessions, skipped-report
handling (split from tools.eval_harness; baseline persistence lives in
tools.eval.baseline)."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from tools.eval.live import (
    LiveOutcome,
    ReliabilityMetrics,
    RunProvenance,
    TrialTelemetry,
    aggregate_finding_lifecycle,
    build_run_provenance,
    classify_live_outcome,
    compute_reliability_metrics,
    extract_trial_telemetry,
)
from tools.eval.metrics import _mint_run_id, _now_iso
from tools.eval.suite import (
    EvalSuiteResult,
    docker_suite_down,
    docker_suite_up,
    load_target_oracle,
    score_against_oracle,
)
from tools.eval_checks import CheckExecutor, default_check_executor
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
# Feature 1 — Graded eval loop (flag oracle schema v2 + baseline/regression)
# ---------------------------------------------------------------------------

#: Agent runner seam: ``(target_id, oracle, config) -> dict`` returning at
#: minimum ``{"findings": [...], "outcome_summary": str, "run_dir": str|None}``.
AgentRunner = Callable[[str, dict[str, Any], dict[str, Any]], Any]

#: In-memory config plumbing keys consumed by :func:`default_agent_runner`.
#: They are set by :func:`run_graded_eval` on its deep-copied config dict and
#: never persisted to config.yaml (same policy as main.py's api.serve_webui
#: in-memory override).
_CONFIG_PATH_KEY = "_config_path"
_WORKSPACE_KEY = "_eval_workspace_root"


@dataclass
class FlagCheckResult:
    """Outcome of one independently-verified oracle flag check."""

    flag_id: str
    passed: bool
    detail: str
    check: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TargetScore:
    """Graded score for one oracle target.

    ``score`` is a 0.0-1.0 composite: the unweighted mean of

    1. the flag ratio (``flags_captured / flags_total``; 1.0 when the target
       declares no flags),
    2. the host-owned ratio (``hosts_owned / hosts_total``), and
    3. the findings precision-recall F1 (harmonic mean of
       ``true_positives / (tp + fp)`` and ``true_positives / expected_total``,
       0.0 when both are zero), computed by the existing
       :func:`score_against_oracle` paper-scoring semantics.
    """

    target_id: str
    flags: list[FlagCheckResult] = field(default_factory=list)
    hosts_owned: int = 0
    hosts_total: int = 0
    flags_captured: int = 0
    flags_total: int = 0
    findings_verified: int = 0
    findings_claimed: int = 0
    success: bool = False
    score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def host_owned(self) -> bool:
        return self.hosts_total > 0 and self.hosts_owned >= self.hosts_total

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["flags"] = [f.to_dict() for f in self.flags]
        data["host_owned"] = self.host_owned
        return data


def _f1_score(precision: float, recall: float) -> float:
    if precision + recall <= 0.0:
        return 0.0
    return 2.0 * precision * recall / (precision + recall)


def _build_target_score(
    target_id: str,
    oracle: dict[str, Any],
    flag_results: list[FlagCheckResult],
    suite_result: EvalSuiteResult,
    findings_claimed: int,
) -> TargetScore:
    """Evaluate ``host_owned_when`` over flag results and compute the composite."""
    flags_total = len(flag_results)
    flags_captured = sum(1 for f in flag_results if f.passed)
    owned = _host_owned_when_met(flag_results, oracle.get("host_owned_when", "any"))
    hosts_total = 1
    hosts_owned = 1 if owned else 0

    precision = suite_result.precision
    recall = suite_result.recall
    findings_f1 = _f1_score(precision, recall)
    flags_ratio = (flags_captured / flags_total) if flags_total else 1.0
    host_ratio = (hosts_owned / hosts_total) if hosts_total else 1.0
    score = (flags_ratio + host_ratio + findings_f1) / 3.0

    return TargetScore(
        target_id=target_id,
        flags=flag_results,
        hosts_owned=hosts_owned,
        hosts_total=hosts_total,
        flags_captured=flags_captured,
        flags_total=flags_total,
        findings_verified=suite_result.true_positives,
        findings_claimed=findings_claimed,
        success=owned,
        score=round(score, 4),
        details={
            "findings_false_positives": suite_result.false_positives,
            "findings_expected_total": suite_result.expected_total,
            "findings_precision": round(precision, 4),
            "findings_recall": round(recall, 4),
        },
    )


def _host_owned_when_met(flag_results: list[FlagCheckResult], host_owned_when: Any) -> bool:
    """Evaluate the oracle's ``host_owned_when`` condition over flag results.

    - ``"any"`` (default) — the host counts as owned when at least one flag
      was captured.
    - ``"all"`` — every flag must be captured.
    - a list of flag ids — all of the listed flags must be captured (unknown
      ids simply count as uncaptured; an empty list falls back to ``any``).
    """
    captured = {f.flag_id for f in flag_results if f.passed}
    if isinstance(host_owned_when, (list, tuple)):
        required = [str(fid) for fid in host_owned_when]
        if not required:
            return bool(captured)
        return all(fid in captured for fid in required)
    if str(host_owned_when or "").strip().lower() == "all":
        return bool(flag_results) and len(captured) == len(flag_results)
    # "any" (and any unrecognized value) falls back to the default.
    return bool(captured)


@dataclass
class EvalReport:
    """Aggregate graded report across the oracle target suite."""

    run_id: str = ""
    timestamp: str = ""
    targets: list[TargetScore] = field(default_factory=list)
    live_outcome: str = LiveOutcome.FAIL
    provenance: RunProvenance = field(default_factory=RunProvenance)
    trials: list[TrialTelemetry] = field(default_factory=list)
    reliability: ReliabilityMetrics = field(default_factory=ReliabilityMetrics)

    @property
    def targets_run(self) -> int:
        return len(self.targets)

    @property
    def targets_succeeded(self) -> int:
        return sum(1 for t in self.targets if t.success)

    @property
    def flags_captured_total(self) -> int:
        return sum(t.flags_captured for t in self.targets)

    @property
    def flags_total_total(self) -> int:
        return sum(t.flags_total for t in self.targets)

    @property
    def hosts_owned_total(self) -> int:
        return sum(t.hosts_owned for t in self.targets)

    @property
    def hosts_total_total(self) -> int:
        return sum(t.hosts_total for t in self.targets)

    @property
    def findings_verified_total(self) -> int:
        return sum(t.findings_verified for t in self.targets)

    @property
    def findings_claimed_total(self) -> int:
        return sum(t.findings_claimed for t in self.targets)

    @property
    def overall_score(self) -> float:
        if not self.targets:
            return 0.0
        return round(sum(t.score for t in self.targets) / len(self.targets), 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "live_outcome": self.live_outcome,
            "provenance": self.provenance.to_dict(),
            "targets": [t.to_dict() for t in self.targets],
            "trials": [t.to_dict() for t in self.trials],
            "reliability": self.reliability.to_dict(),
            "aggregate": {
                "targets_run": self.targets_run,
                "targets_succeeded": self.targets_succeeded,
                "flags_captured": self.flags_captured_total,
                "flags_total": self.flags_total_total,
                "hosts_owned": self.hosts_owned_total,
                "hosts_total": self.hosts_total_total,
                "findings_verified": self.findings_verified_total,
                "findings_claimed": self.findings_claimed_total,
                "overall_score": self.overall_score,
            },
        }

    def _reliability_lines(self) -> list[str]:
        """Human-readable reliability section (shared by markdown/HTML paths)."""
        rel = self.reliability
        prov = self.provenance
        lines = [
            f"- **Live outcome**: `{rel.live_outcome}`",
            f"- **Verified compromise rate**: {rel.verified_compromise_rate:.1%}",
            f"- **False-compromise rate**: {rel.false_compromise_rate:.1%}",
            f"- **Stuck-loop rate**: {rel.stuck_loop_rate:.1%}",
            f"- **Duplicate actions**: {rel.duplicate_action_count}",
            f"- **Mean actions to verified objective**: {rel.mean_actions_to_verified_objective}",
            f"- **Timeout rate**: {rel.timeout_rate:.1%}",
            f"- **Scope-rejection rate**: {rel.scope_rejection_rate:.3%}",
            f"- **Scope violations reaching network layer**: {rel.scope_violation_count} (must be 0)",
            f"- **Tool error rate**: {rel.tool_error_rate:.1%}",
            f"- **Tokens per verified scenario**: {rel.tokens_per_verified_scenario}",
            f"- **Findings reproduced twice**: {rel.findings_reproduced_twice_count}"
            f"/{rel.findings_reproduced_twice_denominator} ({rel.findings_reproduced_twice_rate:.1%})",
            (
                "- **Mean time finding → verified remediation**: "
                f"{rel.mean_time_to_remediation_seconds}s over {rel.remediated_count} remediated"
                if rel.mean_time_to_remediation_seconds is not None
                else f"- **Mean time finding → verified remediation**: pending collection "
                f"({rel.remediated_count} remediated)"
            ),
            "",
            "## Provenance",
            "",
            f"- **Model**: `{prov.model_alias or 'n/a'}` (provider `{prov.provider or 'n/a'}`)",
            f"- **Scenario version**: `{prov.scenario_version or 'n/a'}`",
            f"- **Code revision**: `{prov.code_revision or 'n/a'}`",
            f"- **Seed**: `{prov.seed or 'n/a'}`",
            f"- **Action budget**: {prov.action_budget} (max_rounds {prov.max_rounds}, trials {prov.trials})",
            f"- **Sandbox**: {'enabled' if prov.sandbox_enabled else 'disabled'}"
            + (f" (`{prov.sandbox_image}`)" if prov.sandbox_image else ""),
        ]
        if rel.success_rate_by_family:
            lines += ["", "## Success rate by vulnerability family", ""]
            for family in sorted(rel.success_rate_by_family):
                lines.append(f"- `{family}`: {rel.success_rate_by_family[family]:.1%}")
        return lines

    def render_markdown(self) -> str:
        """Render a readable Markdown report (matching render_markdown style)."""
        lines = [
            "# Graded Eval Report",
            "",
            f"- **Run ID**: {self.run_id}",
            f"- **Timestamp**: {self.timestamp}",
            f"- **Targets**: {self.targets_run} (succeeded: {self.targets_succeeded})",
            f"- **Overall score**: {self.overall_score}",
            "",
            "## Reliability",
            "",
            *self._reliability_lines(),
            "",
            "## Targets",
            "",
            "| Target | Score | Flags | Host owned | Findings (verified/claimed) | Success |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for t in self.targets:
            skipped = " (skipped)" if t.details.get("skipped") else ""
            lines.append(
                f"| {t.target_id}{skipped} | {t.score} | {t.flags_captured}/{t.flags_total} "
                f"| {t.hosts_owned}/{t.hosts_total} | {t.findings_verified}/{t.findings_claimed} "
                f"| {t.success} |"
            )
        lines.append("")
        lines.append("## Flags")
        lines.append("")
        for t in self.targets:
            for f in t.flags:
                status = "PASS" if f.passed else "FAIL"
                lines.append(f"- `{status}` {t.target_id}/{f.flag_id}: {f.detail}")
        return "\n".join(lines)

    def render_html(self) -> str:
        """Render a minimal self-contained HTML report (no external dependencies)."""
        rows = "\n".join(
            f"      <tr><td>{t.target_id}</td><td>{t.score}</td><td>{t.flags_captured}/{t.flags_total}</td>"
            f"<td>{t.hosts_owned}/{t.hosts_total}</td><td>{t.findings_verified}/{t.findings_claimed}</td>"
            f"<td>{t.success}</td></tr>"
            for t in self.targets
        )
        flag_rows = "\n".join(
            f"      <li>{'PASS' if f.passed else 'FAIL'} {t.target_id}/{f.flag_id}: {f.detail}</li>"
            for t in self.targets
            for f in t.flags
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Graded Eval Report — {self.run_id}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 56rem; }}
    h1 {{ border-bottom: 1px solid #ccc; padding-bottom: .3rem; }}
    table {{ border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ddd; padding: .4rem .8rem; text-align: left; }}
    th {{ background: #f5f5f5; }}
  </style>
</head>
<body>
  <h1>Graded Eval Report</h1>
  <p><strong>Run ID:</strong> {self.run_id}<br>
     <strong>Timestamp:</strong> {self.timestamp}<br>
     <strong>Overall score:</strong> {self.overall_score}</p>
  <h2>Targets</h2>
  <table>
    <thead>
      <tr><th>Target</th><th>Score</th><th>Flags</th><th>Host owned</th><th>Findings</th><th>Success</th></tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <h2>Flag checks</h2>
  <ul>
{flag_rows}
  </ul>
</body>
</html>
"""


def verify_flag_check(check: dict[str, Any], executor: CheckExecutor) -> FlagCheckResult:
    """Verify one oracle flag entry via the injected executor (never agent claims).

    ``check`` is the flag entry from the oracle's ``flags`` list
    (``{"id", "description", "check": {...}}``); a bare check spec
    (``{"type": ...}`` with no nested ``check``) is also accepted, with the
    id falling back to the check type.

    This function is sync. The graded loop calls it through
    ``asyncio.to_thread`` so the default executor can bridge an async MCP
    session onto its bound loop without deadlocking.
    """
    spec: dict[str, Any] = check if isinstance(check, dict) else {}
    nested = spec.get("check")
    if isinstance(nested, dict):
        spec = nested
    flag_id = str(check.get("id", "") or "") if isinstance(check, dict) else ""
    if not flag_id:
        flag_id = str(spec.get("id", "") or spec.get("type", "") or "unnamed_flag")
    try:
        passed, detail = executor(spec)
    except Exception as exc:  # noqa: BLE001 -- an executor crash is a failed check, never an eval abort
        passed, detail = False, f"executor error: {exc}"
    return FlagCheckResult(flag_id=flag_id, passed=bool(passed), detail=detail, check=spec)


# ---------------------------------------------------------------------------
# Graded eval loop
# ---------------------------------------------------------------------------


def _oracle_target_ids(oracle_dir: Path) -> list[str]:
    return sorted(p.name[: -len(".oracle.json")] for p in oracle_dir.glob("*.oracle.json"))


async def _open_verify_session(host: str, config: dict[str, Any]) -> "tuple[Any, Any, Any]":
    """Open a soft-fail MCP session used only for independent flag verification.

    Returns ``(cm, session, loop)`` — ``(None, None, None)`` when the MCP
    server did not boot (HTTP/file checks still verify; ``shell_command``
    degrades to UNVERIFIED). Mirrors run_eval's probe with ``_EXC_GROUP_CATCH``
    handling; the caller must ``__aexit__`` the returned ``cm`` when
    ``session is not None``.
    """
    config_path = Path(str(config.get(_CONFIG_PATH_KEY, "config.yaml") or "config.yaml"))
    exploit_port = int((config.get("mcp", {}) or {}).get("http_port", 8001) or 8001)
    try:
        cm = _eval_shim("open_exploit_mcp_session", open_exploit_mcp_session)(
            transport="stdio",
            config_path=config_path,
            target_ip=host,
            exploit_port=exploit_port,
            soft_fail=True,
        )
        session = await cm.__aenter__()
    except _EXC_GROUP_CATCH as exc:
        print(f"[!] Flag-verify MCP session failed: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
        return None, None, None
    except Exception as exc:
        print(f"[!] Flag-verify MCP session failed: {exc}")
        return None, None, None
    return cm, session, asyncio.get_running_loop()


async def _close_verify_session(cm: Any, entered: bool) -> None:
    if not entered:
        return
    try:
        await cm.__aexit__(None, None, None)
    except _EXC_GROUP_CATCH as exc:
        print(f"[!] Flag-verify MCP session teardown failed: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
    except Exception:
        pass


async def default_agent_runner(target_id: str, oracle: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Default agent runner: a thin wrapper over run_eval's direct-runner path.

    Deep-copies ``config`` and pins ``exploit.allowed_targets`` to include the
    oracle host (127.0.0.1) — an in-memory union, never a replacement and
    never persisted to config.yaml — then runs the same ExploitSettings +
    GoalEngine + MCP-session sequence as :func:`run_eval`.

    Returns ``{"findings": [...], "outcome_summary": str, "run_dir": str|None}``
    (findings extracted from the final-result dict with the same lenient
    heuristic the legacy suite scorer uses) plus the reliability-telemetry
    keys :func:`extract_trial_telemetry` reads (``total_actions``,
    ``records``, ``attack_focus``, ``verdict_mismatch``,
    ``cancelled_by_operator``, ``total_tokens``, ``duration_seconds``).
    Custom runners may return only findings — missing keys degrade to
    safe defaults downstream.
    """
    cfg = copy.deepcopy(config)
    host = str(oracle.get("host", "127.0.0.1"))
    exploit_cfg = cfg.setdefault("exploit", {})
    allowed = list(exploit_cfg.get("allowed_targets", []) or [])
    if host not in allowed:
        allowed.append(host)  # in-memory union only; never persisted to config.yaml
    exploit_cfg["allowed_targets"] = allowed

    config_path = Path(str(cfg.get(_CONFIG_PATH_KEY, "config.yaml") or "config.yaml"))
    eval_cfg = cfg.get("eval", {}) or {}
    workspace_root = (
        Path(str(cfg.get(_WORKSPACE_KEY, ""))) if cfg.get(_WORKSPACE_KEY) else Path("reports/eval/eval_workspace")
    )
    workspace_root.mkdir(parents=True, exist_ok=True)
    max_rounds = int(eval_cfg.get("max_rounds", 30) or 30)

    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

    ollama_host = cfg.get("ollama", {}).get("host", "https://api.ollama.com")
    registry = cfg.get("models", {}).get("registry")
    provider = get_ai_provider(cfg)
    if provider == "chatgpt":
        router = build_router(
            registry,
            host=ollama_host,
            provider="chatgpt",
            chatgpt_config=get_chatgpt_config(cfg),
            config=cfg,
        )
    elif provider == "opencode_go":
        router = build_router(
            registry,
            host=ollama_host,
            provider="opencode_go",
            opencode_go_config=get_opencode_go_config(cfg),
            config=cfg,
        )
    else:
        router = build_router(registry, host=ollama_host)
    model_alias = cfg.get("models", {}).get("default_alias", "glm")
    if provider == "opencode_go":
        model_alias = str(get_opencode_go_config(cfg).get("default_model") or "muse-spark-1.2-contributor")
    try:
        model_client = router.get_client(model_alias)
    except KeyError:
        from tools.model_router import _build_model_client, build_model_client_for_provider

        if provider in ("chatgpt", "opencode_go"):
            router.register(
                model_alias, build_model_client_for_provider(cfg, model_alias, request_timeout_seconds=None)
            )
        else:
            router.register(
                model_alias, _build_model_client(model_alias, host=ollama_host, request_timeout_seconds=None)
            )
        model_client = router.get_client(model_alias)

    exploit_settings = ExploitSettings(
        enabled=True,
        mode="attack",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=max_rounds,
        workspace_root=workspace_root,
        target_ip=host,
    )
    goal = GoalEngine().get("initial_access", risk_profile="high_authorized_testing")

    result: dict[str, Any] = {}
    try:
        result = await run_exploit_session(
            client=model_client,
            model=model_alias,
            target_ip=host,
            mode="attack",
            goal=goal,
            exploit_settings=exploit_settings,
            config_path=config_path,
            mcp_transport="stdio",
            exploit_port=int((cfg.get("mcp", {}) or {}).get("http_port", 8001) or 8001),
            reports_dir=workspace_root,
        )
    except _EXC_GROUP_CATCH as exc:
        print(f"[!] Exploit session failed for {target_id}: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
        result = {"outcome_summary": "", "findings": [], "error": str(exc)}
    except Exception as exc:
        print(f"[!] Exploit session failed for {target_id}: {exc}")
        result = {"outcome_summary": "", "findings": [], "error": str(exc)}

    telemetry_keys = (
        "total_actions",
        "records",
        "attack_focus",
        "verdict_mismatch",
        "cancelled_by_operator",
        "total_tokens",
        "duration_seconds",
        "stuck_loop",
    )
    payload: dict[str, Any] = {
        "findings": _findings_from_result(result),
        "outcome_summary": str(result.get("outcome_summary", "") or ""),
        "run_dir": str(result.get("workspace", "")) or None,
    }
    if isinstance(result, dict):
        for key in telemetry_keys:
            if key in result:
                payload[key] = result[key]
    return payload


def _findings_from_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract claimed findings from a final-result dict (graded-loop contract).

    The agent's claims are only ever used for the findings precision/recall
    component — flags are decided exclusively by the executor.
    """
    findings: list[dict[str, Any]] = []
    if not isinstance(result, dict):
        return findings
    candidate = result.get("findings")
    if isinstance(candidate, list):
        findings.extend(f for f in candidate if isinstance(f, dict))
    return findings


async def run_graded_eval(
    target_ids: list[str] | None,
    config: dict[str, Any],
    *,
    runner: AgentRunner | None = None,
    compose_up: bool = True,
    compose_down: bool = True,
    oracle_dir: str | Path = "eval_targets",
    now_fn: Callable[[], str] | None = None,
) -> EvalReport:
    """Run the graded eval loop across oracle targets (schema v2).

    For each ``*.oracle.json`` target: load the oracle, run the agent via the
    injectable ``runner`` (default :func:`default_agent_runner`), score the
    claimed findings with the existing :func:`score_against_oracle` semantics,
    then verify every flag INDEPENDENTLY via :func:`verify_flag_check` — the
    executor is the truth source; agent claims never decide a flag. The
    oracle's ``host_owned_when`` condition is evaluated over the flag results
    and everything folds into a :class:`TargetScore` composite.

    Writes ``<output_dir>/<run_id>/report.json`` (plus ``report.md`` /
    ``report.html`` when ``eval.write_markdown`` / ``eval.write_html``) and
    returns the :class:`EvalReport`.
    """
    oracle_dir_path = Path(oracle_dir)
    if target_ids is None or not target_ids:
        target_ids = _oracle_target_ids(oracle_dir_path)
    runner_fn: AgentRunner = runner if runner is not None else default_agent_runner

    eval_cfg = config.get("eval", {}) or {}
    output_dir = Path(str(eval_cfg.get("output_dir", "reports/eval") or "reports/eval"))
    write_markdown = bool(eval_cfg.get("write_markdown", True))
    write_html = bool(eval_cfg.get("write_html", True))
    run_id = _mint_run_id()
    timestamp = now_fn() if now_fn is not None else _now_iso()
    report = EvalReport(
        run_id=run_id,
        timestamp=timestamp,
        provenance=build_run_provenance(config, trial_count=len(target_ids or [])),
    )

    workspace_root = output_dir / run_id / "exploit_workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    # In-memory plumbing for the default runner / verify session (deep-copied
    # config; these keys are never written back to config.yaml).
    cfg = copy.deepcopy(config)
    cfg[_CONFIG_PATH_KEY] = str(cfg.get(_CONFIG_PATH_KEY, "config.yaml") or "config.yaml")
    cfg[_WORKSPACE_KEY] = str(workspace_root)

    if compose_up:
        rc = _eval_shim("docker_suite_up", docker_suite_up)()
        if rc != 0:
            print(f"[!] docker compose up returned {rc}; proceeding against any already-running targets.")

    skipped_count = 0
    infra_failures = 0
    for target_id in target_ids:
        oracle = load_target_oracle(oracle_dir_path / f"{target_id}.oracle.json")
        if not oracle:
            print(f"[!] Oracle missing or unparseable for target {target_id!r}; skipping.")
            report.targets.append(
                TargetScore(
                    target_id=target_id,
                    score=0.0,
                    details={"skipped": "oracle missing or unparseable"},
                )
            )
            skipped_count += 1
            continue

        host = str(oracle.get("host", "127.0.0.1"))
        print(f"\n=== Graded eval target: {target_id} ({host}) ===")

        findings: list[dict[str, Any]] = []
        outcome_summary = ""
        runner_result: dict[str, Any] | None = None
        runner_crashed = False
        try:
            runner_result = await runner_fn(target_id, oracle, cfg)
        except Exception as exc:  # noqa: BLE001 -- one target failure never aborts the suite
            print(f"[!] Runner for {target_id} failed: {exc}")
            runner_result = {"findings": [], "outcome_summary": f"runner error: {exc}", "run_dir": None}
            runner_crashed = True
        if isinstance(runner_result, dict):
            raw_findings = runner_result.get("findings", [])
            if isinstance(raw_findings, list):
                findings = [f for f in raw_findings if isinstance(f, dict)]
            outcome_summary = str(runner_result.get("outcome_summary", "") or "")
        if outcome_summary:
            print(f"  outcome: {outcome_summary}")

        suite_result = score_against_oracle(findings, oracle)

        # Verify each flag independently — open a dedicated soft-fail session
        # for the verification executor (never trust the agent's claims).
        flag_results: list[FlagCheckResult] = []
        cm: Any = None
        try:
            cm, session, loop = await _open_verify_session(host, cfg)
            executor = _eval_shim("default_check_executor", default_check_executor)(
                session=session, workspace=workspace_root, loop=loop
            )
            for flag in oracle.get("flags", []) or []:
                if not isinstance(flag, dict):
                    continue
                flag_results.append(await asyncio.to_thread(verify_flag_check, flag, executor))
        finally:
            if cm is not None:
                await _close_verify_session(cm, entered=True)

        for fr in flag_results:
            status = "PASS" if fr.passed else "FAIL"
            print(f"  [{status}] {fr.flag_id}: {fr.detail}")

        target_score = _build_target_score(target_id, oracle, flag_results, suite_result, len(findings))
        report.targets.append(target_score)
        if runner_crashed:
            infra_failures += 1
        expected = oracle.get("expected_findings", {}) if isinstance(oracle, dict) else {}
        family = ""
        if isinstance(expected, dict):
            for key in ("vulnerabilities", "services", "misconfigurations"):
                values = expected.get(key)
                if isinstance(values, list) and values:
                    family = str(key)
                    break
        telemetry = extract_trial_telemetry(
            target_id,
            runner_result if isinstance(runner_result, dict) else {},
            verified_success=bool(target_score.success),
            vulnerability_family=family or str(oracle.get("target_id", target_id) or target_id),
        )
        report.trials.append(telemetry)

    if compose_down:
        _eval_shim("docker_suite_down", docker_suite_down)()

    # Classify the live outcome: skipped-only runs and infra-wide failures
    # can never present as PASS.
    executed = [t for t in report.targets if not t.details.get("skipped")]
    if not executed:
        live_outcome = LiveOutcome.SKIPPED
    elif infra_failures >= len(executed):
        live_outcome = LiveOutcome.INFRA_ERROR
    else:
        live_outcome = classify_live_outcome(success=any(t.success for t in executed))
    report.live_outcome = live_outcome
    # Lifecycle aggregation (metrics #9 reproduced-twice + #11 FIXED
    # timing): best-effort scan of this run's stored enhanced reports for
    # verify/retest histories. Absent artifacts → None → pending-collection
    # defaults (never fabricated).
    lifecycle = _collect_finding_lifecycle(output_dir / run_id)
    report.reliability = compute_reliability_metrics(
        report.trials, skipped=skipped_count, live_outcome=live_outcome, lifecycle=lifecycle
    )

    # Persist the graded report.
    out_dir = output_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    if write_markdown:
        (out_dir / "report.md").write_text(report.render_markdown(), encoding="utf-8")
    if write_html:
        (out_dir / "report.html").write_text(report.render_html(), encoding="utf-8")

    agg = report.to_dict()["aggregate"]
    print(
        f"\n=== Graded aggregate: live_outcome={live_outcome} score={agg['overall_score']} "
        f"flags={agg['flags_captured']}/{agg['flags_total']} "
        f"hosts={agg['hosts_owned']}/{agg['hosts_total']} succeeded={agg['targets_succeeded']}/{agg['targets_run']} ==="
    )
    print(f"  report: {out_dir}")
    return report


def _collect_finding_lifecycle(run_dir: Path | str) -> dict[str, Any] | None:
    """Best-effort lifecycle summary over stored enhanced-report findings.

    Scans ``run_dir`` for ``enhanced_report.json`` artifacts and aggregates
    their verify/retest histories via :func:`aggregate_finding_lifecycle`
    (metrics #9 reproduced-twice and #11 FIXED timing). Returns ``None``
    when no findings exist yet — the caller then leaves the lifecycle
    fields at their pending-collection defaults. Never raises: lifecycle
    collection must not break the eval path.
    """
    try:
        root = Path(run_dir)
        if not root.is_dir():
            return None
        findings: list[dict[str, Any]] = []
        for path in sorted(root.rglob("enhanced_report.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            items = data.get("technical_findings") if isinstance(data, dict) else None
            if isinstance(items, list):
                findings.extend(f for f in items if isinstance(f, dict))
        if not findings:
            return None
        return aggregate_finding_lifecycle(findings)
    except Exception:  # noqa: BLE001 -- lifecycle collection is advisory; the report above is the record
        return None


def write_skipped_eval_report(
    output_dir: Path | str,
    *,
    reason: str,
    config: dict[str, Any] | None = None,
    run_id: str = "",
) -> Path:
    """Persist an explicit SKIPPED graded-eval report (missing live infra).

    A skipped live run must never appear green: the report carries
    ``live_outcome=SKIPPED``, empty targets/trials, zeroed reliability
    metrics, and full provenance so reviewers can see *what* was skipped
    and *why*. Callers (CI ``eval.yml``) must upload this artifact and
    surface the reason in the step summary instead of ``exit 0`` silence.
    """
    out_root = Path(output_dir)
    resolved_run_id = str(run_id or _mint_run_id())
    provenance = build_run_provenance(config, trial_count=0)
    # trial_count=0 still records trials=1 via max(); correct it for a skip.
    provenance.trials = 0
    reliability = ReliabilityMetrics(targets_run=0, targets_skipped=0, live_outcome=LiveOutcome.SKIPPED)
    report = EvalReport(
        run_id=resolved_run_id,
        timestamp=_now_iso(),
        targets=[],
        live_outcome=LiveOutcome.SKIPPED,
        provenance=provenance,
        trials=[],
        reliability=reliability,
    )
    payload = report.to_dict()
    payload["skip_reason"] = str(reason or "live infrastructure unavailable")
    out_dir = out_root / resolved_run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    (out_dir / "report.md").write_text(
        f"# Graded eval — SKIPPED\n\n"
        f"- **Live outcome**: `SKIPPED`\n"
        f"- **Reason**: {reason}\n"
        f"- **Run id**: `{resolved_run_id}`\n"
        f"- **Timestamp**: `{report.timestamp}`\n\n"
        f"This run executed zero live targets, so it produced zero PASS/FAIL "
        f"signal. Do not interpret this artifact as a green evaluation.\n",
        encoding="utf-8",
    )
    print(f"[i] skipped eval report: {out_dir} (reason: {reason})")
    return out_dir / "report.json"
