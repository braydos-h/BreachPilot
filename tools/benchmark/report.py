"""Public benchmark report rendering (Markdown + HTML).

Renders FROM the persisted structured files (run.json / summary.json) — the
JSON stays the canonical data source; reports are views. The report includes
a methodology section (how success is verified, trial count, model config,
sandbox config, target versions, known limitations) so published numbers are
defensible. It never invents numbers: everything rendered comes from the run
payload.
"""

from __future__ import annotations

import html as _html
from typing import Any

__all__ = ["render_report_markdown", "render_report_html"]

_METHODOLOGY = """## Methodology

- **Verified success**: the independent oracle confirms the expected target
  state, the agent performed recorded tool actions, and its structured
  outcome reports success. Oracle-confirmed state that the agent did not
  recognize is recorded as a false negative and is not credited. Agent
  self-reports, OutcomeJudge text, exit codes, and tool output do not replace
  the independent oracle.
- **False positives**: trials where the agent claimed success but the oracle
  disagreed. They are reported prominently, never averaged away.
- **Trials**: each scenario runs for the recorded number of repeated trials;
  per-scenario success probability and a Wilson 95% confidence interval are
  computed over completed trials. Single-trial results are labeled as such.
- **Model**: the exact model alias/id and provider recorded at run start.
  Unknown metadata is recorded as unknown, never substituted.
- **Sandbox**: all attack execution runs inside the disposable sandbox worker
  (network-allowlisted container); the sandbox image digest is recorded.
- **Targets**: deliberately vulnerable lab images pinned by the scenario
  manifests. Benchmarks operate ONLY in authorized lab environments.
- **Known limitations**: results depend on model availability, target image
  drift, and host resources; infrastructure errors and skipped trials are
  excluded from success-rate denominators but always reported. If no trial
  has a usable outcome, rates and confidence intervals are unavailable rather
  than a measured 0%. The shipped Metasploitable 2 scenario is explicitly
  skipped because its current verifier cannot independently inspect the target
  (the available shell check runs locally); it contributes no success result.
  Trials are not cherry-picked.
"""


def _fmt_pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_probability(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_duration(seconds: Any) -> str:
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "n/a"
    if s <= 0:
        return "n/a"
    minutes, secs = divmod(int(s), 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s"


def _fmt_cost(value: Any) -> str:
    if value is None:
        return "n/a (not computed)"
    try:
        return f"${float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def _scope_violations_display(summary: dict[str, Any]) -> int | str:
    count = summary.get("scope_violation_count")
    if (summary.get("scope_violation_telemetry_available") is True and type(count) is int and count >= 0) or (
        type(count) is int and count > 0
    ):
        return count
    return "n/a (not measured)"


def render_report_markdown(run: dict[str, Any], summary: dict[str, Any] | None) -> str:
    """Markdown public report from run.json + summary.json payloads."""
    env = run.get("environment", {}) or {}
    config = run.get("config", {}) or {}
    s = summary or {}
    lines = [
        "# BreachPilot Benchmark Report",
        "",
        f"- **Version**: {env.get('breachpilot_version', 'unknown')}",
        f"- **Git**: `{env.get('git_sha', 'unknown')}`" + (" (dirty)" if env.get("git_dirty") else ""),
        f"- **Model**: {env.get('model_provider', 'unknown')} / {env.get('model_id', 'unknown')}"
        f" (alias {env.get('model_alias', 'unknown')}, version {env.get('model_version', 'unknown')})",
        f"- **Sandbox image**: {env.get('sandbox_image', 'unknown')} @ `{env.get('sandbox_image_digest', 'unknown')}`",
        f"- **Benchmark**: {run.get('suite', 'unknown')}",
        f"- **Trials per scenario**: {config.get('trials', 1)}",
        f"- **Run ID**: `{run.get('run_id', 'unknown')}` ({run.get('timestamp') or run.get('status', '')})",
        "",
        "## Results",
        "",
        f"- **Verified**: **{s.get('solved', 0)}/{s.get('trials_completed', 'n/a')} completed** "
        f"({s.get('trials_total', 0)} total trials)",
        f"- **Verified success rate**: {_fmt_pct(s.get('verified_success_rate'))}",
        f"- **False positive rate**: {_fmt_pct(s.get('false_positive_rate'))}",
        f"- **Median solve time**: {_fmt_duration(s.get('median_solve_time'))}",
        f"- **Median actions**: {s.get('median_tool_actions', 'n/a')}",
        f"- **Average cost**: {_fmt_cost(s.get('estimated_cost'))}",
        f"- **Sandbox blocked actions**: {s.get('sandbox_blocked_actions', 0)}",
        f"- **Scope violations reaching network layer**: {_scope_violations_display(s)}",
        f"- **Stuck loops**: {s.get('stuck_loop_count') if s.get('stuck_loop_count') is not None else 'n/a'} "
        f"({_fmt_pct(s.get('stuck_loop_rate'))})",
        f"- **Reproduced twice**: {_fmt_pct(s.get('reproduced_twice_rate'))}",
        f"- **Infrastructure errors / skipped**: {s.get('infra_error_count', 0)} / {s.get('skipped_count', 0)} "
        "(excluded from success-rate denominator)",
        "",
        "## Per-scenario results",
        "",
        "| Scenario | Verified | Completed / total | P(success) | 95% CI | FP | Median time |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for sc in s.get("scenarios", []) or []:
        ci_low = sc.get("ci95_low")
        ci_high = sc.get("ci95_high")
        ci = (
            f"[{ci_low:.2f}, {ci_high:.2f}]"
            if isinstance(ci_low, (int, float)) and isinstance(ci_high, (int, float))
            else "n/a"
        )
        lines.append(
            f"| {sc.get('scenario_id', '?')} | {sc.get('verified', 0)}/{sc.get('trials_completed', 'n/a')} "
            f"| {sc.get('trials_completed', 'n/a')} / {sc.get('trials', 0)} | "
            f"{_fmt_probability(sc.get('success_probability'))} | {ci} "
            f"| {sc.get('false_positives', 0)} | {_fmt_duration(sc.get('median_duration'))} |"
        )
    failures = s.get("failure_categories", {}) or {}
    if failures:
        lines += ["", "## Failure categories", ""]
        for cat, count in sorted(failures.items()):
            lines.append(f"- {cat}: {count}")
    lines += ["", _METHODOLOGY]
    return "\n".join(lines) + "\n"


def render_report_html(run: dict[str, Any], summary: dict[str, Any] | None) -> str:
    """HTML public report (self-contained, no external assets)."""
    md_rows: list[str] = []
    s = summary or {}
    for sc in s.get("scenarios", []) or []:
        md_rows.append(
            f"<tr><td>{_html.escape(str(sc.get('scenario_id', '?')))}</td>"
            f"<td>{sc.get('verified', 0)}/{sc.get('trials_completed', 'n/a')} completed "
            f"({sc.get('trials', 0)} total)</td>"
            f"<td>{_fmt_probability(sc.get('success_probability'))}</td>"
            f"<td>{sc.get('false_positives', 0)}</td>"
            f"<td>{_fmt_duration(sc.get('median_duration'))}</td></tr>"
        )
    env = run.get("environment", {}) or {}
    e = _html.escape
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>BreachPilot Benchmark Report — {e(str(run.get("run_id", "")))}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; }}
    table {{ border-collapse: collapse; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ddd; padding: .4rem .7rem; text-align: left; }}
    th {{ background: #f5f5f5; }}
    .stat {{ font-size: 1.4rem; font-weight: 600; }}
    code {{ background: #f4f4f4; padding: 0 .3rem; }}
  </style>
</head>
<body>
  <h1>BreachPilot Benchmark Report</h1>
  <p>
    <strong>Version:</strong> {e(str(env.get("breachpilot_version", "unknown")))} ·
    <strong>Git:</strong> <code>{e(str(env.get("git_sha", "unknown")))}</code> ·
    <strong>Benchmark:</strong> {e(str(run.get("suite", "unknown")))} ·
    <strong>Trials:</strong> {e(str((run.get("config") or {}).get("trials", 1)))}
  </p>
  <p>
    <strong>Model:</strong> {e(str(env.get("model_provider", "unknown")))} / {e(str(env.get("model_id", "unknown")))}<br>
    <strong>Sandbox image digest:</strong> <code>{e(str(env.get("sandbox_image_digest", "unknown")))}</code>
  </p>
  <div class="stat">{s.get("solved", 0)}/{s.get("trials_completed", "n/a")} completed verified
  ({s.get("trials_total", 0)} total trials; {_fmt_pct(s.get("verified_success_rate"))})</div>
  <p>
    False positives: {_fmt_pct(s.get("false_positive_rate"))} ·
    Median solve time: {_fmt_duration(s.get("median_solve_time"))} ·
    Average cost: {_fmt_cost(s.get("estimated_cost"))} ·
    Infra errors / skipped: {s.get("infra_error_count", 0)} / {s.get("skipped_count", 0)}
  </p>
  <p>
    Scope violations reaching network layer: {e(str(_scope_violations_display(s)))} ·
    Stuck loops: {e(str(s.get("stuck_loop_count") if s.get("stuck_loop_count") is not None else "n/a"))} ({_fmt_pct(s.get("stuck_loop_rate"))}) ·
    Reproduced twice: {_fmt_pct(s.get("reproduced_twice_rate"))} ·
    Sandbox blocked actions: {e(str(s.get("sandbox_blocked_actions", 0)))}
  </p>
  <h2>Per-scenario results</h2>
  <table>
    <thead><tr><th>Scenario</th><th>Verified / trials</th><th>P(success)</th><th>FP</th><th>Median time</th></tr></thead>
    <tbody>
      {"".join(md_rows) or '<tr><td colspan="5">no completed trials</td></tr>'}
    </tbody>
  </table>
  <h2>Methodology</h2>
  <pre style="white-space: pre-wrap; font-family: inherit;">{_METHODOLOGY}</pre>
</body>
</html>
"""
