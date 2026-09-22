"""Eval metrics: single-run scoring and report rendering (split from tools.eval_harness)."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
