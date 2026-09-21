"""HTML report renderers (split out of ``tools.enhanced_reporting``).

Module-level functions; :class:`tools.reporting.generator.EnhancedReportGenerator`
keeps same-named thin methods that delegate here so existing method call
sites and monkeypatch seams keep working. Re-exported through
:mod:`tools.enhanced_reporting`.
"""

from __future__ import annotations

import html
from typing import Any

from tools.reporting.models import apply_hitl_filter, approved_findings

__all__ = [
    "_HTML_CSS",
    "_esc",
    "_format_retest_html",
    "_generate_chains_html",
    "_generate_failures_html",
    "_generate_findings_html",
    "_generate_html",
    "_generate_timeline_html",
    "_sev_class",
]


def _generate_html(report_data: dict[str, Any], *, pending_count: int | None = None) -> str:
    """Generate a self-contained HTML report (inline CSS, no externals).

    All user-controlled strings (target IPs, exploit names, summaries,
    remediation text) are HTML-escaped. Empty sections are omitted.
    """
    # HITL gate (also covers the hitl/verify/retest sibling-refresh path,
    # which calls this renderer directly with stored JSON) — see
    # _generate_markdown for the pending-count contract.
    fresh_pending = apply_hitl_filter(report_data)
    pending = fresh_pending if pending_count is None else pending_count
    meta = report_data.get("report_metadata", {}) if isinstance(report_data, dict) else {}
    parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        f"<title>{_esc(meta.get('mission_id', 'Red Team Report'))} - Red Team Assessment</title>",
        "<style>",
        _HTML_CSS,
        "</style>",
        "</head>",
        "<body>",
        "<main class='report'>",
        "<header class='report-header'>",
        "<h1>Red Team Assessment Report</h1>",
        "<div class='meta'>",
        f"<span><strong>Mission ID:</strong> {_esc(meta.get('mission_id', ''))}</span>",
        f"<span><strong>Generated:</strong> {_esc(meta.get('generated_at', ''))}</span>",
        f"<span><strong>Targets Assessed:</strong> {_esc(meta.get('total_targets', ''))}</span>",
        "</div>",
        "</header>",
    ]

    # Executive summary is markdown-ish prose; render as preformatted escaped text.
    exec_summary = report_data.get("executive_summary", "")
    if exec_summary:
        parts.append("<section class='section'>")
        parts.append("<h2>Executive Summary</h2>")
        parts.append(f"<pre class='prose'>{_esc(exec_summary)}</pre>")
        parts.append("</section>")

    timeline = report_data.get("attack_timeline", [])
    if timeline:
        parts.append(_generate_timeline_html(timeline))

    chains = report_data.get("exploitation_chains", [])
    if chains:
        parts.append(_generate_chains_html(chains))

    findings = report_data.get("technical_findings", []) if isinstance(report_data, dict) else []
    if findings or pending:
        parts.append(_generate_findings_html(findings, pending_count=pending))

    failures = report_data.get("failure_analysis", [])
    if failures:
        parts.append(_generate_failures_html(failures))

    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def _generate_timeline_html(timeline: list[dict]) -> str:
    rows = []
    for entry in timeline:
        ts = entry.get("timestamp", "")
        ts_short = ts.split("T")[1].split(".")[0] if "T" in ts else ts
        result_cls = "ok" if entry.get("result") == "success" else "fail"
        rows.append(
            "<tr>"
            f"<td>{_esc(ts_short)}</td>"
            f"<td>{_esc(entry.get('target', ''))}</td>"
            f"<td>{_esc(entry.get('event_type', ''))}</td>"
            f"<td>{_esc(entry.get('module', ''))}</td>"
            f"<td class='{result_cls}'>{_esc(entry.get('result', ''))}</td>"
            "</tr>"
        )
    return (
        "<section class='section'>"
        "<h2>Attack Timeline</h2>"
        "<table class='data-table'><thead><tr>"
        "<th>Time</th><th>Target</th><th>Event</th><th>Module</th><th>Result</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        "</section>"
    )


def _generate_chains_html(chains: list[dict]) -> str:
    sections: list[str] = ["<section class='section'>", "<h2>Exploitation Chains</h2>"]
    for chain in chains:
        sections.append("<div class='chain'>")
        sections.append(
            f"<h3>{_esc(chain.get('target', ''))} "
            f"<span class='chain-id'>({_esc(chain.get('chain_id', ''))})</span></h3>"
        )
        sections.append(
            f"<p><strong>Successful:</strong> {_esc(chain.get('successful', ''))} "
            f"&middot; <strong>Final Privilege:</strong> {_esc(chain.get('final_privilege', ''))}</p>"
        )
        sections.append("<ol class='chain-steps'>")
        for entry in chain.get("entries", []):
            ts = entry.get("timestamp", "")
            ts_short = ts.split("T")[1].split(".")[0] if "T" in ts else ts
            sections.append(
                f"<li><strong>{_esc(entry.get('module', ''))}</strong> "
                f"<span class='muted'>({_esc(entry.get('result', ''))}"
                f"{(' &middot; ' + _esc(ts_short)) if ts_short else ''})</span></li>"
            )
        sections.append("</ol>")
        sections.append("</div>")
    sections.append("</section>")
    return "".join(sections)


def _generate_findings_html(findings: list[dict], *, pending_count: int = 0) -> str:
    sections: list[str] = ["<section class='section'>", "<h2>Technical Findings</h2>"]
    # Defensive: direct callers may pass unfiltered lists.
    findings = approved_findings(findings) if isinstance(findings, list) else []
    if pending_count > 0:
        sections.append(
            f"<p class='pending-banner'>{_esc(pending_count)} finding(s) awaiting human review "
            "— hidden until approved.</p>"
        )
    for finding in findings:
        cvss = finding.get("cvss", {}) or {}
        sections.append("<article class='finding'>")
        sections.append(f"<h3>{_esc(finding.get('title', ''))}</h3>")
        sections.append("<div class='finding-meta'>")
        sev = _esc(str(finding.get("severity", "")))
        confidence_label = f"{float(finding.get('confidence', 0) or 0):.0%}"
        sections.append(
            f"<span class='badge sev-{_sev_class(finding.get('severity', ''))}'>"
            f"{sev}</span>"
            f"<span><strong>CVSS:</strong> {_esc(cvss.get('base_score', 0))}</span>"
            f"<span><strong>Class:</strong> {_esc(finding.get('vuln_class', ''))}</span>"
            f"<span><strong>Confidence:</strong> {_esc(confidence_label)}</span>"
            f"<span><strong>Asset:</strong> {_esc(finding.get('affected_asset', ''))}</span>"
        )
        sections.append("</div>")
        sections.append(f"<p><strong>Summary:</strong> {_esc(finding.get('summary', ''))}</p>")
        if finding.get("hitl_status"):
            sections.append(f"<p><strong>HITL:</strong> {_esc(finding.get('hitl_status', ''))}</p>")
        retest_html = _format_retest_html(finding)
        if retest_html:
            sections.append(f"<p><strong>Retest:</strong> {retest_html}</p>")
        if finding.get("exploitation_result"):
            sections.append(f"<p><strong>Exploitation:</strong> {_esc(finding.get('exploitation_result', ''))}</p>")
        if finding.get("privilege_level_gained"):
            sections.append(
                f"<p><strong>Privilege Gained:</strong> {_esc(finding.get('privilege_level_gained', ''))}</p>"
            )
        repro = finding.get("reproduction_steps", []) or []
        if repro:
            sections.append("<h4>Reproduction Steps</h4><ol class='repro'>")
            for step in repro:
                sections.append(f"<li>{_esc(step)}</li>")
            sections.append("</ol>")
        refs = finding.get("evidence_refs", []) or []
        if refs:
            sections.append("<h4>Evidence References</h4><ul class='evidence-refs'>")
            for ref in refs:
                sections.append(f"<li><code>{_esc(ref)}</code></li>")
            sections.append("</ul>")
        if finding.get("remediation"):
            sections.append(f"<p><strong>Remediation:</strong> {_esc(finding.get('remediation', ''))}</p>")
        sections.append("</article>")
    sections.append("</section>")
    return "".join(sections)


def _generate_failures_html(failures: list[dict]) -> str:
    sections: list[str] = ["<section class='section'>", "<h2>Failure Analysis</h2>"]
    for failure in failures:
        sections.append("<article class='failure'>")
        sections.append(f"<h3>{_esc(failure.get('operation', ''))}</h3>")
        sections.append(
            f"<p><strong>Total Failures:</strong> {_esc(failure.get('failure_count', ''))} "
            f"&middot; <strong>Primary Error:</strong> {_esc(failure.get('primary_error', ''))}</p>"
        )
        breakdown = failure.get("error_breakdown", {}) or {}
        if breakdown:
            sections.append("<ul class='error-breakdown'>")
            for etype, count in breakdown.items():
                sections.append(f"<li>{_esc(etype)}: {_esc(count)}</li>")
            sections.append("</ul>")
        if failure.get("mitigation_suggestion"):
            sections.append(f"<p><strong>Mitigation:</strong> {_esc(failure.get('mitigation_suggestion', ''))}</p>")
        sections.append("</article>")
    sections.append("</section>")
    return "".join(sections)


def _format_retest_html(finding: dict[str, Any]) -> str:
    """Escaped retest status line for the HTML report (never raises)."""
    status = str(finding.get("retest_status") or "")
    if not status:
        return _esc("not retested")
    parts = [_esc(status)]
    history = finding.get("retest_history") or []
    if isinstance(history, list) and history and isinstance(history[-1], dict):
        last = history[-1]
        ts = str(last.get("timestamp") or "")
        evidence = str(last.get("evidence") or "")
        if ts:
            parts.append(f" {_esc('@ ' + ts)}")
        if evidence:
            parts.append(f" (evidence: {_esc(evidence)})")
    return "".join(parts)


def _esc(value: Any) -> str:
    """HTML-escape a value rendered into the HTML report."""
    return html.escape(str(value), quote=True)


def _sev_class(severity: str) -> str:
    """Map a severity label to a CSS class slug."""
    s = str(severity or "").lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s == "medium":
        return "medium"
    if s == "low":
        return "low"
    return "none"


_HTML_CSS = """
body { margin: 0; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #1f2328; background: #f6f8fa; }
.report { max-width: 1100px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.report-header h1 { margin: 0 0 0.5rem 0; font-size: 1.8rem; }
.report-header .meta { display: flex; flex-wrap: wrap; gap: 1.5rem; color: #57606a; font-size: 0.9rem; }
.section { margin: 2rem 0; padding-top: 1rem; border-top: 1px solid #d0d7de; }
.section h2 { font-size: 1.4rem; margin-top: 0; }
h3 { font-size: 1.15rem; margin: 1rem 0 0.4rem; }
h4 { font-size: 0.95rem; margin: 0.8rem 0 0.3rem; color: #57606a; text-transform: uppercase; letter-spacing: 0.04em; }
.prose { white-space: pre-wrap; font-family: inherit; font-size: 0.95rem; line-height: 1.5; margin: 0; }
.data-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
.data-table th, .data-table td { padding: 0.45rem 0.6rem; border: 1px solid #d0d7de; text-align: left; }
.data-table th { background: #f6f8fa; }
.data-table td.ok { color: #1a7f37; font-weight: 600; }
.data-table td.fail { color: #cf222e; font-weight: 600; }
.chain { margin: 1rem 0; padding: 1rem; background: #f6f8fa; border-radius: 6px; }
.chain-id { color: #6e7781; font-weight: 400; font-size: 0.85rem; }
.chain-steps { margin: 0.5rem 0; padding-left: 1.4rem; }
.muted { color: #6e7781; }
.finding, .failure { margin: 1.2rem 0; padding: 1rem 1.2rem; border: 1px solid #d0d7de; border-radius: 6px; }
.finding-meta { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.85rem; color: #57606a; margin-bottom: 0.5rem; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; font-weight: 700; color: #fff; }
.badge.sev-critical { background: #82071e; }
.badge.sev-high { background: #cf222e; }
.badge.sev-medium { background: #bf8700; }
.badge.sev-low { background: #1a7f37; }
.badge.sev-none { background: #6e7781; }
.repro, .evidence-refs, .error-breakdown { margin: 0.3rem 0; padding-left: 1.4rem; }
.repro li, .evidence-refs li { margin: 0.2rem 0; font-size: 0.9rem; }
code { background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85rem; }
"""
