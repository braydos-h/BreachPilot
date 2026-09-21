"""Markdown report renderers (split out of ``tools.enhanced_reporting``).

Module-level functions; :class:`tools.reporting.generator.EnhancedReportGenerator`
keeps same-named thin methods that delegate here so existing method call
sites and monkeypatch seams keep working. Re-exported through
:mod:`tools.enhanced_reporting`.
"""

from __future__ import annotations

from typing import Any

from tools.reporting.models import apply_hitl_filter, approved_findings

__all__ = [
    "_format_retest_md",
    "_generate_chains_md",
    "_generate_failures_md",
    "_generate_findings_md",
    "_generate_markdown",
    "_generate_timeline_md",
]


def _generate_markdown(report_data: dict[str, Any], *, pending_count: int | None = None) -> str:
    """Generate full markdown report from structured data."""
    # HITL gate (also covers the hitl/verify/retest sibling-refresh path,
    # which calls this renderer directly with stored JSON). The banner
    # count is computed fresh here unless the caller passes the count from
    # its own filter pass (generate_full_report filters once for the JSON
    # write; re-filtering the same dict would yield 0).
    fresh_pending = apply_hitl_filter(report_data)
    pending = fresh_pending if pending_count is None else pending_count
    lines = [
        "# Red Team Assessment Report",
        "",
        f"**Mission ID**: {report_data['report_metadata']['mission_id']}",
        f"**Generated**: {report_data['report_metadata']['generated_at']}",
        f"**Targets Assessed**: {report_data['report_metadata']['total_targets']}",
        "",
        "---",
        "",
    ]

    # Executive Summary
    lines.append(report_data["executive_summary"])
    lines.append("")
    lines.append("---")
    lines.append("")

    # Attack Timeline
    lines.append(_generate_timeline_md(report_data["attack_timeline"]))
    lines.append("")
    lines.append("---")
    lines.append("")

    # Exploitation Chains
    lines.append(_generate_chains_md(report_data["exploitation_chains"]))
    lines.append("")
    lines.append("---")
    lines.append("")

    # Technical Findings
    lines.append(_generate_findings_md(report_data["technical_findings"], pending_count=pending))
    lines.append("")
    lines.append("---")
    lines.append("")

    # Failure Analysis
    lines.append(_generate_failures_md(report_data["failure_analysis"]))
    lines.append("")

    return "\n".join(lines)


def _generate_timeline_md(timeline: list[dict]) -> str:
    lines = ["# Attack Timeline", ""]
    if not timeline:
        lines.append("No timeline events recorded.")
        return "\n".join(lines)

    lines.append("| Time | Target | Event | Module | Result |")
    lines.append("|------|--------|-------|--------|--------|")
    for entry in timeline:
        ts = entry.get("timestamp", "").split("T")[1].split(".")[0] if "T" in entry.get("timestamp", "") else ""
        result = "✅" if entry.get("result") == "success" else "❌"
        lines.append(
            f"| {ts} | {entry.get('target', '')} | {entry.get('event_type', '')} | {entry.get('module', '')} | {result} |"
        )
    return "\n".join(lines)


def _generate_chains_md(chains: list[dict]) -> str:
    lines = ["# Exploitation Chains", ""]
    if not chains:
        lines.append("No successful exploitation chains.")
        return "\n".join(lines)

    for chain in chains:
        lines.append(f"## {chain['target']}")
        lines.append(f"- **Chain ID**: {chain['chain_id']}")
        lines.append(f"- **Successful**: {'Yes' if chain['successful'] else 'No'}")
        lines.append(f"- **Final Privilege**: {chain['final_privilege']}")
        lines.append("")
        lines.append("### Chain Steps")
        for i, entry in enumerate(chain["entries"], 1):
            lines.append(f"{i}. {entry['module']} ({entry['result']})")
        lines.append("")
    return "\n".join(lines)


def _generate_findings_md(findings: list[dict], *, pending_count: int = 0) -> str:
    lines = ["# Technical Findings", ""]
    # Defensive: direct callers may pass unfiltered lists.
    findings = approved_findings(findings) if isinstance(findings, list) else []
    if pending_count > 0:
        lines.append(f"> {pending_count} finding(s) awaiting human review — hidden until approved.")
        lines.append("")
    if not findings:
        lines.append("No findings to report.")
        return "\n".join(lines)

    for finding in findings:
        cvss = finding.get("cvss", {})
        lines.append(f"## {finding['title']}")
        lines.append(f"- **Severity**: {finding['severity']} (CVSS: {cvss.get('base_score', 0)})")
        lines.append(f"- **Class**: {finding['vuln_class']}")
        lines.append(f"- **Confidence**: {finding['confidence']:.0%}")
        lines.append(f"- **Asset**: {finding['affected_asset']}")
        lines.append(f"- **Retest**: {_format_retest_md(finding)}")
        if finding.get("hitl_status"):
            lines.append(f"- **HITL**: {finding.get('hitl_status')}")
        lines.append("")
        lines.append(f"**Summary**: {finding['summary']}")
        lines.append("")
        if finding.get("exploitation_result"):
            lines.append(f"**Exploitation**: {finding['exploitation_result']}")
        if finding.get("privilege_level_gained"):
            lines.append(f"**Privilege Gained**: {finding['privilege_level_gained']}")
        lines.append("")
        lines.append(f"**Remediation**: {finding.get('remediation', 'No remediation provided.')}")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def _generate_failures_md(failures: list[dict]) -> str:
    lines = ["# Failure Analysis", ""]
    if not failures:
        lines.append("No failures recorded.")
        return "\n".join(lines)

    for failure in failures:
        lines.append(f"## {failure['operation']}")
        lines.append(f"- **Total Failures**: {failure['failure_count']}")
        lines.append(f"- **Primary Error**: {failure['primary_error']}")
        lines.append("")
        lines.append("### Error Breakdown")
        for error_type, count in failure.get("error_breakdown", {}).items():
            lines.append(f"- {error_type}: {count}")
        lines.append("")
        lines.append(f"**Mitigation**: {failure['mitigation_suggestion']}")
        lines.append("")
    return "\n".join(lines)


def _format_retest_md(finding: dict[str, Any]) -> str:
    """One-line retest status for the Markdown report (never raises)."""
    status = str(finding.get("retest_status") or "")
    if not status:
        return "not retested"
    history = finding.get("retest_history") or []
    if isinstance(history, list) and history and isinstance(history[-1], dict):
        last = history[-1]
        evidence = str(last.get("evidence") or "")
        ts = str(last.get("timestamp") or "")
        suffix = f" @ {ts}" if ts else ""
        if evidence:
            return f"{status}{suffix} (evidence: {evidence})"
        return f"{status}{suffix}"
    return status
