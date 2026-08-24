"""Report Generator — produces reproducible, evidence-linked security reports.

Each report follows a strict template:
# Summary
# Affected Asset
# Vulnerability Class
# Severity / Impact
# Preconditions
# Steps to Reproduce
# Expected Behavior
# Actual Behavior
# Evidence
# Security Impact
# Suggested Remediation
# Notes

Reports must be:
- Concise
- Reproducible
- Free of exaggeration
- Include evidence references
- Include exact affected asset
- Include clear impact
- Include safe reproduction steps
- Avoid dumping huge raw logs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from db import DatabaseManager, _now_iso

# ── Severity labels ────────────────────────────────────────────────────────


def _severity_label(impact_score: int) -> str:
    if impact_score >= 80:
        return "Critical"
    if impact_score >= 50:
        return "High"
    if impact_score >= 30:
        return "Medium"
    if impact_score >= 10:
        return "Low"
    return "Informational"


# ── Report schema ──────────────────────────────────────────────────────────

REPORT_TEMPLATE = """# {title}

**Status**: {status}
**Confidence**: {confidence:.0%}
**Impact Score**: {impact_score}/100

---

## Summary

{summary}

---

## Affected Asset

{affected_asset}{affected_endpoint}

## Vulnerability Class

{vuln_class}

## Severity / Impact

**Severity**: {severity}
**Impact**: {impact}

---

## Exploit Possibility

**Likelihood**: {exploit_likelihood}
**Difficulty**: {exploit_difficulty}
**Success Rating**: {exploit_success_rating}/100

{exploit_rationale}

---

## Suggested Next Goals

{suggested_goals}

---

## Preconditions

{preconditions}

## Steps to Reproduce

{reproduction_steps}

## Expected Behavior

{expected_behavior}

## Actual Behavior

{actual_behavior}

---

## Evidence

{evidence_section}

## Security Impact

{security_impact}

## Suggested Remediation

{remediation}

---

## Notes

{notes}

*Report generated: {generated_at}*
"""


class ReportGenerator:
    """Generates structured markdown reports from verified findings."""

    def __init__(
        self,
        db: DatabaseManager,
        mission_id: str,
        workspace: Path,
    ) -> None:
        self._db = db
        self._mission_id = mission_id
        self._workspace = workspace
        self._reports_dir = workspace / "reports"
        self._reports_dir.mkdir(parents=True, exist_ok=True)

    # ── Main API ────────────────────────────────────────────────────────

    def generate_report(self, finding_id: str) -> str:
        """Generate a markdown report for a finding. Must be report_ready status.

        Returns the markdown content as a string.
        Also writes it to workspace/reports/{finding_id}.md
        """
        finding = self._get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found.")

        if finding.get("status") != "report_ready":
            raise ValueError(
                f"Finding {finding_id} is not 'report_ready'. "
                f"Current status: {finding.get('status')}. "
                f"Validate and mark as report_ready first."
            )

        severity = _severity_label(finding.get("impact_score", 0))

        # Format sections
        affected_line = f"- **Asset**: {finding.get('affected_asset', 'N/A')}"
        endpoint = finding.get("affected_endpoint", "")
        if endpoint:
            affected_endpoint = f"\n- **Endpoint**: {endpoint}"
        else:
            affected_endpoint = ""

        repro_steps = self._format_list(finding.get("reproduction_steps", []))
        if not repro_steps.strip():
            repro_steps = "_No reproduction steps documented._"

        evidence = self._format_evidence(finding.get("evidence_refs", []))
        if not evidence.strip():
            evidence = "_No evidence attached._"

        # Build report
        # ── Exploit possibility fields ──
        exploit_likelihood = finding.get("exploit_likelihood", "")
        exploit_difficulty = finding.get("exploit_difficulty", "")
        exploit_success_rating = finding.get("exploit_success_rating", 0)
        exploit_rationale = finding.get("exploit_rationale", "")
        if not exploit_likelihood:
            exploit_likelihood = "Not assessed"
        if not exploit_difficulty:
            exploit_difficulty = "Not assessed"
        if exploit_rationale:
            exploit_rationale = f"**Rationale**: {exploit_rationale}"
        else:
            exploit_rationale = "_Exploit possibility not yet assessed._"

        # ── Suggested goals ──
        suggested_goals_raw = finding.get("suggested_goals_json", "")
        if suggested_goals_raw:
            try:
                goals_list = (
                    json.loads(suggested_goals_raw) if isinstance(suggested_goals_raw, str) else suggested_goals_raw
                )
                goal_lines = []
                for g in goals_list[:5]:
                    name = g.get("name", "?")
                    rating = g.get("success_rating", 0)
                    likelihood = g.get("exploit_likelihood", "")
                    goal_lines.append(f"- **{name}** [{rating}/100] — {likelihood}")
                suggested_goals = "\n".join(goal_lines) if goal_lines else "_No goal suggestions available._"
            except (json.JSONDecodeError, TypeError):
                suggested_goals = "_Goal suggestions unavailable._"
        else:
            suggested_goals = "_No goal suggestions. Run recon-first mode to generate suggestions._"

        def _escape(s: str) -> str:
            """Escape curly braces so str.format() doesn't choke on user content."""
            return s.replace("{", "{{").replace("}", "}}")

        report = REPORT_TEMPLATE.format(
            title=_escape(finding.get("title", "Untitled Finding")),
            status=_escape(finding.get("status", "unknown")),
            confidence=finding.get("confidence", 0.0),
            impact_score=finding.get("impact_score", 0),
            summary=_escape(finding.get("summary", "No summary provided.")),
            affected_asset=_escape(affected_line),
            affected_endpoint=_escape(affected_endpoint),
            vuln_class=_escape(finding.get("vuln_class", "Unclassified")),
            severity=_escape(severity),
            impact=_escape(finding.get("impact", "Impact not assessed.")),
            exploit_likelihood=_escape(exploit_likelihood),
            exploit_difficulty=_escape(exploit_difficulty),
            exploit_success_rating=exploit_success_rating,
            exploit_rationale=_escape(exploit_rationale),
            suggested_goals=_escape(suggested_goals),
            preconditions="_No specific preconditions documented._",
            reproduction_steps=_escape(repro_steps),
            expected_behavior="_Normal, authorized behavior expected._",
            actual_behavior=_escape(finding.get("summary", "Behavior as described in summary.")),
            evidence_section=_escape(evidence),
            security_impact=_escape(finding.get("impact", "")),
            remediation="_No remediation guidance provided._",
            notes=f"Finding ID: {finding_id}",
            generated_at=_now_iso(),
        )

        # Write to file
        report_path = self._reports_dir / f"{finding_id}.md"
        report_path.write_text(report, encoding="utf-8")

        return report

    def export_report(self, finding_id: str) -> dict[str, Any]:
        """Export the report as structured JSON."""
        finding = self._get_finding(finding_id)
        if not finding:
            return {"error": f"Finding {finding_id} not found."}

        return {
            "finding_id": finding_id,
            "title": finding.get("title", ""),
            "severity": _severity_label(finding.get("impact_score", 0)),
            "vuln_class": finding.get("vuln_class", ""),
            "affected_asset": finding.get("affected_asset", ""),
            "affected_endpoint": finding.get("affected_endpoint", ""),
            "summary": finding.get("summary", ""),
            "impact": finding.get("impact", ""),
            "impact_score": finding.get("impact_score", 0),
            "confidence": finding.get("confidence", 0.0),
            "status": finding.get("status", ""),
            "reproduction_steps": finding.get("reproduction_steps", []),
            "evidence_refs": finding.get("evidence_refs", []),
            "generated_at": _now_iso(),
        }

    def generate_summary_report(self) -> str:
        """Generate a summary report of ALL report_ready findings."""
        findings = self._list_by_status("report_ready")
        validated = self._list_by_status("validated")
        candidates = self._list_by_status("candidate")
        rejected = self._list_by_status("rejected")

        lines = [
            "# Bug Bounty Research Summary",
            "",
            f"**Mission**: {self._mission_id}",
            f"**Generated**: {_now_iso()}",
            "",
            "---",
            "",
            "## Overview",
            "",
            f"- **Report-Ready Findings**: {len(findings)}",
            f"- **Validated (pending report)**: {len(validated)}",
            f"- **Candidate Findings**: {len(candidates)}",
            f"- **Rejected Findings**: {len(rejected)}",
            "",
            "---",
            "",
        ]

        if findings:
            lines.append("## Report-Ready Findings")
            lines.append("")
            for f in findings:
                lines.append(f"### {f.get('title', 'Untitled')}")
                lines.append(f"- **Severity**: {_severity_label(f.get('impact_score', 0))}")
                lines.append(f"- **Asset**: {f.get('affected_asset', 'N/A')}")
                lines.append(f"- **Class**: {f.get('vuln_class', 'Unclassified')}")
                lines.append(f"- **Summary**: {f.get('summary', '')[:200]}")
                lines.append(f"- **ID**: {f.get('finding_id', '')}")
                lines.append("")

        if validated:
            lines.append("## Validated Findings (Pending Report)")
            lines.append("")
            for f in validated[:5]:
                lines.append(f"- **{f.get('title', '')}** [{f.get('vuln_class', '')}] — {f.get('affected_asset', '')}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*Generated by the Authorized Bug Bounty Research Agent*")
        lines.append("")

        report = "\n".join(lines)
        report_path = self._reports_dir / "summary_report.md"
        report_path.write_text(report, encoding="utf-8")
        return report

    # ── Helpers ─────────────────────────────────────────────────────────

    def _get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM findings WHERE id=? AND mission_id=?",
                (finding_id, self._mission_id),
            )
            row = cur.fetchone()
            if row:
                from finding_verifier import _row_to_finding

                return _row_to_finding(dict(row))
        return None

    def _list_by_status(self, status: str) -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM findings WHERE mission_id=? AND status=? ORDER BY impact_score DESC",
                (self._mission_id, status),
            )
            from finding_verifier import _row_to_finding

            return [_row_to_finding(dict(row)) for row in cur.fetchall()]

    @staticmethod
    def _format_list(items: list[str] | list[dict[str, Any]]) -> str:
        if not items:
            return ""
        lines: list[str] = []
        for i, item in enumerate(items, 1):
            if isinstance(item, dict):
                text = item.get("step", item.get("description", str(item)))
            else:
                text = str(item)
            lines.append(f"{i}. {text}")
        return "\n".join(lines)

    @staticmethod
    def _format_evidence(refs: list[str]) -> str:
        if not refs:
            return "_No evidence attached._"
        lines: list[str] = []
        for ref in refs:
            lines.append(f"- Evidence: `{ref}`")
        return "\n".join(lines)
