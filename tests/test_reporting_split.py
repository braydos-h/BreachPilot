"""Reporting split tests (P2-04): import surface + md/html/JSON byte-parity.

``tools/enhanced_reporting.py`` is a re-export shim over
``tools/reporting/{cvss,models,markdown,html,generator}.py`` — every name
previously importable from the shim must resolve to the identical object in
the new package, and rendering a fixed mixed-lifecycle report must be
byte-identical to the checked-in fixtures (generated pre-split).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "reporting_split"


def _finding(fid: str, title: str, **kw: object) -> dict:
    base = {
        "finding_id": fid,
        "title": title,
        "affected_asset": "10.0.0.5",
        "vuln_class": "Known CVE",
        "severity": "Critical",
        "cvss": {
            "base_score": 9.8,
            "temporal_score": None,
            "environmental_score": None,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "Critical",
        },
        "confidence": 0.95,
        "summary": f"Summary of {title} <b>escape</b>",
        "reproduction_steps": ["nmap -sV 10.0.0.5"],
        "evidence_refs": ["E-1"],
        "exploitation_result": "Shell access achieved",
        "persistence_achieved": True,
        "privilege_level_gained": "root",
        "attack_chain": None,
        "remediation": "Patch now.",
        "references": [],
        "verification_probe": {"type": "shell_command", "exec": "id"},
        "retest_status": "",
        "retest_history": [],
        "verify_status": "HOLDING",
        "verify_history": [],
        "hitl_status": "PROPOSED",
        "hitl_history": [],
    }
    base.update(kw)  # type: ignore[typeddict-item]
    return base


def _mixed_report() -> dict:
    human = [{"timestamp": "2026-01-01T00:00:00+00:00", "decision": "APPROVED", "note": "", "actor": "human"}]
    verified_hist = [{"timestamp": "2026-01-02T00:00:00+00:00", "verdict": "VERIFIED", "evidence": "uid=0(root)"}]
    approved = _finding(
        "F-approved",
        "Approved <script>alert(1)</script>",
        hitl_status="APPROVED",
        hitl_history=human,
        verify_status="VERIFIED",
        verify_history=verified_hist,
    )
    still_open = _finding(
        "F-open",
        "Still Open Finding",
        hitl_status="APPROVED",
        hitl_history=human,
        verify_status="VERIFIED",
        verify_history=[{"timestamp": "2026-01-02T00:00:00+00:00", "verdict": "VERIFIED", "evidence": "x"}],
        retest_status="STILL_OPEN",
        retest_history=[{"timestamp": "2026-01-03T00:00:00+00:00", "verdict": "STILL_OPEN", "evidence": "open"}],
    )
    return {
        "report_metadata": {
            "generated_at": "2026-01-04T00:00:00+00:00",
            "mission_id": "FIXTURE",
            "generator_version": "2.0",
            "total_targets": 1,
            "total_exploits": 5,
            "total_failures": 2,
        },
        "executive_summary": "# Executive Summary\n\nTargets: 1",
        "attack_timeline": [
            {
                "timestamp": "2026-01-01T10:00:00+00:00",
                "event_type": "exploit_success",
                "description": "pwned",
                "target": "10.0.0.5",
                "module": "eternalblue",
                "result": "success",
                "metadata": {},
            }
        ],
        "exploitation_chains": [
            {
                "chain_id": "CHAIN-10-0-0-5",
                "target": "10.0.0.5",
                "entries": [{"module": "eternalblue", "timestamp": "2026-01-01T10:00:00+00:00", "result": "success"}],
                "successful": True,
                "final_privilege": "root",
                "total_duration": 0.0,
            }
        ],
        "technical_findings": [
            approved,
            _finding("F-proposed", "SecretProposedTitle"),
            _finding("F-rejected", "SecretRejectedTitle", hitl_status="REJECTED"),
            _finding(
                "F-fixed",
                "SecretFixedTitle",
                hitl_status="APPROVED",
                hitl_history=human,
                verify_status="VERIFIED",
                verify_history=verified_hist,
                retest_status="FIXED",
                retest_history=[{"timestamp": "2026-01-03T00:00:00+00:00", "verdict": "FIXED", "evidence": "closed"}],
            ),
            still_open,
            "not-a-dict",
            None,
        ],
        "failure_analysis": [
            {
                "operation": "smb_login",
                "failure_count": 2,
                "primary_error": "Timeout",
                "error_breakdown": {"Timeout": 2},
                "mitigation_suggestion": "retry",
                "recovery_actions": [],
            }
        ],
    }


# ── import surface ─────────────────────────────────────────────────────────


def test_shim_reexports_canonical_objects() -> None:
    """Every shim name resolves to the identical new-package object."""
    shim = importlib.import_module("tools.enhanced_reporting")
    expected = {
        "CVSSScore": "tools.reporting.cvss",
        "calculate_cvss": "tools.reporting.cvss",
        "estimate_cvss": "tools.reporting.cvss",
        "_bump_cia": "tools.reporting.cvss",
        "_cvss_profile_from_services": "tools.reporting.cvss",
        "_service_field": "tools.reporting.cvss",
        "_service_indicates_vulnerable_version": "tools.reporting.cvss",
        "AttackTimelineEntry": "tools.reporting.models",
        "ExploitationChain": "tools.reporting.models",
        "FailureAnalysis": "tools.reporting.models",
        "TechnicalFinding": "tools.reporting.models",
        "_confidence_from_verdict": "tools.reporting.models",
        "_resolve_verdict": "tools.reporting.models",
        "approved_findings": "tools.reporting.models",
        "apply_hitl_filter": "tools.reporting.models",
        "_format_retest_md": "tools.reporting.markdown",
        "_generate_chains_md": "tools.reporting.markdown",
        "_generate_failures_md": "tools.reporting.markdown",
        "_generate_findings_md": "tools.reporting.markdown",
        "_generate_markdown": "tools.reporting.markdown",
        "_generate_timeline_md": "tools.reporting.markdown",
        "_HTML_CSS": "tools.reporting.html",
        "_esc": "tools.reporting.html",
        "_format_retest_html": "tools.reporting.html",
        "_generate_chains_html": "tools.reporting.html",
        "_generate_failures_html": "tools.reporting.html",
        "_generate_findings_html": "tools.reporting.html",
        "_generate_html": "tools.reporting.html",
        "_generate_timeline_html": "tools.reporting.html",
        "_sev_class": "tools.reporting.html",
        "EnhancedReportGenerator": "tools.reporting.generator",
    }
    for name, module_path in expected.items():
        module = importlib.import_module(module_path)
        assert getattr(shim, name) is getattr(module, name), name
    assert "EnhancedReportGenerator" in shim.__all__
    assert "approved_findings" in shim.__all__


def test_known_callers_import_paths_intact() -> None:
    """Modules the todo lists as callers-unchanged still import cleanly."""
    importlib.import_module("tools.mcp_tools.hitl")
    importlib.import_module("tools.mcp_tools.verify")
    importlib.import_module("tools.mcp_tools.web_scan")
    importlib.import_module("tools.run_service.execute")
    from tools.enhanced_reporting import CVSSScore, EnhancedReportGenerator, TechnicalFinding  # noqa: F401
    from tools.mcp_tools.web_scan import TechnicalFinding as _WS  # noqa: F401


# ── byte parity vs pre-split fixtures ──────────────────────────────────────


def test_rendered_output_matches_pre_split_fixtures(tmp_path: Path) -> None:
    from tools.enhanced_reporting import EnhancedReportGenerator, apply_hitl_filter

    gen = EnhancedReportGenerator(db=None, mission_id="FIXTURE", workspace=tmp_path)
    report = _mixed_report()
    pending = apply_hitl_filter(report)
    assert pending == 5
    assert [f["finding_id"] for f in report["technical_findings"]] == ["F-approved", "F-open"]

    md = gen._generate_markdown(report, pending_count=pending)
    assert md == (FIXTURES / "report.md").read_text(encoding="utf-8")

    html = gen._generate_html(report, pending_count=pending)
    assert html == (FIXTURES / "report.html").read_text(encoding="utf-8")

    rendered_json = json.dumps(report, indent=2, sort_keys=True)
    assert rendered_json == (FIXTURES / "report.json").read_text(encoding="utf-8")

    # No unapproved titles leak into any surface.
    for needle in ("SecretProposedTitle", "SecretRejectedTitle", "SecretFixedTitle"):
        assert needle not in md
        assert needle not in html
        assert needle not in rendered_json
    assert "awaiting human review" in md
    assert "awaiting human review" in html
