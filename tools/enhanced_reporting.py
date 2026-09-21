"""Enhanced Report Generator — professional red-team style reporting (P2-04 shim).

The implementation now lives in :mod:`tools.reporting` (``cvss`` /
``models`` / ``markdown`` / ``html`` / ``generator``). This module is a
re-export shim so every existing import path keeps working unchanged::

    from tools.enhanced_reporting import EnhancedReportGenerator
    generator = EnhancedReportGenerator(db, mission_id, workspace)
    generator.generate_full_report(campaign_result)
"""

from __future__ import annotations

from tools.reporting.cvss import (
    CVSSScore,
    _bump_cia,
    _cvss_profile_from_services,
    _service_field,
    _service_indicates_vulnerable_version,
    calculate_cvss,
    estimate_cvss,
)
from tools.reporting.generator import EnhancedReportGenerator
from tools.reporting.html import (
    _HTML_CSS,
    _esc,
    _format_retest_html,
    _generate_chains_html,
    _generate_failures_html,
    _generate_findings_html,
    _generate_html,
    _generate_timeline_html,
    _sev_class,
)
from tools.reporting.markdown import (
    _format_retest_md,
    _generate_chains_md,
    _generate_failures_md,
    _generate_findings_md,
    _generate_markdown,
    _generate_timeline_md,
)
from tools.reporting.models import (
    AttackTimelineEntry,
    ExploitationChain,
    FailureAnalysis,
    TechnicalFinding,
    _confidence_from_verdict,
    _resolve_verdict,
    apply_hitl_filter,
    approved_findings,
)

__all__ = [
    "AttackTimelineEntry",
    "CVSSScore",
    "EnhancedReportGenerator",
    "ExploitationChain",
    "FailureAnalysis",
    "TechnicalFinding",
    "_HTML_CSS",
    "_bump_cia",
    "_confidence_from_verdict",
    "_cvss_profile_from_services",
    "_esc",
    "_format_retest_html",
    "_format_retest_md",
    "_generate_chains_html",
    "_generate_chains_md",
    "_generate_failures_html",
    "_generate_failures_md",
    "_generate_findings_html",
    "_generate_findings_md",
    "_generate_html",
    "_generate_markdown",
    "_generate_timeline_html",
    "_generate_timeline_md",
    "_resolve_verdict",
    "_service_field",
    "_service_indicates_vulnerable_version",
    "_sev_class",
    "apply_hitl_filter",
    "approved_findings",
    "calculate_cvss",
    "estimate_cvss",
]
