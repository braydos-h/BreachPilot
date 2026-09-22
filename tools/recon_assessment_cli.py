"""Recon-first assessment helpers for the CLI.

Thin wrapper over :mod:`tools.recon.service` — the sequential assessment
path (``run_sequential_assessment``) and the shared CVE-query helper live in
the unified ``ReconService`` module. Public signatures here are unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.attack_ui import AttackUi
from tools.goal_suggester import ReconAssessment
from tools.recon.service import (
    cve_query_from_banner as _cve_query_from_banner,
)
from tools.recon.service import (
    extract_tool_text as _extract_tool_text,
)
from tools.recon.service import (
    run_sequential_assessment,
)

ui = AttackUi(plain=False)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.runtime_context import RuntimeContext

__all__ = [
    "_cve_query_from_banner",
    "_extract_tool_text",
    "run_recon_assessment",
    "ui",
]


async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
    ctx: "RuntimeContext | None" = None,
) -> ReconAssessment:
    """Run quick recon against target and build a structured assessment.

    Executes check_os, quick_scan, and search_cve_intel for each discovered
    service. Returns a ReconAssessment ready for goal suggestion.
    """
    return await run_sequential_assessment(
        session=session,
        target_ip=target_ip,
        reports_dir=reports_dir,
        ui=None if ctx is not None else ui,
        ctx=ctx,
    )
