"""Resume-state loading helpers for CLI runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.goal_suggester import ReconAssessment

def _load_resume_state(
    reports_dir: Path, args: argparse.Namespace
) -> tuple[ReconAssessment, str, str] | None:
    """M21: on a successful --resume, reload the saved recon assessment and
    the operator's previously chosen goal so the resumed run reuses them
    instead of re-running recon and re-asking for a goal.

    Reads ``reports_dir / 'recon_assessment.json'`` (written by
    ``run_recon_assessment`` and annotated with ``chosen_goal`` /
    ``chosen_goal_description`` by the recon-first block). Falls back to
    ``args.goal`` / ``args.custom_goal`` when the saved goal keys are absent so
    a run that was started without recon-first can still resume cleanly.

    Returns ``None`` when there is nothing to restore (no file / unreadable),
    so callers can simply skip the override.
    """
    path = reports_dir / "recon_assessment.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        assessment = ReconAssessment.from_dict(data)
    except Exception:
        return None
    goal_name = str(data.get("chosen_goal") or getattr(args, "goal", "") or "").strip()
    goal_desc = str(
        data.get("chosen_goal_description") or getattr(args, "custom_goal", "") or ""
    ).strip()
    return assessment, goal_name, goal_desc
