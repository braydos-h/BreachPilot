"""Eval package — canonical location for the ``--eval`` harness.

Split from ``tools.eval_harness`` (todo 06) by responsibility:

  - ``metrics`` — single-run scoring + report rendering.
  - ``single_run`` — the ``--eval`` CLI entry.
  - ``suite`` — Docker target-suite scoring.
  - ``graded`` — flag-oracle loop, verify sessions, skipped reports.
  - ``baseline`` — baseline persistence and regression gating.
  - ``live`` — outcome taxonomy, provenance, telemetry, thresholds.

``tools.eval_harness`` is a thin compat shim; tests keep patching
``tools.eval_harness.<name>`` (call sites resolve through the shim at
call time — precedent: ``tools/campaign/phases.py``).
"""

from __future__ import annotations

import importlib
from typing import Any

from tools.eval_checks import default_check_executor as default_check_executor

__all__ = [
    "EvalMetrics",
    "EvalSuiteResult",
    "compute_metrics",
    "render_report",
    "render_markdown",
    "render_html",
    "write_eval_report",
    "run_eval",
    "load_target_oracle",
    "score_against_oracle",
    "run_eval_suite",
    "docker_suite_up",
    "docker_suite_down",
    "FlagCheckResult",
    "TargetScore",
    "EvalReport",
    "verify_flag_check",
    "default_check_executor",
    "run_graded_eval",
    "default_agent_runner",
    "save_baseline",
    "check_regression",
    "LiveOutcome",
    "classify_live_outcome",
    "RunProvenance",
    "build_run_provenance",
    "TrialTelemetry",
    "extract_trial_telemetry",
    "ReliabilityMetrics",
    "compute_reliability_metrics",
    "aggregate_finding_lifecycle",
    "check_live_thresholds",
    "write_skipped_eval_report",
]

_ATTR_MAP: dict[str, str] = {
    "EvalMetrics": "tools.eval.metrics",
    "EvalSuiteResult": "tools.eval.suite",
    "compute_metrics": "tools.eval.metrics",
    "render_report": "tools.eval.metrics",
    "render_markdown": "tools.eval.metrics",
    "render_html": "tools.eval.metrics",
    "write_eval_report": "tools.eval.metrics",
    "run_eval": "tools.eval.single_run",
    "load_target_oracle": "tools.eval.suite",
    "score_against_oracle": "tools.eval.suite",
    "run_eval_suite": "tools.eval.suite",
    "docker_suite_up": "tools.eval.suite",
    "docker_suite_down": "tools.eval.suite",
    "FlagCheckResult": "tools.eval.graded",
    "TargetScore": "tools.eval.graded",
    "EvalReport": "tools.eval.graded",
    "verify_flag_check": "tools.eval.graded",
    "run_graded_eval": "tools.eval.graded",
    "default_agent_runner": "tools.eval.graded",
    "save_baseline": "tools.eval.baseline",
    "check_regression": "tools.eval.baseline",
    "LiveOutcome": "tools.eval.live",
    "classify_live_outcome": "tools.eval.live",
    "RunProvenance": "tools.eval.live",
    "build_run_provenance": "tools.eval.live",
    "TrialTelemetry": "tools.eval.live",
    "extract_trial_telemetry": "tools.eval.live",
    "ReliabilityMetrics": "tools.eval.live",
    "compute_reliability_metrics": "tools.eval.live",
    "aggregate_finding_lifecycle": "tools.eval.live",
    "check_live_thresholds": "tools.eval.live",
    "write_skipped_eval_report": "tools.eval.graded",
}


def __getattr__(name: str) -> Any:
    if name in _ATTR_MAP:
        mod = importlib.import_module(_ATTR_MAP[name])
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
