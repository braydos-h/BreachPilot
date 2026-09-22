"""Thin compat shim — implementation lives in :mod:`tools.eval`.

Split by responsibility (todo 06): ``tools/eval/metrics.py``,
``single_run.py``, ``suite.py``, ``graded.py``, ``baseline.py``, ``live.py``. Tests keep
patching ``tools.eval_harness.<name>``; submodules resolve those seams
through this module at call time.
"""

from __future__ import annotations

from pathlib import Path

from tools.eval.baseline import check_regression as check_regression
from tools.eval.baseline import save_baseline as save_baseline
from tools.eval.graded import _CONFIG_PATH_KEY as _CONFIG_PATH_KEY
from tools.eval.graded import _WORKSPACE_KEY as _WORKSPACE_KEY
from tools.eval.graded import AgentRunner as AgentRunner
from tools.eval.graded import EvalReport as EvalReport
from tools.eval.graded import FlagCheckResult as FlagCheckResult
from tools.eval.graded import TargetScore as TargetScore
from tools.eval.graded import _host_owned_when_met as _host_owned_when_met
from tools.eval.graded import default_agent_runner as default_agent_runner
from tools.eval.graded import run_graded_eval as run_graded_eval
from tools.eval.graded import verify_flag_check as verify_flag_check
from tools.eval.graded import write_skipped_eval_report as write_skipped_eval_report
from tools.eval.live import LiveOutcome as LiveOutcome
from tools.eval.live import ReliabilityMetrics as ReliabilityMetrics
from tools.eval.live import RunProvenance as RunProvenance
from tools.eval.live import TrialTelemetry as TrialTelemetry
from tools.eval.live import aggregate_finding_lifecycle as aggregate_finding_lifecycle
from tools.eval.live import build_run_provenance as build_run_provenance
from tools.eval.live import check_live_thresholds as check_live_thresholds
from tools.eval.live import classify_live_outcome as classify_live_outcome
from tools.eval.live import compute_reliability_metrics as compute_reliability_metrics
from tools.eval.live import extract_trial_telemetry as extract_trial_telemetry
from tools.eval.metrics import EvalMetrics as EvalMetrics
from tools.eval.metrics import compute_metrics as compute_metrics
from tools.eval.metrics import render_html as render_html
from tools.eval.metrics import render_markdown as render_markdown
from tools.eval.metrics import render_report as render_report
from tools.eval.metrics import write_eval_report as write_eval_report
from tools.eval.single_run import run_eval as run_eval
from tools.eval.suite import EvalSuiteResult as EvalSuiteResult
from tools.eval.suite import docker_suite_down as docker_suite_down
from tools.eval.suite import docker_suite_up as docker_suite_up
from tools.eval.suite import load_target_oracle as load_target_oracle
from tools.eval.suite import run_eval_suite as run_eval_suite
from tools.eval.suite import score_against_oracle as score_against_oracle
from tools.eval_checks import default_check_executor as default_check_executor
from tools.mcp_session import open_exploit_mcp_session as open_exploit_mcp_session

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

if __name__ == "__main__":  # pragma: no cover - manual entry
    import asyncio
    from argparse import Namespace

    class _Args(Namespace):
        target = "127.0.0.1"
        config = Path("config.yaml")

    raise SystemExit(asyncio.run(run_eval(_Args())))
