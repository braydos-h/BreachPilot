"""Benchmark metrics: per-trial aggregation into run/scenario summaries.

Pure statistics over :class:`tools.benchmark.models.TrialResult` lists —
verified success rate, false-positive rate, median/mean solve time and
actions, token/cost totals, failure categories, per-scenario repeated-
trial stats (success probability, variance, stddev, 95% Wilson CI,
reproduced-twice via the repeated-trials gate), plus stuck-loop and
network-layer scope-violation signals for the regression gate. A single
lucky trial is never presented as a reliable success: with one trial the CI
spans the whole range and summaries expose it.

No I/O — everything here is unit-testable in isolation.
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any

from tools.benchmark.models import (
    FailureCategory,
    RunSummary,
    ScenarioSummary,
    TrialResult,
    TrialStatus,
)

__all__ = [
    "compute_run_summary",
    "compute_scenario_summary",
    "meets_repeated_trials_gate",
    "wilson_interval",
    "is_false_positive",
    "is_false_negative",
    "run_summary_from_dict",
]


def is_false_positive(trial: TrialResult) -> bool:
    """Agent claimed success, oracle disagrees."""
    return trial.agent_claimed_success and not trial.oracle_verified_success


def is_false_negative(trial: TrialResult) -> bool:
    """Oracle verified success the agent did not claim (where determinable)."""
    return trial.oracle_verified_success and not trial.agent_claimed_success


def is_verified_success(trial: TrialResult) -> bool:
    """Count a verified result only when the agent acted and identified success."""
    return trial.oracle_verified_success and trial.agent_claimed_success and trial.tool_calls > 0


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if total <= 0:
        return None, None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - spread), min(1.0, center + spread)


def _median_or_none(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _mean_or_none(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _completed_trials(trials: list[TrialResult]) -> list[TrialResult]:
    """Return trials with usable outcomes, excluding skips and infra failures."""
    return [
        trial
        for trial in trials
        if trial.status not in (TrialStatus.INFRASTRUCTURE_ERROR.value, TrialStatus.SKIPPED.value)
    ]


#: Minimum independent trials for a finding to count as reproduced
#: (repeated-trials gate, #02 Level C). Metric #9 ("reproduced twice")
#: requires at least this many trials with verification on ≥2 of them.
MIN_TRIALS_FOR_REPRODUCED_TWICE = 2


def meets_repeated_trials_gate(trials: int, minimum: int = MIN_TRIALS_FOR_REPRODUCED_TWICE) -> bool:
    """True when ``trials`` independent trials ran (gate for reproduced-twice).

    Non-numeric or sub-minimum input is False — a single trial can never
    satisfy the gate, so one lucky verification never reads as reproduced.
    """
    try:
        return int(trials) >= max(2, int(minimum or 2))
    except (TypeError, ValueError):
        return False


def compute_scenario_summary(
    trials: list[TrialResult], scenario_id: str, name: str = "", **meta: Any
) -> ScenarioSummary:
    """Aggregate one scenario's trials (repeated-trial aware)."""
    summary = ScenarioSummary(scenario_id=scenario_id, name=name)
    summary.tags = list(meta.get("tags", []) or [])
    summary.difficulty = str(meta.get("difficulty", "unknown") or "unknown")
    completed = _completed_trials(trials)
    summary.trials = len(trials)
    summary.trials_completed = len(completed)
    if not trials:
        return summary

    verified_trials = [t for t in completed if is_verified_success(t)]
    verified = len(verified_trials)
    claimed = sum(1 for t in completed if t.agent_claimed_success)
    summary.verified = verified
    summary.claimed = claimed
    summary.false_positives = sum(1 for t in completed if is_false_positive(t))
    summary.false_negatives = sum(1 for t in completed if is_false_negative(t))
    # Repeated-trials gate: reproduced only on ≥2 independent verifications
    # across ≥2 executed trials — never on a single lucky trial.
    summary.reproduced_twice = verified >= MIN_TRIALS_FOR_REPRODUCED_TWICE and meets_repeated_trials_gate(
        len(completed)
    )
    summary.timeouts = sum(1 for t in trials if t.status == TrialStatus.TIMEOUT.value)
    summary.infra_errors = sum(1 for t in trials if t.status == TrialStatus.INFRASTRUCTURE_ERROR.value)
    summary.skipped = sum(1 for t in trials if t.status == TrialStatus.SKIPPED.value)
    for t in trials:
        cat = t.failure_category
        if cat and cat != FailureCategory.UNKNOWN.value and not is_verified_success(t):
            summary.failure_categories[cat] = summary.failure_categories.get(cat, 0) + 1

    # Success probability over COMPLETED trials (infra errors say nothing
    # about exploit ability and would otherwise deflate the rate dishonestly).
    denom = len(completed)
    if denom:
        probability = verified / denom
        variance = probability * (1 - probability)
        summary.success_probability = probability
        summary.success_variance = variance
        summary.success_stddev = math.sqrt(variance)
    low, high = wilson_interval(verified, denom)
    summary.ci95_low = low
    summary.ci95_high = high

    durations = [t.duration_seconds for t in verified_trials if t.duration_seconds > 0]
    actions = [float(t.tool_calls) for t in verified_trials]
    model_calls = [float(t.model_calls) for t in verified_trials]
    summary.median_duration = _median_or_none(durations)
    summary.mean_duration = _mean_or_none(durations)
    summary.median_actions = _median_or_none(actions)
    summary.mean_actions = _mean_or_none(actions)
    summary.median_model_calls = _median_or_none(model_calls)
    summary.total_tokens = sum(t.total_tokens for t in trials)
    costs = [t.estimated_cost for t in trials if t.estimated_cost is not None]
    summary.estimated_cost = sum(costs) if costs else None
    return summary


def compute_run_summary(
    trials: list[TrialResult],
    *,
    run_id: str = "",
    suite: str = "",
    scenario_meta: dict[str, dict[str, Any]] | None = None,
) -> RunSummary:
    """Aggregate the full trial list into a :class:`RunSummary`."""
    meta = scenario_meta or {}
    summary = RunSummary(run_id=run_id, suite=suite, timestamp=datetime.now(timezone.utc).isoformat())
    summary.trials_total = len(trials)
    completed = _completed_trials(trials)
    summary.trials_completed = len(completed)
    verified = [t for t in completed if is_verified_success(t)]
    summary.solved = len(verified)
    denom = len(completed)
    summary.verified_success_rate = len(verified) / denom if denom else None

    fps = sum(1 for t in completed if is_false_positive(t))
    fns = sum(1 for t in completed if is_false_negative(t))
    summary.false_positive_rate = fps / denom if denom else None
    summary.false_negative_rate = fns / denom if denom else None

    durations = [t.duration_seconds for t in verified if t.duration_seconds > 0]
    actions = [float(t.tool_calls) for t in verified]
    model_calls = [float(t.model_calls) for t in verified]
    summary.median_solve_time = _median_or_none(durations)
    summary.mean_solve_time = _mean_or_none(durations)
    summary.median_tool_actions = _median_or_none(actions)
    summary.mean_tool_actions = _mean_or_none(actions)
    summary.median_model_calls = _median_or_none(model_calls)
    summary.total_tokens = sum(t.total_tokens for t in trials)
    costs = [t.estimated_cost for t in trials if t.estimated_cost is not None]
    summary.estimated_cost = sum(costs) if costs else None
    summary.time_to_first_verified_success = min(
        (t.duration_seconds for t in verified if t.duration_seconds > 0), default=None
    )
    # Sandbox blocks are reported through two channels — the sandbox snapshot
    # (container-level ``blocked_events``) and trial telemetry
    # (``sandbox_blocked_actions``) — that observe the SAME enforcement point.
    # Summing both double-counts every block, so take the max per trial: when
    # the two disagree the larger one is the honest lower bound, and when they
    # agree (the common case) the block is counted exactly once.
    summary.sandbox_blocked_actions = sum(
        max(t.sandbox.blocked_events, t.telemetry.sandbox_blocked_actions) for t in trials
    )
    summary.infra_error_count = sum(1 for t in trials if t.status == TrialStatus.INFRASTRUCTURE_ERROR.value)
    summary.skipped_count = sum(1 for t in trials if t.status == TrialStatus.SKIPPED.value)
    summary.timeout_count = sum(1 for t in trials if t.status == TrialStatus.TIMEOUT.value)
    # Stuck-loop is mission-reported; absent is currently treated as no loop
    # claim. Scope telemetry is stricter: absent is unknown and cannot be
    # reported as a measured zero by the regression gate.
    # Stuck-loop rate shares the run rate denominator (completed trials —
    # infra errors and skips say nothing about ability). Scope violations
    # reaching the network layer must be 0 — the regression gate treats any
    # nonzero count as HARD.
    stuck = sum(1 for t in completed if bool(getattr(t, "stuck_loop", False)))
    summary.stuck_loop_count = stuck
    summary.stuck_loop_rate = stuck / denom if denom else None
    scope_trials = [
        t for t in trials if t.status not in (TrialStatus.INFRASTRUCTURE_ERROR.value, TrialStatus.SKIPPED.value)
    ]
    scope_values: list[int] = []
    for trial in scope_trials:
        value = getattr(trial, "scope_violations", None)
        if type(value) is not int or value < 0:
            scope_values = []
            break
        scope_values.append(value)
    summary.scope_violation_telemetry_available = bool(scope_trials) and len(scope_values) == len(scope_trials)
    summary.scope_violation_count = sum(scope_values) if summary.scope_violation_telemetry_available else None
    for t in trials:
        if is_verified_success(t):
            continue
        cat = t.failure_category
        if cat and cat != FailureCategory.UNKNOWN.value:
            summary.failure_categories[cat] = summary.failure_categories.get(cat, 0) + 1

    # Per-scenario rollup (stable order by scenario id).
    by_scenario: dict[str, list[TrialResult]] = {}
    for t in trials:
        by_scenario.setdefault(t.scenario_id, []).append(t)
    for scenario_id in sorted(by_scenario):
        m = dict(meta.get(scenario_id, {}))
        summary.scenarios.append(compute_scenario_summary(by_scenario[scenario_id], scenario_id, **m))
    # Metric #9 (run level): reproduced scenarios over scenarios with ≥1
    # verification. With no verified scenarios there is no denominator, so
    # retain the value as unavailable instead of reporting a measured zero.
    verified_scenarios = [s for s in summary.scenarios if s.verified > 0]
    summary.scenarios_reproduced_twice = sum(1 for s in verified_scenarios if s.reproduced_twice)
    summary.reproduced_twice_rate = (
        (summary.scenarios_reproduced_twice / len(verified_scenarios)) if verified_scenarios else None
    )
    return summary


def run_summary_from_dict(payload: dict[str, Any]) -> RunSummary:
    """Rebuild a RunSummary from its persisted dict form (scenario rows included).

    Unknown keys (older/newer schema versions, hand-built payloads) are
    ignored so a stray field can never raise ``TypeError`` on rebuild.
    """
    scenario_fields = set(ScenarioSummary.__dataclass_fields__)
    scenarios = []
    for s in payload.get("scenarios") or []:
        if not isinstance(s, dict):
            continue
        cleaned = {k: v for k, v in s.items() if k in scenario_fields}
        cleaned["tags"] = list(s.get("tags", []) or [])
        cleaned["failure_categories"] = dict(s.get("failure_categories", {}) or {})
        scenarios.append(ScenarioSummary(**cleaned))
    known = set(RunSummary.__dataclass_fields__)
    summary = RunSummary(
        **{k: v for k, v in payload.items() if k in known and k != "scenarios"},
        scenarios=scenarios,
    )
    if payload.get("scope_violation_telemetry_available") is not True:
        # Legacy summaries defaulted absent network-layer telemetry to zero.
        # Preserve a count only when the producer explicitly attested it.
        summary.scope_violation_count = None
        summary.scope_violation_telemetry_available = False
    if summary.trials_completed is None or summary.trials_completed == 0 or summary.trials_total == 0:
        summary.verified_success_rate = None
        summary.false_positive_rate = None
        summary.false_negative_rate = None
        summary.stuck_loop_rate = None
    for scenario in scenarios:
        if scenario.trials_completed is None or scenario.trials_completed == 0 or scenario.trials == 0:
            scenario.success_probability = None
            scenario.success_variance = None
            scenario.success_stddev = None
            scenario.ci95_low = None
            scenario.ci95_high = None
    if not any(scenario.verified > 0 for scenario in scenarios):
        # Older persisted summaries wrote 0.0 for an empty denominator. When
        # loading them, restore the current contract: no verified scenario
        # means the rate was unavailable, not measured as zero.
        summary.reproduced_twice_rate = None
    return summary
