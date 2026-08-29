"""Unit tests for benchmark models + metrics (no I/O)."""

from __future__ import annotations

from tools.benchmark.metrics import (
    compute_run_summary,
    compute_scenario_summary,
    is_false_negative,
    is_false_positive,
    run_summary_from_dict,
    wilson_interval,
)
from tools.benchmark.models import (
    FailureCategory,
    RunSummary,
    TrialResult,
    TrialStatus,
)


def _trial(
    scenario_id: str = "s1",
    *,
    verified: bool = False,
    claimed: bool = False,
    status: str = TrialStatus.FAILED.value,
    duration: float = 60.0,
    actions: int = 10,
    tokens: int = 100,
    cost: float | None = None,
    category: str = FailureCategory.UNKNOWN.value,
) -> TrialResult:
    t = TrialResult(
        run_id="r1",
        suite="xben",
        scenario_id=scenario_id,
        trial_index=0,
        trial_id=f"{scenario_id}#t0",
        status=status,
        agent_claimed_success=claimed,
        oracle_verified_success=verified,
        duration_seconds=duration,
        tool_calls=actions,
        total_tokens=tokens,
        estimated_cost=cost,
        failure_category=category,
    )
    return t


# ---------------------------------------------------------------------------
# Claimed vs verified primitives
# ---------------------------------------------------------------------------


def test_false_positive_detection():
    assert is_false_positive(_trial(claimed=True, verified=False))
    assert not is_false_positive(_trial(claimed=True, verified=True))
    assert not is_false_positive(_trial(claimed=False, verified=False))


def test_false_negative_detection():
    assert is_false_negative(_trial(claimed=False, verified=True))
    assert not is_false_negative(_trial(claimed=True, verified=True))


def test_status_false_positive_requires_claim():
    t = _trial(claimed=True, verified=False, status=TrialStatus.FALSE_POSITIVE.value)
    assert t.status == "FALSE_POSITIVE"


# ---------------------------------------------------------------------------
# Wilson interval
# ---------------------------------------------------------------------------


def test_wilson_interval_bounds():
    low, high = wilson_interval(0, 10)
    assert low == 0.0 and 0.0 < high < 0.35
    low, high = wilson_interval(10, 10)
    assert 0.65 < low <= 1.0 and high == 1.0
    low, high = wilson_interval(5, 10)
    assert low < 0.5 < high
    assert wilson_interval(0, 0) == (None, None)


def test_single_trial_wide_interval():
    """One lucky trial must not look reliable: CI spans most of the range."""
    low, high = wilson_interval(1, 1)
    assert low is not None and high is not None
    assert high - low > 0.5


# ---------------------------------------------------------------------------
# Scenario summary
# ---------------------------------------------------------------------------


def test_scenario_summary_counts():
    trials = [
        _trial(verified=True, claimed=True, status="VERIFIED", duration=60, actions=8, tokens=50),
        _trial(verified=False, claimed=True, status="FALSE_POSITIVE", category=FailureCategory.FALSE_POSITIVE.value),
        _trial(verified=False, claimed=False, status="TIMEOUT", category=FailureCategory.TIMEOUT.value),
    ]
    s = compute_scenario_summary(trials, "s1", name="Scenario 1", tags=["web"], difficulty="easy")
    assert s.trials == 3
    assert s.verified == 1
    assert s.false_positives == 1
    assert s.timeouts == 1
    assert s.success_probability == 1 / 3
    assert s.ci95_low is not None and s.ci95_high is not None
    assert s.median_duration == 60.0
    assert s.median_actions == 8.0
    assert s.total_tokens == 150
    assert s.failure_categories.get(FailureCategory.FALSE_POSITIVE.value) == 1


def test_scenario_summary_infra_errors_excluded_from_rate():
    """Infra errors say nothing about exploit ability — excluded from the rate."""
    trials = [
        _trial(verified=True, claimed=True, status="VERIFIED"),
        _trial(status="INFRASTRUCTURE_ERROR", category=FailureCategory.SANDBOX_FAILED.value),
    ]
    s = compute_scenario_summary(trials, "s1")
    assert s.infra_errors == 1
    assert s.success_probability == 1.0


# ---------------------------------------------------------------------------
# Run summary
# ---------------------------------------------------------------------------


def test_run_summary_aggregate():
    trials = [
        _trial("s1", verified=True, claimed=True, status="VERIFIED", duration=120, cost=0.5, tokens=500),
        _trial("s2", verified=False, claimed=True, status="FALSE_POSITIVE", duration=30),
        _trial("s2", verified=False, claimed=False, status="FAILED", duration=45),
    ]
    summary = compute_run_summary(
        trials, run_id="r1", suite="xben", scenario_meta={"s1": {"name": "S1"}, "s2": {"name": "S2"}}
    )
    assert summary.trials_total == 3
    assert summary.solved == 1
    assert abs(summary.verified_success_rate - 1 / 3) < 1e-9
    assert abs(summary.false_positive_rate - 1 / 3) < 1e-9
    assert summary.median_solve_time == 45.0
    assert summary.estimated_cost == 0.5
    assert summary.total_tokens == 600
    assert summary.time_to_first_verified_success == 120.0
    assert len(summary.scenarios) == 2


def test_run_summary_empty():
    summary = compute_run_summary([], run_id="r1", suite="xben")
    assert summary.trials_total == 0
    assert summary.verified_success_rate == 0.0
    assert summary.estimated_cost is None


def test_run_summary_from_dict_roundtrip():
    trials = [_trial("s1", verified=True, claimed=True, status="VERIFIED", duration=90)]
    original = compute_run_summary(trials, run_id="r1", suite="xben", scenario_meta={"s1": {"name": "S1"}})
    payload = original.to_dict()
    rebuilt = run_summary_from_dict(payload)
    assert isinstance(rebuilt, RunSummary)
    assert rebuilt.run_id == original.run_id
    assert rebuilt.verified_success_rate == original.verified_success_rate
    assert len(rebuilt.scenarios) == len(original.scenarios)
    assert rebuilt.scenarios[0].scenario_id == "s1"
