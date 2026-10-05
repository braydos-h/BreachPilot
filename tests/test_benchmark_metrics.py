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
    claimed: bool | None = None,
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
        agent_claimed_success=verified if claimed is None else claimed,
        oracle_verified_success=verified,
        duration_seconds=duration,
        tool_calls=actions,
        total_tokens=tokens,
        estimated_cost=cost,
        failure_category=category,
        scope_violations=0,
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
    assert s.trials_completed == 3
    assert s.verified == 1
    assert s.false_positives == 1
    assert s.timeouts == 1
    assert s.success_probability == 1 / 3
    assert s.ci95_low is not None and s.ci95_high is not None
    assert s.median_duration == 60.0
    assert s.median_actions == 8.0
    assert s.total_tokens == 250
    assert s.failure_categories.get(FailureCategory.FALSE_POSITIVE.value) == 1


def test_scenario_summary_infra_errors_excluded_from_rate():
    """Infra errors say nothing about exploit ability — excluded from the rate."""
    trials = [
        _trial(verified=True, claimed=True, status="VERIFIED"),
        _trial(status="INFRASTRUCTURE_ERROR", category=FailureCategory.SANDBOX_FAILED.value),
        _trial(status=TrialStatus.SKIPPED.value),
    ]
    s = compute_scenario_summary(trials, "s1")
    assert s.infra_errors == 1
    assert s.trials == 3
    assert s.trials_completed == 1
    assert s.success_probability == 1.0


def test_all_infrastructure_errors_and_skips_have_unavailable_rates():
    trials = [
        _trial(
            "s1",
            status=TrialStatus.INFRASTRUCTURE_ERROR.value,
            category=FailureCategory.SANDBOX_FAILED.value,
        ),
        _trial("s1", status=TrialStatus.SKIPPED.value),
    ]

    scenario = compute_scenario_summary(trials, "s1")
    summary = compute_run_summary(trials, run_id="r1", suite="xben")

    assert scenario.trials == 2
    assert scenario.trials_completed == 0
    assert scenario.infra_errors == 1
    assert scenario.skipped == 1
    assert scenario.success_probability is None
    assert scenario.success_variance is None
    assert scenario.success_stddev is None
    assert scenario.ci95_low is None and scenario.ci95_high is None

    assert scenario.to_dict()["success_probability"] is None

    assert summary.trials_total == 2
    assert summary.trials_completed == 0
    assert summary.solved == 0
    assert summary.infra_error_count == 1
    assert summary.skipped_count == 1
    assert summary.verified_success_rate is None
    assert summary.false_positive_rate is None
    assert summary.false_negative_rate is None
    assert summary.stuck_loop_rate is None


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
    # Median solve time is over VERIFIED trials (the one verified run: 120s).
    assert summary.median_solve_time == 120.0
    assert summary.estimated_cost == 0.5
    assert summary.total_tokens == 700
    assert summary.time_to_first_verified_success == 120.0
    assert len(summary.scenarios) == 2


def test_run_summary_empty():
    summary = compute_run_summary([], run_id="r1", suite="xben")
    assert summary.trials_total == 0
    assert summary.trials_completed == 0
    assert summary.verified_success_rate is None
    assert summary.false_positive_rate is None
    assert summary.reproduced_twice_rate is None
    assert summary.estimated_cost is None


def test_run_summary_from_dict_normalizes_legacy_empty_outcome_rates():
    payload = {
        "trials_total": 2,
        "trials_completed": 0,
        "verified_success_rate": 0.0,
        "false_positive_rate": 0.0,
        "false_negative_rate": 0.0,
        "stuck_loop_rate": 0.0,
        "scenarios": [
            {
                "scenario_id": "s1",
                "trials": 2,
                "trials_completed": 0,
                "success_probability": 0.0,
                "success_variance": 0.0,
                "success_stddev": 0.0,
                "ci95_low": 0.0,
                "ci95_high": 0.65,
            }
        ],
    }

    summary = run_summary_from_dict(payload)

    assert summary.verified_success_rate is None
    assert summary.false_positive_rate is None
    assert summary.false_negative_rate is None
    assert summary.stuck_loop_rate is None
    scenario = summary.scenarios[0]
    assert scenario.success_probability is None
    assert scenario.success_variance is None
    assert scenario.success_stddev is None
    assert scenario.ci95_low is None and scenario.ci95_high is None

    payload.pop("trials_completed")
    payload["scenarios"][0].pop("trials_completed")
    summary_without_denominator = run_summary_from_dict(payload)
    assert summary_without_denominator.verified_success_rate is None
    assert summary_without_denominator.false_positive_rate is None
    assert summary_without_denominator.scenarios[0].success_probability is None


def test_reproduced_twice_rate_is_unavailable_without_verified_scenarios():
    summary = compute_run_summary(
        [_trial("s1", verified=False, claimed=False, status=TrialStatus.FAILED.value)],
        run_id="r1",
        suite="xben",
    )
    assert summary.scenarios_reproduced_twice == 0
    assert summary.reproduced_twice_rate is None
    assert summary.to_dict()["reproduced_twice_rate"] is None

    stale_payload = summary.to_dict()
    stale_payload["reproduced_twice_rate"] = 0.0
    assert run_summary_from_dict(stale_payload).reproduced_twice_rate is None


def test_reproduced_twice_rate_uses_only_scenarios_with_verified_trials():
    trials = [
        _trial("s1", verified=True, claimed=True, status=TrialStatus.VERIFIED.value),
        _trial("s1", verified=True, claimed=True, status=TrialStatus.VERIFIED.value),
        _trial("s2", verified=True, claimed=True, status=TrialStatus.VERIFIED.value),
        _trial("s3", verified=False, status=TrialStatus.FAILED.value),
    ]
    summary = compute_run_summary(trials, run_id="r1", suite="xben")
    assert summary.scenarios_reproduced_twice == 1
    assert summary.reproduced_twice_rate == 0.5


def test_run_summary_from_dict_roundtrip():
    trials = [_trial("s1", verified=True, claimed=True, status="VERIFIED", duration=90)]
    original = compute_run_summary(trials, run_id="r1", suite="xben", scenario_meta={"s1": {"name": "S1"}})
    payload = original.to_dict()
    rebuilt = run_summary_from_dict(payload)
    assert isinstance(rebuilt, RunSummary)
    assert rebuilt.run_id == original.run_id
    assert rebuilt.verified_success_rate == original.verified_success_rate


def test_legacy_scope_zero_is_not_restored_as_measured():
    from tools.benchmark.metrics import run_summary_from_dict

    payload = RunSummary(scope_violation_count=0).to_dict()
    payload.pop("scope_violation_telemetry_available")
    rebuilt = run_summary_from_dict(payload)
    assert rebuilt.scope_violation_count is None
    assert rebuilt.scope_violation_telemetry_available is False
