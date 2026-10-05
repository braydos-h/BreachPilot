"""Unit tests for benchmark storage, regression, and verifier."""

from __future__ import annotations

import json

import pytest

from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import FailureCategory, RunConfig, RunEnvironment, TrialResult, TrialStatus
from tools.benchmark.regression import (
    RegressionThresholds,
    compare_summaries_payload,
    compare_to_baseline,
    load_baseline,
    save_baseline,
    thresholds_from_config,
)
from tools.benchmark.storage import BenchmarkStorage
from tools.benchmark.verifier import IndependentVerifier


def _trial(scenario: str, index: int, status: str, **kw) -> TrialResult:
    kw.setdefault("scope_violations", 0)
    if status == TrialStatus.VERIFIED.value:
        kw.setdefault("agent_claimed_success", True)
        kw.setdefault("tool_calls", 1)
    return TrialResult(
        run_id="r1",
        suite="xben",
        scenario_id=scenario,
        trial_index=index,
        trial_id=f"{scenario}#t{index}",
        status=status,
        **kw,
    )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_storage_roundtrip(tmp_path):
    storage = BenchmarkStorage(tmp_path / "bench")
    config = RunConfig(suite="xben", scenario_ids=["s1"], trials=1)
    env = RunEnvironment(git_sha="abc123")
    run_dir = storage.init_run("xben", "run1", config, env, ["s1"])
    assert (run_dir / "run.json").exists()

    trial = _trial("s1", 0, TrialStatus.VERIFIED.value, oracle_verified_success=True)
    storage.write_trial("xben", "run1", trial)
    summary = compute_run_summary([trial], run_id="run1", suite="xben")
    storage.finalize_run(
        "xben",
        "run1",
        status="completed",
        trials=[trial],
        summary=summary,
        config=config,
        environment=env,
        scenario_ids=["s1"],
    )

    run = storage.load_run("xben", "run1")
    assert run is not None
    assert run["status"] == "completed"
    assert run["environment"]["git_sha"] == "abc123"
    assert run["summary"]["solved"] == 1

    runs = storage.list_runs("xben")
    assert len(runs) == 1
    assert runs[0]["run_id"] == "run1"
    assert runs[0]["verified_success_rate"] == 1.0


def test_storage_rejects_path_traversal(tmp_path):
    storage = BenchmarkStorage(tmp_path)
    with pytest.raises(ValueError):
        storage.run_dir("..", "run1")
    with pytest.raises(ValueError):
        storage.run_dir("xben", "../evil")
    with pytest.raises(ValueError):
        storage.scenario_dir("xben", "run1", "a/../b")


def test_storage_list_runs_across_suites(tmp_path):
    storage = BenchmarkStorage(tmp_path)
    for suite, rid in (("xben", "r-a"), ("fake", "r-b")):
        storage.init_run(suite, rid, RunConfig(suite=suite), RunEnvironment(), ["s1"])
        summary = compute_run_summary([_trial("s1", 0, "VERIFIED")], run_id=rid, suite=suite)
        storage.finalize_run(
            suite,
            rid,
            status="completed",
            trials=[],
            summary=summary,
            config=RunConfig(suite=suite),
            environment=RunEnvironment(),
            scenario_ids=["s1"],
        )
    runs = storage.list_runs()
    assert {r["suite"] for r in runs} == {"xben", "fake"}


def test_storage_load_missing_returns_none(tmp_path):
    storage = BenchmarkStorage(tmp_path)
    assert storage.load_run("xben", "nope") is None
    assert storage.load_summary("xben", "nope") is None
    assert storage.load_events("xben", "nope") == []


def test_storage_events_filtering(tmp_path):
    storage = BenchmarkStorage(tmp_path)
    storage.init_run("xben", "r1", RunConfig(suite="xben"), RunEnvironment(), ["s1"])
    events_path = storage.run_dir("xben", "r1") / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as fh:
        for i, (tid, seq) in enumerate([("s1#t0", 1), ("s1#t1", 2), ("s2#t0", 3)]):
            fh.write(json.dumps({"sequence": seq, "trial_id": tid, "type": "x"}) + "\n")
    assert len(storage.load_events("xben", "r1")) == 3
    assert [e["sequence"] for e in storage.load_events("xben", "r1", trial_id="s1#t0")] == [1]
    assert [e["sequence"] for e in storage.load_events("xben", "r1", after=2)] == [3]


# ---------------------------------------------------------------------------
# Regression
# ---------------------------------------------------------------------------


def _summary_payload(rate=0.9, fp=0.02, time=600.0, actions=30.0, cost=1.0, scenarios=None):
    scenario_rows = scenarios or {"s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 1, "trials": 1}}
    # Hand-authored fixtures model all rows as completed unless a test supplies
    # a different effective denominator explicitly.
    scenario_rows = {
        scenario_id: {**row, "trials_completed": row.get("trials_completed", row.get("trials"))}
        for scenario_id, row in scenario_rows.items()
    }
    return {
        "run_id": "base",
        "suite": "xben",
        "trials_total": 10,
        "verified_success_rate": rate,
        "false_positive_rate": fp,
        "stuck_loop_rate": 0.0,
        "scope_violation_count": 0,
        "scope_violation_telemetry_available": True,
        "median_solve_time": time,
        "median_tool_actions": actions,
        "estimated_cost": cost,
        "scenarios": scenario_rows,
    }


def test_regression_fail_closed_on_missing_baseline(tmp_path):
    result = compare_to_baseline(compute_run_summary([]), None)
    assert not result.passed
    assert result.findings[0].severity == "hard"


def test_regression_hard_on_success_rate_drop(tmp_path):
    baseline = _summary_payload(
        rate=0.9,
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 0.9, "verified": 9, "trials": 10}},
    )
    current = compute_run_summary(
        [_trial("s1", 0, "VERIFIED", oracle_verified_success=True)]
        + [_trial("s1", index, "FAILED") for index in range(1, 10)],
        suite="xben",
    )
    result = compare_to_baseline(current, baseline, RegressionThresholds(success_rate_tolerance=0.02))
    assert not result.passed
    assert any(f.severity == "hard" and f.metric == "verified_success_rate" for f in result.findings)


def test_regression_hard_on_false_positive_increase(tmp_path):
    baseline = _summary_payload(
        fp=0.0,
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 5, "trials": 5}},
    )
    current = compute_run_summary(
        [
            _trial("s1", 0, "FALSE_POSITIVE", agent_claimed_success=True),
            _trial("s1", 1, "VERIFIED", oracle_verified_success=True),
            _trial("s1", 2, "VERIFIED", oracle_verified_success=True),
            _trial("s1", 3, "VERIFIED", oracle_verified_success=True),
            _trial("s1", 4, "VERIFIED", oracle_verified_success=True),
        ],
        suite="xben",
    )
    result = compare_to_baseline(current, baseline)
    assert not result.passed
    assert any(f.severity == "hard" and f.metric == "false_positive_rate" for f in result.findings)


def test_regression_warning_on_time_and_cost_increase():
    baseline = _summary_payload(time=100.0, cost=1.0)
    current = compute_run_summary(
        [_trial("s1", 0, "VERIFIED", oracle_verified_success=True, duration_seconds=100.0, estimated_cost=2.0)],
        suite="xben",
    )
    result = compare_to_baseline(current, baseline)
    assert result.passed  # warnings do not fail CI
    assert any(f.severity == "warning" and f.metric == "estimated_cost" for f in result.findings)


def test_regression_hard_on_previously_solved_now_unsolved():
    baseline = _summary_payload()
    current = compute_run_summary([_trial("s1", 0, "FAILED")], suite="xben")
    result = compare_to_baseline(current, baseline)
    assert not result.passed
    assert any(f.metric == "scenario:s1" and f.severity == "hard" for f in result.findings)


def test_filtered_run_marks_aggregate_rates_incomparable_to_full_baseline():
    baseline = _summary_payload(
        rate=0.5,
        scenarios={
            "s1": {"scenario_id": "s1", "success_probability": 0.0, "verified": 0, "trials": 1},
            "s2": {"scenario_id": "s2", "success_probability": 1.0, "verified": 1, "trials": 1},
        },
    )
    current = compute_run_summary([_trial("s1", 0, "FAILED")], suite="xben")

    result = compare_to_baseline(current, baseline)

    assert not result.passed  # an incomplete comparison cannot be reported as a pass
    assert result.hard_count == 0
    assert result.incomparable_count == 6
    assert {f.metric for f in result.findings if f.severity == "incomparable"} == {
        "verified_success_rate",
        "false_positive_rate",
        "stuck_loop_rate",
        "median_solve_time",
        "median_tool_actions",
        "estimated_cost",
    }
    assert not any(f.metric.startswith("scenario:") and f.severity == "hard" for f in result.findings)


def test_filtered_run_still_detects_regression_on_a_shared_scenario():
    baseline = _summary_payload(
        rate=1.0,
        scenarios={
            "s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 1, "trials": 1},
            "s2": {"scenario_id": "s2", "success_probability": 1.0, "verified": 1, "trials": 1},
        },
    )
    current = compute_run_summary([_trial("s1", 0, "FAILED")], suite="xben")

    result = compare_to_baseline(current, baseline)

    assert any(f.metric == "scenario:s1" and f.severity == "hard" for f in result.findings)
    assert any(f.metric == "verified_success_rate" and f.severity == "incomparable" for f in result.findings)


def test_regression_marks_different_per_scenario_trial_counts_incomparable():
    baseline = _summary_payload(
        rate=0.8,
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 0.8, "verified": 8, "trials": 10}},
    )
    current = compute_run_summary([_trial("s1", 0, "VERIFIED", oracle_verified_success=True)], suite="xben")

    result = compare_to_baseline(current, baseline)

    assert not result.passed
    assert result.incomparable_count > 0
    assert any(f.metric == "verified_success_rate" and f.severity == "incomparable" for f in result.findings)
    assert any(f.metric == "scenario:s1" and f.severity == "incomparable" for f in result.findings)
    assert not any(f.metric == "scenario:s1" and f.severity == "hard" for f in result.findings)


def test_scope_violation_remains_hard_when_no_trial_has_a_usable_outcome():
    trial = _trial("s1", 0, "INFRASTRUCTURE_ERROR")
    trial.scope_violations = 1
    current = compute_run_summary([trial], suite="xben")
    baseline = _summary_payload()

    result = compare_to_baseline(current, baseline)

    assert current.verified_success_rate is None
    assert not result.passed
    assert any(finding.metric == "scope_violation_count" and finding.severity == "hard" for finding in result.findings)


def test_scope_violation_is_reported_even_when_baseline_is_missing():
    trial = _trial("s1", 0, "FAILED")
    trial.scope_violations = 1

    result = compare_to_baseline(compute_run_summary([trial], suite="xben"), None)

    assert any(finding.metric == "scope_violation_count" and finding.severity == "hard" for finding in result.findings)


def test_legacy_baseline_without_completed_trial_counts_fails_closed():
    baseline = _summary_payload()
    baseline["scenarios"]["s1"].pop("trials_completed")
    current = compute_run_summary([_trial("s1", 0, "VERIFIED", oracle_verified_success=True)], suite="xben")

    result = compare_to_baseline(current, baseline)

    assert not result.passed
    assert result.incomparable_count > 0
    assert any(f.metric == "scenario:s1" and f.severity == "incomparable" for f in result.findings)


def test_regression_compares_completed_trials_not_only_total_rows(tmp_path):
    def trial(index, status, *, verified=False):
        return _trial("s1", index, status, oracle_verified_success=verified)

    baseline_summary = compute_run_summary(
        [trial(0, "VERIFIED", verified=True)] + [trial(i, "FAILED") for i in range(1, 10)], suite="xben"
    )
    candidate_summary = compute_run_summary(
        [trial(0, "VERIFIED", verified=True)] + [trial(i, "INFRASTRUCTURE_ERROR") for i in range(1, 10)],
        suite="xben",
    )
    baseline_path = save_baseline(baseline_summary, tmp_path / "baseline.json")
    baseline = load_baseline(baseline_path)

    assert baseline is not None
    assert baseline["scenarios"]["s1"]["trials"] == 10
    assert baseline["scenarios"]["s1"]["trials_completed"] == 10
    assert candidate_summary.scenarios[0].trials == 10
    assert candidate_summary.scenarios[0].trials_completed == 1

    result = compare_to_baseline(candidate_summary, baseline)

    assert not result.passed
    assert result.incomparable_count > 0
    assert not any(f.metric == "verified_success_rate" and f.severity == "improvement" for f in result.findings)


def test_regression_improvement_detection():
    baseline = _summary_payload(
        rate=0.5,
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 0.5, "verified": 1, "trials": 2}},
    )
    current = compute_run_summary(
        [
            _trial("s1", 0, "VERIFIED", oracle_verified_success=True),
            _trial("s1", 1, "VERIFIED", oracle_verified_success=True),
        ],
        suite="xben",
    )
    result = compare_to_baseline(current, baseline)
    assert result.passed
    assert any(f.severity == "improvement" and f.metric == "verified_success_rate" for f in result.findings)
    assert result.improvement_count >= 1


def test_baseline_save_load_roundtrip(tmp_path):
    summary = compute_run_summary([_trial("s1", 0, "VERIFIED", oracle_verified_success=True)])
    path = save_baseline(summary, tmp_path / "baseline.json")
    loaded = load_baseline(path)
    assert loaded is not None
    assert loaded["run_id"] == summary.run_id
    assert "s1" in loaded["scenarios"]


def test_legacy_baseline_scope_zero_is_normalized_to_unknown(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(
        json.dumps(
            {
                "scope_violation_count": 0,
                "trials_total": 1,
                "scenarios": {"s1": {"scenario_id": "s1", "trials": 1}},
            }
        ),
        encoding="utf-8",
    )
    loaded = load_baseline(path)
    assert loaded is not None
    assert loaded["scope_violation_count"] is None
    assert loaded["scope_violation_telemetry_available"] is False
    assert loaded["scenarios"]["s1"]["trials"] == 1


def test_legacy_baseline_positive_scope_count_is_preserved_as_failure_evidence(tmp_path):
    path = tmp_path / "legacy-positive.json"
    path.write_text(json.dumps({"scope_violation_count": 2, "trials_total": 1}), encoding="utf-8")

    loaded = load_baseline(path)

    assert loaded is not None
    assert loaded["scope_violation_count"] == 2
    assert loaded["scope_violation_telemetry_available"] is False


def test_load_baseline_normalizes_legacy_zero_for_empty_reproduction_denominator(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "run_id": "legacy",
                "suite": "xben",
                "trials_total": 2,
                "verified_success_rate": 0.0,
                "false_positive_rate": 0.0,
                "reproduced_twice_rate": 0.0,
                "scenarios": {"s1": {"success_probability": 0.0, "verified": 0, "trials": 1}},
            }
        ),
        encoding="utf-8",
    )

    loaded = load_baseline(path)

    assert loaded is not None
    assert loaded["verified_success_rate"] is None
    assert loaded["false_positive_rate"] is None
    assert loaded["scenarios"]["s1"]["success_probability"] is None
    assert loaded["reproduced_twice_rate"] is None


def test_thresholds_from_config():
    th = thresholds_from_config({"benchmark": {"regression": {"success_rate_tolerance": 0.1}}})
    assert th.success_rate_tolerance == 0.1
    assert th.false_positive_tolerance == 0.01  # default


def test_compare_summaries_payload_categories():
    base = _summary_payload(
        scenarios={
            "s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 1, "trials": 1},
            "s2": {"scenario_id": "s2", "success_probability": 1.0, "verified": 1, "trials": 1},
            "s3": {"scenario_id": "s3", "success_probability": 0.0, "verified": 0, "trials": 1},
        }
    )
    current = _summary_payload(
        rate=0.95,
        scenarios={
            "s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 1, "trials": 1},
            "s2": {"scenario_id": "s2", "success_probability": 0.0, "verified": 0, "trials": 1},
            "s3": {"scenario_id": "s3", "success_probability": 1.0, "verified": 1, "trials": 1},
            "s4": {"scenario_id": "s4", "success_probability": 1.0, "verified": 1, "trials": 1},
        },
    )
    payload = compare_summaries_payload(base, current)
    assert set(payload["categories"]) == {"newly_solved", "regressed", "still_solved", "still_failing", "not_compared"}
    assert "s3" in payload["categories"]["newly_solved"]
    assert "s2" in payload["categories"]["regressed"]
    assert "s1" in payload["categories"]["still_solved"]
    by_id = {r["scenario_id"]: r for r in payload["scenarios"]}
    assert by_id["s4"]["category"] == "not_compared"
    assert by_id["s4"]["baseline"] is None
    assert by_id["s4"]["current"] == 1.0
    metrics = {m["metric"]: m for m in payload["metrics"]}
    assert metrics["verified_success_rate"]["direction"] == "incomparable"
    assert metrics["solved"]["direction"] == "incomparable"


def test_compare_summaries_surfaces_scope_violation_for_different_trial_counts():
    base = _summary_payload(
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 0.5, "verified": 5, "trials": 10}}
    )
    current = _summary_payload(
        scenarios={"s1": {"scenario_id": "s1", "success_probability": 1.0, "verified": 1, "trials": 1}}
    )
    current["scope_violation_count"] = 2
    current["scope_violation_telemetry_available"] = True

    payload = compare_summaries_payload(base, current)
    metrics = {m["metric"]: m for m in payload["metrics"]}

    assert metrics["scope_violation_count"]["direction"] == "regressed"
    assert metrics["scope_violation_count"]["current"] == 2
    assert metrics["scope_violation_count"]["safety_gate"] == "failed"
    assert payload["scenarios"][0]["category"] == "not_compared"


def test_compare_summaries_marks_scenario_not_compared_for_different_completed_denominators():
    base = _summary_payload(
        scenarios={
            "s1": {
                "scenario_id": "s1",
                "success_probability": 0.5,
                "verified": 5,
                "trials": 10,
                "trials_completed": 10,
            }
        }
    )
    current = _summary_payload(
        scenarios={
            "s1": {
                "scenario_id": "s1",
                "success_probability": 1.0,
                "verified": 1,
                "trials": 10,
                "trials_completed": 1,
            }
        }
    )

    payload = compare_summaries_payload(base, current)
    metrics = {m["metric"]: m for m in payload["metrics"]}

    assert metrics["verified_success_rate"]["direction"] == "incomparable"
    assert payload["scenarios"][0]["category"] == "not_compared"


def test_unavailable_reproduced_rate_stays_null_in_baseline_and_comparison(tmp_path):
    summary = compute_run_summary([_trial("s1", 0, "FAILED")], run_id="no-verified", suite="xben")
    path = save_baseline(summary, tmp_path / "baseline.json")
    loaded = load_baseline(path)
    assert loaded is not None
    assert loaded["reproduced_twice_rate"] is None

    stale_summary = summary.to_dict()
    stale_summary["reproduced_twice_rate"] = 0.0
    comparison = compare_summaries_payload(stale_summary, stale_summary)
    reproduced = next(row for row in comparison["metrics"] if row["metric"] == "reproduced_twice_rate")
    assert reproduced["baseline"] is None
    assert reproduced["current"] is None
    assert reproduced["delta"] is None
    assert reproduced["direction"] == "unavailable"


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def _scenario_with_oracle(oracle, suite="xben", scenario_id="s1"):
    from tools.benchmark.models import BenchmarkScenario

    return BenchmarkScenario(suite=suite, scenario_id=scenario_id, oracle=oracle)


def test_verifier_passes_when_executor_passes():
    oracle = {"flags": [{"id": "f1", "check": {"type": "fake"}}], "host_owned_when": "any"}
    scenario = _scenario_with_oracle(oracle)

    def executor(check):
        return True, "ok"

    outcome = IndependentVerifier(scenario, executor=executor).verify_sync()
    assert outcome.verified
    assert outcome.flags_captured == 1
    assert outcome.flags_total == 1


def test_verifier_fails_when_executor_fails():
    scenario = _scenario_with_oracle({"flags": [{"id": "f1", "check": {}}]})
    outcome = IndependentVerifier(scenario, executor=lambda check: (False, "nope")).verify_sync()
    assert not outcome.verified


def test_verifier_crashing_check_is_a_failed_check():
    scenario = _scenario_with_oracle({"flags": [{"id": "f1", "check": {}}]})

    def executor(check):
        raise RuntimeError("boom")

    outcome = IndependentVerifier(scenario, executor=executor).verify_sync()
    assert not outcome.verified
    assert "boom" in outcome.flags[0].detail


def test_verifier_host_owned_when_all():
    oracle = {
        "flags": [{"id": "f1", "check": {}}, {"id": "f2", "check": {}}],
        "host_owned_when": "all",
    }
    scenario = _scenario_with_oracle(oracle)
    outcome = IndependentVerifier(scenario, executor=lambda c: (True, "ok")).verify_sync()
    assert outcome.verified

    # One flag failing fails the host with host_owned_when: all.
    def half(check):
        return check.get("type") != "x", "ok"

    oracle_half = {"flags": [{"id": "f1", "check": {}}, {"id": "f2", "check": {"type": "x"}}], "host_owned_when": "all"}
    outcome2 = IndependentVerifier(_scenario_with_oracle(oracle_half), executor=half).verify_sync()
    assert not outcome2.verified


def test_verifier_no_flags_means_not_verified():
    """An oracle with no checks cannot be 'verified' — fail closed."""
    scenario = _scenario_with_oracle({"flags": []})
    outcome = IndependentVerifier(scenario, executor=lambda c: (True, "ok")).verify_sync()
    assert not outcome.verified


def test_verifier_uses_eval_check_executor_by_default(tmp_path, monkeypatch):
    """The default executor stack is the graded eval's default_check_executor."""
    import tools.benchmark.verifier as verifier_mod

    captured = {}

    def fake_default_executor(**kw):
        captured.update(kw)
        return lambda check: (True, "ok")

    monkeypatch.setattr(verifier_mod, "default_check_executor", fake_default_executor)
    scenario = _scenario_with_oracle({"flags": [{"id": "f1", "check": {}}]})
    outcome = verifier_mod.IndependentVerifier(scenario, workspace=tmp_path).verify_sync()
    assert outcome.verified
    assert captured["workspace"] == tmp_path
