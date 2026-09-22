"""TODO 14 — verified rates over capability count (mocked, hermetic).

Covers the metric #9/#11 aggregation wiring (verify proof capsules +
retest FIXED lifecycle into ``ReliabilityMetrics`` / benchmark summaries),
the repeated-trials gate for "reproduced twice", the regression gates that
fail on false-compromise rise / scope-violation > 0 / stuck-loop rise, and
the README/docs contract (headlines link the live table + repro commands;
counts only from generated catalogs — never invented numbers here).

No network, no docker, no model keys.
"""

from __future__ import annotations

import json
from pathlib import Path

T0 = "2026-01-01T00:00:00+00:00"
T1 = "2026-01-01T01:00:00+00:00"  # exactly 3600s after T0


def _finding(**overrides):
    base = {
        "finding_id": "F-1",
        "verify_status": "",
        "verify_history": [],
        "retest_status": "",
        "retest_history": [],
    }
    base.update(overrides)
    return base


# ── retest FIXED lifecycle (metric #11) ────────────────────────────────────


def test_aggregate_retest_lifecycle_fixed_timing():
    from tools.mcp_tools.retest import FIXED, aggregate_retest_lifecycle
    from tools.mcp_tools.verify import VERIFIED

    findings = [
        _finding(
            finding_id="F-fixed",
            verify_status=VERIFIED,
            verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "uid=0"}],
            retest_status=FIXED,
            retest_history=[{"timestamp": T1, "verdict": FIXED, "evidence": "refused"}],
        ),
        _finding(finding_id="F-open"),
    ]
    agg = aggregate_retest_lifecycle(findings)
    assert agg["total_findings"] == 2
    assert agg["verified_findings"] == 1
    assert agg["fixed_count"] == 1
    assert agg["fixed_finding_ids"] == ["F-fixed"]
    assert agg["mean_time_to_fix_seconds"] == 3600.0


def test_aggregate_retest_lifecycle_missing_timestamps_excluded_not_fabricated():
    from tools.mcp_tools.retest import FIXED, aggregate_retest_lifecycle

    findings = [
        _finding(
            finding_id="F-notime",
            retest_status=FIXED,
            retest_history=[{"timestamp": "", "verdict": FIXED, "evidence": "x"}],
        ),
    ]
    agg = aggregate_retest_lifecycle(findings)
    assert agg["fixed_count"] == 1
    assert agg["mean_time_to_fix_seconds"] is None
    assert agg["remediation_times_seconds"] == []


def test_aggregate_retest_lifecycle_empty():
    from tools.mcp_tools.retest import aggregate_retest_lifecycle

    agg = aggregate_retest_lifecycle([])
    assert agg["total_findings"] == 0
    assert agg["fixed_count"] == 0
    assert agg["mean_time_to_fix_seconds"] is None


# ── verify reproduced-twice (metric #9) ────────────────────────────────────


def test_is_reproduced_twice_capsule_and_repeat_paths():
    from tools.mcp_tools.verify import HOLDING, VERIFIED, is_reproduced_twice

    # One verify_finding call with the default repeats=2 already qualifies.
    assert is_reproduced_twice(
        _finding(verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x", "proof_capsule": {"n": 2}}])
    )
    # Two separate single-run VERIFIED verdicts also qualify.
    assert is_reproduced_twice(
        _finding(
            verify_history=[
                {"timestamp": T0, "verdict": VERIFIED, "evidence": "x"},
                {"timestamp": T1, "verdict": VERIFIED, "evidence": "y"},
            ]
        )
    )
    # A single single-run proof is not reproduced twice.
    assert not is_reproduced_twice(_finding(verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x"}]))
    # HOLDING never counts, and non-dicts are safe.
    assert not is_reproduced_twice(_finding(verify_history=[{"timestamp": T0, "verdict": HOLDING, "evidence": "x"}]))
    assert not is_reproduced_twice({})  # type: ignore[arg-type]


def test_count_reproduced_twice_denominator_is_verified_only():
    from tools.mcp_tools.verify import VERIFIED, count_reproduced_twice

    findings = [
        _finding(
            finding_id="F-twice",
            verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x", "proof_capsule": {"n": 2}}],
        ),
        _finding(
            finding_id="F-once",
            verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x"}],
        ),
        _finding(finding_id="F-never"),
    ]
    reproduced, denominator = count_reproduced_twice(findings)
    assert (reproduced, denominator) == (1, 2)
    assert count_reproduced_twice([]) == (0, 0)


# ── replay repeated-trials gate (plan-level repeatability) ─────────────────


def test_simulate_repeated_rules_path_is_stable():
    from tools.replay_simulator import simulate_repeated

    plan = {
        "target_ip": "10.0.0.50",
        "steps": [
            {
                "phase": "exploit",
                "tool": "quick_scan",
                "reason": "probe port 80",
                "target_ip": "10.0.0.50",
                "arguments": {"target_ip": "10.0.0.50", "ports": "80"},
            }
        ],
    }
    recon = {"target_ip": "10.0.0.50", "open_ports": [80], "cve_findings": []}
    repeated = simulate_repeated(plan, recon, trials=2)
    assert repeated.trials == 2
    assert repeated.stable is True  # deterministic rules path agrees with itself
    assert repeated.confidence_spread == 0.0
    payload = repeated.to_dict()
    assert payload["stable"] is True and len(payload["runs"]) == 2


def test_simulate_repeated_single_trial_never_stable():
    from tools.replay_simulator import simulate_repeated

    plan = {"target_ip": "10.0.0.50", "steps": []}
    recon = {"target_ip": "10.0.0.50", "open_ports": [], "cve_findings": []}
    repeated = simulate_repeated(plan, recon, trials=1)
    assert repeated.trials == 1
    assert repeated.stable is False  # one run is no evidence of reproduction


# ── eval harness: lifecycle merge + scope extraction + gates ────────────────


def _telemetry(**kwargs):
    from tools.eval_harness import TrialTelemetry

    base = {"target_id": "t"}
    base.update(kwargs)
    return TrialTelemetry(**base)


def test_extract_trial_telemetry_scope_violations():
    from tools.eval_harness import extract_trial_telemetry

    tel = extract_trial_telemetry("t", {"records": [], "scope_violations_network": 2})
    assert tel.scope_violations == 2
    assert tel.scope_rejections == 0  # distinct signal: blocked attempts vs past-containment
    tel2 = extract_trial_telemetry("t", {"records": [], "scope_violations_network": "bogus"})
    assert tel2.scope_violations == 0
    tel3 = extract_trial_telemetry("t", {"records": []})
    assert tel3.scope_violations == 0  # absent signal is no signal


def test_aggregate_finding_lifecycle_combines_verify_and_retest():
    from tools.eval_harness import aggregate_finding_lifecycle
    from tools.mcp_tools.retest import FIXED
    from tools.mcp_tools.verify import VERIFIED

    findings = [
        _finding(
            finding_id="F-full",
            verify_status=VERIFIED,
            verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x", "proof_capsule": {"n": 2}}],
            retest_status=FIXED,
            retest_history=[{"timestamp": T1, "verdict": FIXED, "evidence": "y"}],
        ),
    ]
    lifecycle = aggregate_finding_lifecycle(findings)
    assert lifecycle["reproduced_twice_count"] == 1
    assert lifecycle["reproduced_twice_denominator"] == 1
    assert lifecycle["reproduced_twice_rate"] == 1.0
    assert lifecycle["fixed_count"] == 1
    assert lifecycle["mean_time_to_fix_seconds"] == 3600.0
    assert aggregate_finding_lifecycle([])["reproduced_twice_rate"] == 0.0
    assert aggregate_finding_lifecycle(None)["fixed_count"] == 0


def test_compute_reliability_metrics_merges_lifecycle():
    from tools.eval_harness import aggregate_finding_lifecycle, compute_reliability_metrics
    from tools.mcp_tools.verify import VERIFIED

    findings = [
        _finding(
            verify_history=[{"timestamp": T0, "verdict": VERIFIED, "evidence": "x", "proof_capsule": {"n": 2}}],
        ),
    ]
    lifecycle = aggregate_finding_lifecycle(findings)
    trials = [_telemetry(target_id="a", total_actions=10, verified_success=True)]
    m = compute_reliability_metrics(trials, live_outcome="PASS", lifecycle=lifecycle)
    assert m.findings_reproduced_twice_rate == 1.0
    assert m.findings_reproduced_twice_count == 1
    assert m.findings_reproduced_twice_denominator == 1
    # No lifecycle → pending-collection defaults (remediation mean stays None).
    m2 = compute_reliability_metrics(trials, live_outcome="PASS")
    assert m2.findings_reproduced_twice_rate == 0.0
    assert m2.mean_time_to_remediation_seconds is None
    assert m2.scope_violation_count == 0


def test_check_live_thresholds_scope_gate():
    from tools.eval_harness import check_live_thresholds, compute_reliability_metrics

    trials = [_telemetry(target_id="a", total_actions=10, verified_success=True, scope_violations=1)]
    m = compute_reliability_metrics(trials, live_outcome="PASS")
    assert m.scope_violation_count == 1
    passed, messages = check_live_thresholds(m)
    assert passed is False
    assert any("scope_violation_count" in line for line in messages)


def _graded_report(**reliability_kwargs):
    from tools.eval_harness import EvalReport, ReliabilityMetrics, TargetScore

    rel = ReliabilityMetrics(live_outcome="PASS", **reliability_kwargs)
    return EvalReport(
        run_id="r1",
        timestamp="2026-01-01T00:00:00+00:00",
        targets=[TargetScore(target_id="a", score=0.9)],
        live_outcome="PASS",
        reliability=rel,
    )


def test_save_baseline_carries_reliability_snapshot(tmp_path):
    from tools.eval_harness import save_baseline

    path = save_baseline(_graded_report(false_compromise_rate=0.0), tmp_path / "base.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["reliability"]["false_compromise_rate"] == 0.0
    assert payload["reliability"]["scope_violation_count"] == 0
    assert "findings_reproduced_twice_rate" in payload["reliability"]


def test_check_regression_false_compromise_rise_is_hard(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_graded_report(false_compromise_rate=0.0), tmp_path / "base.json")
    current = _graded_report(false_compromise_rate=0.5)
    passed, messages = check_regression(current, tmp_path / "base.json")
    assert passed is False
    assert any("false_compromise_rate" in line and "REGRESSION" in line for line in messages)


def test_check_regression_scope_violation_is_hard(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_graded_report(), tmp_path / "base.json")
    current = _graded_report(scope_violation_count=1)
    passed, messages = check_regression(current, tmp_path / "base.json")
    assert passed is False
    assert any("scope_violation_count" in line and "REGRESSION" in line for line in messages)


def test_check_regression_stuck_loop_rise_is_hard(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_graded_report(stuck_loop_rate=0.0), tmp_path / "base.json")
    current = _graded_report(stuck_loop_rate=0.5)
    passed, messages = check_regression(current, tmp_path / "base.json")
    assert passed is False
    assert any("stuck_loop_rate" in line and "REGRESSION" in line for line in messages)


def test_check_regression_clean_run_passes(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_graded_report(), tmp_path / "base.json")
    passed, messages = check_regression(_graded_report(), tmp_path / "base.json")
    assert passed is True
    assert any("[ok] scope_violation_count 0" in line for line in messages)


def test_check_regression_legacy_baseline_skips_reliability_gates(tmp_path):
    from tools.eval_harness import check_regression

    legacy = {"run_id": "old", "timestamp": "t", "targets": {"a": {"score": 0.9}}}
    (tmp_path / "base.json").write_text(json.dumps(legacy), encoding="utf-8")
    passed, messages = check_regression(_graded_report(), tmp_path / "base.json")
    assert passed is True  # skip, never a failure on an old baseline
    assert any("[skip] reliability gates" in line for line in messages)


def test_check_regression_missing_baseline_fails_closed(tmp_path):
    from tools.eval_harness import check_regression

    passed, messages = check_regression(_graded_report(), tmp_path / "nope.json")
    assert passed is False
    assert "fail-closed" in messages[0]


def test_collect_finding_lifecycle_scans_run_dir(tmp_path):
    from tools.eval.graded import _collect_finding_lifecycle
    from tools.mcp_tools.retest import FIXED
    from tools.mcp_tools.verify import VERIFIED

    run_dir = tmp_path / "run1"
    enhanced = run_dir / "enhanced"
    enhanced.mkdir(parents=True)
    (enhanced / "enhanced_report.json").write_text(
        json.dumps(
            {
                "technical_findings": [
                    _finding(
                        finding_id="F-x",
                        verify_history=[
                            {
                                "timestamp": T0,
                                "verdict": VERIFIED,
                                "evidence": "x",
                                "proof_capsule": {"n": 2},
                            }
                        ],
                        retest_status=FIXED,
                        retest_history=[{"timestamp": T1, "verdict": FIXED, "evidence": "y"}],
                    )
                ]
            }
        ),
        encoding="utf-8",
    )
    lifecycle = _collect_finding_lifecycle(run_dir)
    assert lifecycle is not None
    assert lifecycle["fixed_count"] == 1
    assert lifecycle["reproduced_twice_rate"] == 1.0
    assert _collect_finding_lifecycle(tmp_path / "missing") is None
    (tmp_path / "empty").mkdir()
    assert _collect_finding_lifecycle(tmp_path / "empty") is None


# ── benchmark metrics: reproduced-twice, stuck, scope ──────────────────────


def _trial(scenario_id="s1", *, verified=False, claimed=False, status="FAILED", stuck=False, scope=0):
    from tools.benchmark.models import TrialResult

    return TrialResult(
        run_id="r1",
        suite="xben",
        scenario_id=scenario_id,
        trial_index=0,
        trial_id=f"{scenario_id}#t0",
        status=status,
        agent_claimed_success=claimed,
        oracle_verified_success=verified,
        stuck_loop=stuck,
        scope_violations=scope,
    )


def test_meets_repeated_trials_gate():
    from tools.benchmark.metrics import meets_repeated_trials_gate

    assert meets_repeated_trials_gate(2) is True
    assert meets_repeated_trials_gate(5) is True
    assert meets_repeated_trials_gate(1) is False
    assert meets_repeated_trials_gate(0) is False
    assert meets_repeated_trials_gate("bogus") is False


def test_scenario_reproduced_twice_needs_two_verifications():
    from tools.benchmark.metrics import compute_scenario_summary

    two = compute_scenario_summary([_trial(verified=True), _trial(verified=True)], "s1")
    assert two.verified == 2
    assert two.reproduced_twice is True
    one = compute_scenario_summary([_trial(verified=True)], "s1")
    assert one.reproduced_twice is False  # a single lucky trial never reproduces


def test_run_summary_reproduced_twice_rate_and_signals():
    from tools.benchmark.metrics import compute_run_summary

    summary = compute_run_summary(
        [
            _trial("s1", verified=True, status="VERIFIED"),
            _trial("s1", verified=True, status="VERIFIED"),
            _trial("s2", verified=True, status="VERIFIED"),
            _trial("s3", status="FAILED", stuck=True, scope=0),
        ]
    )
    assert summary.scenarios_reproduced_twice == 1  # s1 only
    assert summary.reproduced_twice_rate == 1 / 3  # over scenarios with ≥1 verification
    assert summary.stuck_loop_count == 1
    assert summary.stuck_loop_rate == 1 / 4
    assert summary.scope_violation_count == 0


def test_run_summary_scope_violations_counted():
    from tools.benchmark.metrics import compute_run_summary

    summary = compute_run_summary([_trial("s1", status="FAILED", scope=2)])
    assert summary.scope_violation_count == 2


def test_run_summary_empty_signals_are_zero_not_green():
    from tools.benchmark.metrics import compute_run_summary

    summary = compute_run_summary([])
    assert summary.reproduced_twice_rate == 0.0
    assert summary.stuck_loop_rate == 0.0
    assert summary.scope_violation_count == 0


# ── benchmark regression gates ─────────────────────────────────────────────


def _bench_summary(**overrides):
    from tools.benchmark.metrics import compute_run_summary

    trials = overrides.pop("trials", [_trial("s1", verified=True, status="VERIFIED")])
    summary = compute_run_summary(trials, run_id="r1", suite="xben")
    for key, value in overrides.items():
        setattr(summary, key, value)
    return summary


def test_benchmark_regression_scope_violation_is_hard(tmp_path):
    from tools.benchmark.regression import compare_to_baseline, load_baseline, save_baseline

    save_baseline(_bench_summary(), tmp_path / "base.json")
    current = _bench_summary(trials=[_trial("s1", status="FAILED", scope=1)])
    result = compare_to_baseline(current, load_baseline(tmp_path / "base.json"))
    assert result.passed is False
    assert any(f.severity == "hard" and f.metric == "scope_violation_count" for f in result.findings)


def test_benchmark_regression_stuck_loop_rise_is_hard(tmp_path):
    from tools.benchmark.regression import compare_to_baseline, load_baseline, save_baseline

    save_baseline(_bench_summary(), tmp_path / "base.json")
    current = _bench_summary(trials=[_trial("s1", status="FAILED", stuck=True)])
    result = compare_to_baseline(current, load_baseline(tmp_path / "base.json"))
    assert result.passed is False
    assert any(f.severity == "hard" and f.metric == "stuck_loop_rate" for f in result.findings)


def test_benchmark_regression_false_positive_rise_is_hard(tmp_path):
    from tools.benchmark.regression import compare_to_baseline, load_baseline, save_baseline

    save_baseline(_bench_summary(), tmp_path / "base.json")
    current = _bench_summary(trials=[_trial("s1", claimed=True, status="FALSE_POSITIVE")])
    result = compare_to_baseline(current, load_baseline(tmp_path / "base.json"))
    assert result.passed is False
    assert any(f.severity == "hard" and f.metric == "false_positive_rate" for f in result.findings)


def test_benchmark_regression_clean_run_passes(tmp_path):
    from tools.benchmark.regression import compare_to_baseline, load_baseline, save_baseline

    save_baseline(_bench_summary(), tmp_path / "base.json")
    result = compare_to_baseline(_bench_summary(), load_baseline(tmp_path / "base.json"))
    assert result.passed is True
    assert result.hard_count == 0


def test_benchmark_regression_old_baseline_without_new_keys(tmp_path):
    from tools.benchmark.regression import compare_to_baseline

    legacy = {
        "run_id": "old",
        "suite": "xben",
        "timestamp": "t",
        "verified_success_rate": 1.0,
        "false_positive_rate": 0.0,
        "scenarios": {},
    }
    result = compare_to_baseline(_bench_summary(), legacy)
    assert result.passed is True  # missing keys default to 0.0/0 — clean stays clean


def test_benchmark_regression_missing_baseline_fails_closed():
    from tools.benchmark.regression import compare_to_baseline

    result = compare_to_baseline(_bench_summary(), None)
    assert result.passed is False


# ── README / docs contract: headlines link the table, counts stay generated ─


def test_readme_headlines_link_live_table_not_counts():
    text = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    assert "139 skills, 153 MCP tools" not in text
    assert "153 MCP" not in text
    assert "167 MCP" not in text
    assert "Reliability over capability counts" in text
    assert "docs/reliability-metrics.md#live-results" in text
    for command in ("--benchmark xben --trials 5", "--eval --save-baseline", "--eval --check-regression"):
        assert command in text, f"README must carry the repro command: {command}"
    assert "docs/generated/capability-counts.json" in text
    assert "tool-catalog-generated" in text


def test_reliability_doc_names_implementations_and_stays_unpopulated():
    text = (Path(__file__).resolve().parent.parent / "docs" / "reliability-metrics.md").read_text(encoding="utf-8")
    for symbol in (
        "count_reproduced_twice",
        "aggregate_retest_lifecycle",
        "check_regression",
        "compare_to_baseline",
        "stuck_loop_tolerance",
    ):
        assert symbol in text, f"reliability-metrics.md must name the implementation: {symbol}"
    # No live numbers invented: the results table is still UNPOPULATED.
    assert text.count("UNPOPULATED") >= 5
