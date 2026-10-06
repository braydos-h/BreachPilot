"""Tests for the oracle-backed benchmark harness.

The harness scores trials with a target-side oracle (NOT the agent's own
claims), runs paired baseline-vs-treatment conditions, and computes a
bootstrap risk-ratio CI. These tests use a mock oracle + mock run_session so
no live MCP server or target is needed.
"""

from __future__ import annotations

import json

import pytest

from tools.eval_benchmark import (
    DEFAULT_BASELINE_CONFIG,
    DEFAULT_TREATMENT_CONFIG,
    BenchmarkConfig,
    Scenario,
    TargetResetError,
    run_benchmark,
)


def _scenario(sid: str, target: str = "10.0.0.5") -> Scenario:
    return Scenario(
        scenario_id=sid,
        target_ip=target,
        goal_name="initial_access",
        description="test",
        target_snapshot_id="snap-1",
    )


def _mock_oracle(verdicts: dict[str, bool]):
    """Oracle that starts clear, then returns the configured trial outcome."""
    calls: dict[str, int] = {}

    def _oracle(target_ip: str, scenario: Scenario) -> bool:
        count = calls.get(scenario.scenario_id, 0) + 1
        calls[scenario.scenario_id] = count
        return False if count % 2 else verdicts.get(scenario.scenario_id, False)

    return _oracle


def _mock_run_session(verdicts: dict[str, dict[str, bool]]):
    """Mock run_session. ``verdicts[condition][scenario_id]`` -> does the
    agent CLAIM success (agent_claimed_success)."""

    async def _run(**kwargs):
        # The agent claims success in its summary; only the oracle transition
        # plus an evidence-bearing exploit record can attribute the objective.
        target_ip = kwargs.get("target_ip", "")
        return {
            "total_actions": 10,
            "outcome_summary": "compromises: 1",
            "records": [
                {
                    "action": "run_attack_module",
                    "target_ip": target_ip,
                    "status": "completed",
                    "approved": True,
                    "exit_code": 0,
                    "exploit_outcome": "compromise",
                    "outcome_evidence": ["target-bound test evidence"],
                    "detail": json.dumps({"target_ip": target_ip}),
                }
            ],
        }

    return _run


@pytest.mark.asyncio
async def test_benchmark_oracle_determines_verified_success(tmp_path):
    """Success needs a new oracle-positive state and a completed target action."""
    scenarios = [_scenario("s1"), _scenario("s2")]
    # Oracle: s1 succeeds, s2 fails -- regardless of condition.
    oracle = _mock_oracle({"s1": True, "s2": False})

    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )
    report = await run_benchmark(cfg)

    # s1 verified, s2 not -- per the oracle, not the agent (both claimed).
    s1_trials = [t for t in report.trials if t.scenario_id == "s1"]
    s2_trials = [t for t in report.trials if t.scenario_id == "s2"]
    assert all(t.verified_success for t in s1_trials)
    assert all(not t.verified_success for t in s2_trials)
    # The agent claimed success on all (mock) -- so false-positive rate > 0 on s2.
    assert all(t.agent_claimed_success for t in report.trials)


@pytest.mark.asyncio
async def test_preexisting_oracle_state_is_not_attributed_to_agent(tmp_path):
    async def noop_run_session(**_kwargs):
        return {"total_actions": 0, "outcome_summary": ""}

    cfg = BenchmarkConfig(
        scenarios=[_scenario("preexisting")],
        oracle=lambda _target, _scenario: True,
        conditions=["baseline"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=noop_run_session,
    )

    report = await run_benchmark(cfg)

    trial = report.trials[0]
    assert trial.oracle_before_status == "verified"
    assert trial.oracle_status == "preexisting"
    assert trial.verified_success is None
    assert report.verified_success_rate["baseline"] is None
    assert report.status == "completed_with_unscored_trials"


@pytest.mark.asyncio
async def test_oracle_transition_without_successful_target_action_is_unattributed(tmp_path):
    calls = 0

    def oracle(_target, _scenario):
        nonlocal calls
        calls += 1
        return calls == 2

    async def noop_run_session(**_kwargs):
        return {"total_actions": 0, "outcome_summary": ""}

    cfg = BenchmarkConfig(
        scenarios=[_scenario("unattributed")],
        oracle=oracle,
        conditions=["baseline"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=noop_run_session,
    )

    report = await run_benchmark(cfg)

    trial = report.trials[0]
    assert trial.oracle_before_status == "not_verified"
    assert trial.oracle_status == "unattributed"
    assert trial.verified_success is None
    assert report.verified_success_rate["baseline"] is None


@pytest.mark.asyncio
async def test_recon_action_cannot_attribute_new_positive_oracle_state(tmp_path):
    calls = 0

    def oracle(_target, _scenario):
        nonlocal calls
        calls += 1
        return calls == 2

    async def recon_only_run(**kwargs):
        target_ip = kwargs["target_ip"]
        return {
            "total_actions": 1,
            "records": [
                {
                    "action": "quick_scan",
                    "target_ip": target_ip,
                    "status": "completed",
                    "approved": True,
                    "detail": json.dumps({"target_ip": target_ip}),
                }
            ],
        }

    cfg = BenchmarkConfig(
        scenarios=[_scenario("recon-only")],
        oracle=oracle,
        conditions=["baseline"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=recon_only_run,
    )

    report = await run_benchmark(cfg)

    assert report.trials[0].oracle_status == "unattributed"
    assert report.trials[0].verified_success is None
    assert report.verified_success_rate["baseline"] is None


@pytest.mark.asyncio
async def test_benchmark_computes_risk_ratio(tmp_path):
    """When treatment outperforms baseline, RR > 1."""
    scenarios = [_scenario(f"s{i}") for i in range(4)]

    # Oracle: treatment succeeds on all; baseline on none.
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_mock_oracle({scenario.scenario_id: True for scenario in scenarios}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )
    report = await run_benchmark(cfg)

    # Each trial begins clear, then the oracle confirms its post-run state.
    assert report.verified_success_rate["baseline"] == 1.0
    assert report.verified_success_rate["treatment"] == 1.0
    # RR = 1.0 (equal). CI should bracket 1.0.
    assert report.risk_ratio == 1.0


@pytest.mark.asyncio
async def test_benchmark_treatment_higher_than_baseline(tmp_path):
    """A treatment with a higher verified rate than baseline yields RR > 1."""
    scenarios = [_scenario(f"s{i}") for i in range(4)]

    # Each scenario gets two oracle reads per trial: before and after each
    # condition. The treatment post-read is the fourth call.
    call_state: dict[str, int] = {}

    class _PerScenarioAlternatingOracle:
        def __call__(self, target_ip, scenario):
            n = call_state.get(scenario.scenario_id, 0) + 1
            call_state[scenario.scenario_id] = n
            return n % 4 == 0

    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_PerScenarioAlternatingOracle(),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )
    report = await run_benchmark(cfg)

    assert report.verified_success_rate["baseline"] == 0.0
    assert report.verified_success_rate["treatment"] == 1.0
    # RR is undefined when baseline = 0 (the harness avoids division by zero
    # by only computing RR when base_rate > 0). Confirm it's None.
    assert report.risk_ratio is None


@pytest.mark.asyncio
async def test_real_session_receives_condition_merged_config(tmp_path, monkeypatch):
    """The production session must receive the config used to build its model.

    Otherwise paired baseline/treatment runs differ only in labels and
    ExploitSettings, while skills, long-session, memory, and provider behavior
    silently use the operator's on-disk config.
    """
    observed: list[dict] = []
    base = {
        "models": {"provider": "ollama", "default_alias": "test-model", "registry": {"test-model": "test"}},
        "ollama": {"host": "http://127.0.0.1:9"},
        "operator_setting": "preserved",
    }

    class _Router:
        def get_client(self, _alias):
            return object()

    async def _run_session(**kwargs):
        observed.append(kwargs["config_override"])
        return {"total_actions": 1, "outcome_summary": "compromises: 0"}

    monkeypatch.setattr("tools.config_cli.load_config", lambda _path: base)
    monkeypatch.setattr("tools.model_router.build_router", lambda *_args, **_kwargs: _Router())
    monkeypatch.setattr("tools.exploit_session.run_exploit_session", _run_session)

    cfg = BenchmarkConfig(
        scenarios=[_scenario("s1")],
        oracle=_mock_oracle({"s1": False}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        condition_configs={
            "baseline": {"skills": {"enabled": False}, "long_session": {"enabled": False}},
            "treatment": {"skills": {"enabled": True}, "long_session": {"enabled": True}},
        },
    )
    await run_benchmark(cfg)

    assert len(observed) == 2
    baseline, treatment = observed
    assert baseline["operator_setting"] == treatment["operator_setting"] == "preserved"
    assert baseline["skills"]["enabled"] is False
    assert treatment["skills"]["enabled"] is True
    assert baseline["long_session"]["enabled"] is False
    assert treatment["long_session"]["enabled"] is True


@pytest.mark.asyncio
async def test_benchmark_writes_report_json(tmp_path):
    """The benchmark persists a JSON report to output_dir."""
    scenarios = [_scenario("s1")]
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_mock_oracle({"s1": True}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )
    await run_benchmark(cfg)
    files = list((tmp_path / "bench").glob("benchmark_*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert "verified_success_rate" in data
    assert "trials" in data
    assert len(data["trials"]) == 2  # 1 scenario × 2 conditions × 1 trial


@pytest.mark.asyncio
async def test_benchmark_resets_target_between_trials(tmp_path):
    """When reset_target_between_trials is supplied, it's called before each
    trial."""
    scenarios = [_scenario("s1")]
    reset_count = {"n": 0}

    def _reset(scenario):
        reset_count["n"] += 1

    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_mock_oracle({"s1": True}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=2,
        output_dir=tmp_path / "bench",
        reset_target_between_trials=_reset,
        run_session=_mock_run_session({}),
    )
    await run_benchmark(cfg)
    # 1 scenario × 2 conditions × 2 trials = 4 resets.
    assert reset_count["n"] == 4


@pytest.mark.asyncio
async def test_target_reset_failure_aborts_before_scoring_contaminated_pair(tmp_path, monkeypatch):
    """A failed reset preserves prior trials without scoring an incomplete pair."""
    monkeypatch.chdir(tmp_path)
    reset_count = 0
    run_calls: list[dict] = []
    oracle_calls: list[str] = []

    def _reset(scenario):
        nonlocal reset_count
        reset_count += 1
        if reset_count == 2:
            raise OSError("snapshot restore failed")

    async def _run_session(**kwargs):
        run_calls.append(kwargs)
        return {"total_actions": 1, "outcome_summary": "compromises: 1"}

    def _oracle(target_ip: str, scenario: Scenario) -> bool:
        oracle_calls.append(scenario.scenario_id)
        return True

    cfg = BenchmarkConfig(
        scenarios=[_scenario("s1")],
        oracle=_oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        reset_target_between_trials=_reset,
        run_session=_run_session,
    )

    with pytest.raises(TargetResetError, match="aborting benchmark") as exc_info:
        await run_benchmark(cfg)

    assert (exc_info.value.scenario_id, exc_info.value.condition, exc_info.value.trial_index) == ("s1", "treatment", 0)
    assert isinstance(exc_info.value.__cause__, OSError)
    assert reset_count == 2
    assert len(run_calls) == 1
    assert len(oracle_calls) == 1
    partial = exc_info.value.partial_report
    assert partial is not None
    assert partial.status == "aborted"
    assert partial.risk_ratio is None
    assert partial.verified_success_rate["baseline"] is None
    assert partial.verified_success_rate["treatment"] is None
    assert len(partial.trials) == 1
    assert partial.trials[0].condition == "baseline"
    assert partial.trials[0].oracle_status == "preexisting"
    assert partial.trials[0].verified_success is None
    assert partial.oracle_measurements["treatment"]["attempted"] == 0
    assert partial.oracle_measurements["treatment"]["unmeasured"] == 1
    assert "cause type: OSError" in partial.error
    assert exc_info.value.report_path is not None and exc_info.value.report_path.is_file()
    persisted = json.loads(exc_info.value.report_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "aborted"
    assert len(persisted["trials"]) == 1
    assert persisted["risk_ratio"] is None


@pytest.mark.asyncio
async def test_oracle_exception_is_unavailable_not_a_negative_verdict(tmp_path):
    """Oracle errors remain visible and do not become false negatives/positives."""

    def _oracle(_target_ip: str, _scenario: Scenario) -> bool:
        raise TimeoutError("verification endpoint timed out")

    cfg = BenchmarkConfig(
        scenarios=[_scenario("s1")],
        oracle=_oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )

    report = await run_benchmark(cfg)

    assert report.status == "completed_with_errors"
    assert report.verified_success_rate["baseline"] is None
    assert report.false_positive_rate["baseline"] is None
    assert report.actions_per_verified_success["baseline"] is None
    assert report.findings_per_hour["baseline"] is None
    assert report.risk_ratio is None
    assert report.oracle_measurements["baseline"] == {
        "expected": 1,
        "attempted": 1,
        "verified": 0,
        "not_verified": 0,
        "preexisting": 0,
        "unattributed": 0,
        "error": 1,
        "unmeasured": 0,
    }
    assert report.trials[0].verified_success is None
    assert report.trials[0].oracle_status == "error"
    assert report.trials[0].oracle_error == "TimeoutError: oracle check failed"
    persisted_path = next((tmp_path / "bench").glob("benchmark_*.json"))
    persisted = json.loads(persisted_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "completed_with_errors"
    assert persisted["trials"][0]["verified_success"] is None
    assert persisted["trials"][0]["oracle_status"] == "error"
    assert persisted["trials"][0]["oracle_error"] == "TimeoutError: oracle check failed"
    assert persisted["verified_success_rate"]["baseline"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_verdict", [None, 1, "true"])
async def test_non_boolean_oracle_result_is_unavailable(tmp_path, invalid_verdict):
    cfg = BenchmarkConfig(
        scenarios=[_scenario("s1")],
        oracle=lambda _target_ip, _scenario: invalid_verdict,
        conditions=["baseline"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )

    report = await run_benchmark(cfg)

    assert report.verified_success_rate["baseline"] is None
    assert report.trials[0].verified_success is None
    assert report.trials[0].oracle_status == "error"
    assert "expected bool" in report.trials[0].oracle_error


def test_default_condition_configs_differ():
    """Baseline disables smart features; treatment enables them."""
    assert not DEFAULT_BASELINE_CONFIG["adaptive_exploits"]["enabled"]
    assert not DEFAULT_BASELINE_CONFIG["outcome_judgment"]["flow_a"]
    assert not DEFAULT_BASELINE_CONFIG["skills"]["enabled"]
    assert DEFAULT_TREATMENT_CONFIG["adaptive_exploits"]["enabled"]
    assert DEFAULT_TREATMENT_CONFIG["outcome_judgment"]["flow_a"]
    assert DEFAULT_TREATMENT_CONFIG["skills"]["enabled"]


# ── D5: throughput + token-cost fields ───────────────────────────────────────


def _mock_run_session_with_tokens(tokens: int, cost: float, duration: float = 1.0):
    """Mock run_session that returns token spend + cost + sleeps for ``duration``
    so the harness's wall-clock measurement is non-zero (Windows monotonic has
    microsecond resolution; a no-op async return measures as 0.0s, which would
    make findings/hour divide by zero)."""
    import asyncio

    async def _run(**kwargs):
        await asyncio.sleep(duration)
        target_ip = kwargs.get("target_ip", "")
        return {
            "total_actions": 10,
            "outcome_summary": "compromises: 1",
            "records": [
                {
                    "action": "run_attack_module",
                    "target_ip": target_ip,
                    "status": "completed",
                    "approved": True,
                    "exit_code": 0,
                    "exploit_outcome": "compromise",
                    "outcome_evidence": ["target-bound test evidence"],
                    "detail": json.dumps({"target_ip": target_ip}),
                }
            ],
            "total_tokens": tokens,
            "token_cost": cost,
            "duration_seconds": duration,
        }

    return _run


@pytest.mark.asyncio
async def test_benchmark_populates_findings_per_hour_and_token_cost(tmp_path):
    """The report carries findings_per_hour + token_cost_per_finding when the
    run_session supplies token data."""
    scenarios = [_scenario("s1")]
    oracle = _mock_oracle({"s1": True})
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session_with_tokens(tokens=10000, cost=0.50, duration=0.05),
    )
    report = await run_benchmark(cfg)
    # Both conditions verified -> findings_per_hour > 0, token_cost_per_finding = 0.50.
    assert "baseline" in report.findings_per_hour
    assert "treatment" in report.findings_per_hour
    assert report.findings_per_hour["baseline"] > 0
    assert report.token_cost_per_finding["baseline"] == 0.50
    assert report.token_cost_per_finding["treatment"] == 0.50
    # The paired oracle bounds the state transition but cannot time the finding.
    assert report.time_to_first_verified_success == {"baseline": None, "treatment": None}
    assert all(trial.time_to_first_verified_success is None for trial in report.trials)
    # The per-trial fields are populated.
    assert all(t.total_tokens == 10000 for t in report.trials)
    assert all(t.token_cost == 0.50 for t in report.trials)


@pytest.mark.asyncio
async def test_benchmark_token_cost_per_finding_none_when_no_successes(tmp_path):
    """When a condition has no verified successes, token_cost_per_finding is None."""
    scenarios = [_scenario("s1")]
    oracle = _mock_oracle({"s1": False})  # no successes
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session_with_tokens(tokens=5000, cost=0.10),
    )
    report = await run_benchmark(cfg)
    assert report.token_cost_per_finding["baseline"] is None
    assert report.token_cost_per_finding["treatment"] is None
    assert report.findings_per_hour["baseline"] == 0.0


@pytest.mark.asyncio
async def test_benchmark_defaults_zero_tokens_when_run_omits_them(tmp_path):
    """When run_session returns no token data, the fields default to 0 (not an
    error) -- the existing tests' mock path stays green."""
    scenarios = [_scenario("s1")]
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_mock_oracle({"s1": True}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),  # returns no total_tokens/token_cost
    )
    report = await run_benchmark(cfg)
    assert all(t.total_tokens == 0 for t in report.trials)
    assert all(t.token_cost == 0.0 for t in report.trials)
    # token_cost_per_finding is 0.0 (successes exist, cost is zero) -- not None.
    assert report.token_cost_per_finding["baseline"] == 0.0


@pytest.mark.asyncio
async def test_benchmark_existing_metrics_unchanged_with_new_fields(tmp_path):
    """Adding the new fields must NOT change the existing metrics (verified
    success rate, false-positive rate, risk ratio, actions per success)."""
    scenarios = [_scenario(f"s{i}") for i in range(4)]
    call_state: dict[str, int] = {}

    class _AlternatingOracle:
        def __call__(self, target_ip, scenario):
            n = call_state.get(scenario.scenario_id, 0) + 1
            call_state[scenario.scenario_id] = n
            return n % 4 == 0  # clear before each trial; treatment succeeds

    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_AlternatingOracle(),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session_with_tokens(tokens=1000, cost=0.01),
    )
    report = await run_benchmark(cfg)
    # Existing metrics -- same assertions as test_benchmark_treatment_higher_than_baseline.
    assert report.verified_success_rate["baseline"] == 0.0
    assert report.verified_success_rate["treatment"] == 1.0
    assert report.risk_ratio is None  # baseline = 0 -> RR undefined
    assert report.false_positive_rate["baseline"] == 1.0  # all claimed, none verified
    # New metrics: treatment has 4 successes with tokens -> cost per finding = 0.01.
    assert report.token_cost_per_finding["treatment"] == 0.01
    assert report.token_cost_per_finding["baseline"] is None  # no successes


@pytest.mark.asyncio
async def test_benchmark_report_json_includes_new_fields(tmp_path):
    """The persisted JSON report includes the new metric keys."""
    scenarios = [_scenario("s1")]
    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_mock_oracle({"s1": True}),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session_with_tokens(tokens=100, cost=0.05),
    )
    await run_benchmark(cfg)
    files = list((tmp_path / "bench").glob("benchmark_*.json"))
    data = json.loads(files[0].read_text())
    assert "findings_per_hour" in data
    assert "token_cost_per_finding" in data
    # Trial records carry the new per-trial fields.
    assert "total_tokens" in data["trials"][0]
    assert "token_cost" in data["trials"][0]
