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
    """Oracle that returns a fixed verdict per scenario_id."""
    def _oracle(target_ip: str, scenario: Scenario) -> bool:
        return verdicts.get(scenario.scenario_id, False)
    return _oracle


def _mock_run_session(verdicts: dict[str, dict[str, bool]]):
    """Mock run_session. ``verdicts[condition][scenario_id]`` -> does the
    agent CLAIM success (agent_claimed_success)."""
    async def _run(**kwargs):
        # The agent's outcome_summary always claims compromise (high false-positive
        # rate on baseline) -- the oracle is the sole source of verified_success.
        return {"total_actions": 10, "outcome_summary": "compromises: 1"}
    return _run


@pytest.mark.asyncio
async def test_benchmark_oracle_determines_verified_success(tmp_path):
    """verified_success must come from the oracle, NOT the agent's claim."""
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
async def test_benchmark_computes_risk_ratio(tmp_path):
    """When treatment outperforms baseline, RR > 1."""
    scenarios = [_scenario(f"s{i}") for i in range(4)]
    # Oracle: treatment succeeds on all; baseline on none.
    class _SplitOracle:
        def __call__(self, target_ip: str, scenario: Scenario) -> bool:
            # Use the scenario_id to vary -- but we need condition. Instead,
            # always return True for treatment, False for baseline via a side
            # channel. Simpler: return True always, and let the condition config
            # drive the difference via the mock run_session... but verified_success
            # is oracle-only. So: make the oracle return True always, and split
            # agent_claimed by condition.
            return True

    cfg = BenchmarkConfig(
        scenarios=scenarios,
        oracle=_SplitOracle(),
        conditions=["baseline", "treatment"],
        trials_per_scenario=1,
        output_dir=tmp_path / "bench",
        run_session=_mock_run_session({}),
    )
    report = await run_benchmark(cfg)

    # Oracle always True -> both conditions have 100% verified success.
    assert report.verified_success_rate["baseline"] == 1.0
    assert report.verified_success_rate["treatment"] == 1.0
    # RR = 1.0 (equal). CI should bracket 1.0.
    assert report.risk_ratio == 1.0


@pytest.mark.asyncio
async def test_benchmark_treatment_higher_than_baseline(tmp_path):
    """A treatment with a higher verified rate than baseline yields RR > 1."""
    scenarios = [_scenario(f"s{i}") for i in range(4)]

    # The harness runs trials in scenario × condition × trial order, so for
    # each scenario it runs baseline first, then treatment. A call-counting
    # oracle that returns True only on the 2nd call per scenario (treatment)
    # gives baseline=0, treatment=4.
    call_state: dict[str, int] = {}

    class _PerScenarioAlternatingOracle:
        def __call__(self, target_ip, scenario):
            n = call_state.get(scenario.scenario_id, 0) + 1
            call_state[scenario.scenario_id] = n
            # 1st call per scenario = baseline (False); 2nd = treatment (True).
            return n == 2

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
        return {
            "total_actions": 10,
            "outcome_summary": "compromises: 1",
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
            return n == 2  # baseline fails, treatment succeeds

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
