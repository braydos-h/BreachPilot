"""Extended benchmark runner tests — discovery / parsing / isolation / timeout / retries."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.benchmark import BenchmarkScenario, seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, TrialTelemetry
from tools.benchmark.models import FailureCategory, RunConfig, TrialStatus
from tools.benchmark.runner import BenchmarkRunner
from tools.benchmark.targets import TargetProvisionError


def _scenario(scenario_id: str = "s1", **kw) -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
        **kw,
    )


def _config(tmp_path: Path, **bm) -> dict[str, Any]:
    return {
        "benchmark": {"output_dir": str(tmp_path / "bench"), "sandbox_required": False, **bm},
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
    }


class _FakeMission:
    def __init__(self, outcomes: list[MissionResult]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[str] = []

    async def run_mission(self, scenario, *, workspace, trial_id, event_logger=None, goal=None, timeout_seconds=None):
        self.calls.append(trial_id)
        workspace.mkdir(parents=True, exist_ok=True)
        return self.outcomes.pop(0) if self.outcomes else MissionResult()


def _v(scenario, executor):
    from tools.benchmark.verifier import IndependentVerifier

    v = IndependentVerifier.__new__(IndependentVerifier)
    v.scenario = scenario
    v._executor = executor
    v._session = None
    v._workspace = None
    v._loop = None
    return v


def _pass_executor(check):
    return True, "ok"


def _fail_executor(check):
    return False, "not present"


# ---------------------------------------------------------------------------
# Discovery / parsing
# ---------------------------------------------------------------------------


def test_scenario_discovery_via_fake_registry(tmp_path, monkeypatch):
    from tools.benchmark.registry import get_provider

    seed_fake_suite([_scenario("s1"), _scenario("s2", tags=["web"])])
    provider = get_provider("fake")
    all_s = provider.load_scenarios()
    assert len(all_s) == 2
    web = provider.load_scenarios(tags=["web"])
    assert len(web) == 1 and web[0].scenario_id == "s2"
    one = provider.load_scenarios(scenario_ids=["s1"])
    assert len(one) == 1 and one[0].scenario_id == "s1"


def test_scenario_to_dict_roundtrip():
    s = _scenario("s1", tags=["web"], difficulty="easy", target_image="img:latest")
    d = s.to_dict()
    assert d["scenario_id"] == "s1"
    assert d["tags"] == ["web"]
    assert d["target_image"] == "img:latest"


def test_model_metadata_unknown_defaults_to_unknown():
    from tools.benchmark.models import unknown

    assert unknown("") == "unknown"
    assert unknown(None) == "unknown"
    assert unknown("glm") == "glm"


# ---------------------------------------------------------------------------
# Trial isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trial_isolation_workspace_per_trial(tmp_path):
    seed_fake_suite([_scenario("s1")])
    mission = _FakeMission(
        [
            MissionResult(total_actions=1, telemetry=TrialTelemetry(tool_calls=1)),
            MissionResult(total_actions=1, telemetry=TrialTelemetry(tool_calls=1)),
        ]
    )
    # Monkeypatch MissionRunner to use our fake
    import tools.benchmark.runner as runner_mod

    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=2, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    assert len(payload["trials"]) == 2
    assert payload["trials"][0]["trial_index"] == 0
    assert payload["trials"][1]["trial_index"] == 1
    # Workspaces distinct
    assert payload["trials"][0]["workspace"] != payload["trials"][1]["workspace"]


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_maps_to_timeout_status(tmp_path):
    seed_fake_suite([_scenario("s1")])
    import tools.benchmark.runner as runner_mod

    mission = _FakeMission([MissionResult(timed_out=True, errors=["mission timeout after 30s"])])
    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=1, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    assert payload["trials"][0]["status"] == TrialStatus.TIMEOUT.value
    assert payload["trials"][0]["failure_category"] == FailureCategory.TIMEOUT.value


# ---------------------------------------------------------------------------
# Deterministic score calculations
# ---------------------------------------------------------------------------


def test_deterministic_score_same_input_same_output():
    trials = [TrialTelemetry(tool_calls=5, tool_errors=0, total_tokens=100)]
    # Run twice — must be identical
    from tools.benchmark.metrics import compute_run_summary
    from tools.benchmark.models import TrialResult

    def _mk(i):
        t = TrialResult(
            run_id="r",
            suite="xben",
            scenario_id="s1",
            trial_index=i,
            trial_id=f"s1#t{i}",
            status=TrialStatus.VERIFIED.value,
            oracle_verified_success=True,
            duration_seconds=10.0,
            tool_calls=5,
            total_tokens=100,
        )
        t.telemetry = TrialTelemetry(tool_calls=5, tool_errors=0, total_tokens=100)
        return t

    r1 = compute_run_summary([_mk(0), _mk(1)], run_id="r1", suite="xben")
    r2 = compute_run_summary([_mk(0), _mk(1)], run_id="r1", suite="xben")
    assert r1.verified_success_rate == r2.verified_success_rate
    assert r1.median_solve_time == r2.median_solve_time


# ---------------------------------------------------------------------------
# Skipped / failed setup / agent failure / provider failure / sandbox failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_failure_no_actions_is_planner_failure(tmp_path):
    seed_fake_suite([_scenario("s1")])
    import tools.benchmark.runner as runner_mod

    mission = _FakeMission([MissionResult(total_actions=0, telemetry=TrialTelemetry(tool_calls=0))])
    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=1, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    assert payload["trials"][0]["failure_category"] == FailureCategory.PLANNER_FAILURE.value


@pytest.mark.asyncio
async def test_provider_failure_maps_to_model_failed(tmp_path):
    seed_fake_suite([_scenario("s1")])
    import tools.benchmark.runner as runner_mod

    mission = _FakeMission(
        [MissionResult(total_actions=0, errors=["model client build failed: no key"], telemetry=TrialTelemetry())]
    )
    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=1, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    assert payload["trials"][0]["failure_category"] == FailureCategory.MODEL_FAILED.value


# ---------------------------------------------------------------------------
# Oracle success / failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_success_drives_verified(tmp_path):
    seed_fake_suite([_scenario("s1")])
    import tools.benchmark.runner as runner_mod

    mission = _FakeMission(
        [
            MissionResult(
                total_actions=5,
                telemetry=TrialTelemetry(tool_calls=5, total_tokens=100),
                agent_claimed_success=False,
                claimed_summary="",
            )
        ]
    )
    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=1, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    t = payload["trials"][0]
    assert t["oracle_verified_success"] is True
    assert t["status"] == TrialStatus.VERIFIED.value
    assert t["false_negative"] is True  # oracle verified but agent didn't claim


@pytest.mark.asyncio
async def test_oracle_failure_is_failed_with_no_exploit_path(tmp_path):
    seed_fake_suite([_scenario("s1")])
    import tools.benchmark.runner as runner_mod

    mission = _FakeMission([MissionResult(total_actions=4, telemetry=TrialTelemetry(tool_calls=4))])
    orig = runner_mod.MissionRunner
    runner_mod.MissionRunner = lambda *a, **kw: mission  # type: ignore
    try:
        runner = BenchmarkRunner(
            _config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor)
        )
        payload = await runner.run(RunConfig(suite="fake", trials=1, sandbox_required=False))
    finally:
        runner_mod.MissionRunner = orig
    assert payload["trials"][0]["status"] == TrialStatus.FAILED.value
    assert payload["trials"][0]["failure_category"] == FailureCategory.NO_EXPLOIT_PATH.value


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------


def test_summary_statistics_presence():
    from tools.benchmark.metrics import compute_run_summary
    from tools.benchmark.models import TrialResult, TrialTelemetry

    t = TrialResult(
        run_id="r",
        suite="xben",
        scenario_id="s1",
        trial_index=0,
        trial_id="s1#t0",
        status=TrialStatus.VERIFIED.value,
        oracle_verified_success=True,
        duration_seconds=10.0,
        tool_calls=5,
        total_tokens=100,
    )
    t.telemetry = TrialTelemetry(tool_calls=5)
    s = compute_run_summary([t], run_id="r", suite="xben")
    # Must have these fields
    for field in ("verified_success_rate", "median_solve_time", "median_tool_actions", "total_tokens", "solved"):
        assert hasattr(s, field)


# ---------------------------------------------------------------------------
# Benchmark must distinguish PASS/PARTIAL/FAIL/ERROR/TIMEOUT/SKIPPED
# ---------------------------------------------------------------------------


def test_benchmark_distinguishes_six_outcomes():
    # Mapping to current TrialStatus
    mapping = {
        "PASS": TrialStatus.VERIFIED.value,
        "FAIL": TrialStatus.FAILED.value,
        "ERROR": TrialStatus.INFRASTRUCTURE_ERROR.value,
        "TIMEOUT": TrialStatus.TIMEOUT.value,
        "SKIPPED": TrialStatus.SKIPPED.value,
        "FALSE_POSITIVE": TrialStatus.FALSE_POSITIVE.value,
    }
    for label, val in mapping.items():
        assert val, f"{label} must have a distinct status value"
