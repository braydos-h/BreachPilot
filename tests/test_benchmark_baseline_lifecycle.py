"""Regression-gate lifecycle and shared baseline-path contracts."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from tools.benchmark import BenchmarkScenario, seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, TrialTelemetry
from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import RunConfig, RunEnvironment, TargetSnapshot, TrialResult, TrialStatus
from tools.benchmark.paths import DEFAULT_BASELINE_PATH, resolve_baseline_path
from tools.benchmark.regression import compare_to_baseline, load_baseline, save_baseline
from tools.benchmark.runner import BenchmarkRunner
from tools.benchmark.storage import BenchmarkStorage


def _scenario() -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id="s1",
        name="Scenario s1",
        target_type="host",
        target_host="127.0.0.1",
        tags=["web"],
        oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
    )


def _verified_summary(run_id: str, *, verified: bool = True):
    trial = TrialResult(
        run_id=run_id,
        suite="fake",
        scenario_id="s1",
        trial_index=0,
        trial_id=f"{run_id}#s1#t0",
        status=TrialStatus.VERIFIED.value if verified else TrialStatus.FALSE_POSITIVE.value,
        agent_claimed_success=True,
        oracle_verified_success=verified,
        duration_seconds=60.0,
        tool_calls=1,
    )
    return compute_run_summary([trial], run_id=run_id, suite="fake")


def _verifier(scenario: Any, *, verified: bool):
    from tools.benchmark.verifier import IndependentVerifier

    verifier = IndependentVerifier.__new__(IndependentVerifier)
    verifier.scenario = scenario
    verifier._executor = lambda _check: (verified, "fixture")
    verifier._session = None
    verifier._workspace = None
    verifier._loop = None
    return verifier


def _config(tmp_path: Path, *, baseline_path: str = "gates/baseline.json") -> dict[str, Any]:
    return {
        "benchmark": {
            "output_dir": str(tmp_path / "bench"),
            "baseline_path": baseline_path,
            "sandbox_required": False,
        },
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
        "sandbox": {"enabled": False},
    }


def test_default_and_custom_relative_paths_share_storage_root(tmp_path):
    root = tmp_path / "bench"
    assert resolve_baseline_path(DEFAULT_BASELINE_PATH, root) == (root / "baseline.json").absolute()
    assert resolve_baseline_path("gates/baseline.json", root) == (root / "gates" / "baseline.json").absolute()


def test_combined_regression_check_advances_baseline_only_after_pass(tmp_path, monkeypatch):
    scenario = _scenario()
    seed_fake_suite([scenario])
    config = _config(tmp_path)
    storage = BenchmarkStorage(config["benchmark"]["output_dir"])
    baseline_path = resolve_baseline_path(config["benchmark"]["baseline_path"], storage.root)
    save_baseline(_verified_summary("baseline-run"), baseline_path)
    original = baseline_path.read_bytes()

    class _Mission:
        async def run_mission(self, *_args, **_kwargs):
            return MissionResult(
                agent_claimed_success=True,
                total_actions=4,
                telemetry=TrialTelemetry(tool_calls=4),
            )

    class _Targets:
        def provision(self, _scenario):
            return TargetSnapshot(host="127.0.0.1", reset_strategy="external-reset")

        def reset(self, _scenario):
            return TargetSnapshot(host="127.0.0.1", reset_strategy="external-reset")

        def destroy_all(self):
            return None

    monkeypatch.setattr("tools.benchmark.runner.MissionRunner", lambda *_args, **_kwargs: _Mission())
    runner = BenchmarkRunner(
        config,
        Path("config.yaml"),
        verifier_factory=lambda current: _verifier(current, verified=False),
        target_manager=_Targets(),
    )
    failed = asyncio.run(
        runner.run(
            RunConfig(
                suite="fake",
                scenario_ids=["s1"],
                trials=1,
                sandbox_required=False,
                check_regression=True,
                save_baseline=True,
            )
        )
    )
    assert failed["regression"]["passed"] is False
    assert baseline_path.read_bytes() == original
    assert load_baseline(baseline_path)["run_id"] == "baseline-run"

    runner = BenchmarkRunner(
        config,
        Path("config.yaml"),
        verifier_factory=lambda current: _verifier(current, verified=True),
        target_manager=_Targets(),
    )
    passed = asyncio.run(
        runner.run(
            RunConfig(
                suite="fake",
                scenario_ids=["s1"],
                trials=1,
                sandbox_required=False,
                check_regression=True,
                save_baseline=True,
            )
        )
    )
    assert passed["trials"][0]["status"] == TrialStatus.VERIFIED.value
    assert passed["regression"]["passed"] is True, passed["regression"]
    assert load_baseline(baseline_path)["run_id"] == passed["run_id"]


def test_missing_or_legacy_baseline_cannot_pass(tmp_path):
    current = _verified_summary("current-run")
    missing = compare_to_baseline(current, load_baseline(tmp_path / "missing.json"))
    assert missing.passed is False

    legacy = {
        "run_id": "legacy-run",
        "suite": "fake",
        "verified_success_rate": 1.0,
        "false_positive_rate": 0.0,
        "scenarios": {"s1": {"success_probability": 1.0, "verified": 1, "trials": 1}},
    }
    comparison = compare_to_baseline(current, legacy)
    assert comparison.passed is False
    assert comparison.incomparable_count > 0


def test_api_baseline_save_uses_same_relative_path_as_runner(tmp_path, monkeypatch):
    token = "test-token-0123456789abcdef01234567"
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    config = _config(tmp_path, baseline_path="api-gates/baseline.json")
    config["reports_dir"] = str(tmp_path / "reports")
    config["api"] = {"host": "127.0.0.1", "port": 8765}

    from app import create_app

    storage = BenchmarkStorage(config["benchmark"]["output_dir"])
    storage.init_run("fake", "api-run", RunConfig(suite="fake"), RunEnvironment(), ["s1"])
    trial = TrialResult(
        run_id="api-run",
        suite="fake",
        scenario_id="s1",
        trial_index=0,
        trial_id="api-run#s1#t0",
        status=TrialStatus.VERIFIED.value,
        agent_claimed_success=True,
        oracle_verified_success=True,
        duration_seconds=60.0,
    )
    summary = compute_run_summary([trial], run_id="api-run", suite="fake")
    storage.finalize_run(
        "fake",
        "api-run",
        status="completed",
        trials=[trial],
        summary=summary,
        config=RunConfig(suite="fake"),
        environment=RunEnvironment(),
        scenario_ids=["s1"],
    )

    client = TestClient(create_app(config=config))
    headers = {"Authorization": f"Bearer {token}"}
    expected = resolve_baseline_path(config["benchmark"]["baseline_path"], storage.root)
    runner_path = resolve_baseline_path(config["benchmark"]["baseline_path"], BenchmarkStorage(storage.root).root)
    assert runner_path == expected
    response = client.post("/api/v1/benchmarks/baseline", headers=headers, json={"run_id": "api-run"})
    assert response.status_code == 200, response.text
    assert Path(response.json()["path"]) == expected
    assert expected.is_file()
