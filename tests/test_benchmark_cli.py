"""Tests for the benchmark CLI (tools/benchmark_cli.py) and service (API layer)."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import pytest

from tools.benchmark import seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, TrialTelemetry
from tools.benchmark.models import BenchmarkScenario, RunConfig
from tools.benchmark.service import BenchmarkService
from tools.benchmark_cli import run_benchmark_cli


def _scenario(scenario_id: str = "s1", *, tags: list[str] | None = None) -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        tags=tags or ["web"],
        oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
    )


def _config(tmp_path: Path) -> dict[str, Any]:
    return {
        "benchmark": {"output_dir": str(tmp_path / "bench"), "sandbox_required": False, "trials": 1},
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
    }


def _args(**kw) -> argparse.Namespace:
    defaults = {
        "config": Path("config.yaml"),
        "benchmark": ["fake"],
        "benchmark_list": False,
        "scenario": None,
        "tag": None,
        "trials": None,
        "timeout_seconds": None,
        "save_baseline": False,
        "check_regression": False,
    }
    defaults.update(kw)
    return argparse.Namespace(**defaults)


@pytest.fixture
def fake_suite():
    seed_fake_suite([_scenario("s1"), _scenario("s2", tags=["crypto"])])


def _patch_runner(monkeypatch, tmp_path, mission_outcomes):
    """Patch the CLI's BenchmarkRunner to a deterministic fake-mission runner."""
    from tools.benchmark.runner import BenchmarkRunner as _Real

    class _PatchedRunner(_Real):
        def __init__(self, config, config_path, **kw):
            super().__init__(config, config_path, **kw)

        async def run(self, run_config, **kw):  # type: ignore[override]
            from tools.benchmark.metrics import compute_run_summary
            from tools.benchmark.models import TrialResult, TrialStatus
            from tools.benchmark.regression import (
                compare_to_baseline,
                load_baseline,
                thresholds_from_config,
            )

            trials = []
            for i in range(run_config.trials):
                outcome = mission_outcomes[min(i, len(mission_outcomes) - 1)]
                trials.append(
                    TrialResult(
                        run_id="r1",
                        suite=run_config.suite,
                        scenario_id="s1",
                        trial_index=i,
                        trial_id=f"s1#t{i}",
                        status=TrialStatus.VERIFIED.value
                        if outcome.agent_claimed_success
                        else TrialStatus.FAILED.value,
                        oracle_verified_success=outcome.agent_claimed_success,
                        agent_claimed_success=outcome.agent_claimed_success,
                        tool_calls=outcome.telemetry.tool_calls,
                        duration_seconds=60.0,
                    )
                )
            summary = compute_run_summary(trials, run_id="r1", suite=run_config.suite)
            regression = None
            if run_config.check_regression:
                benchmark_cfg = (self.config or {}).get("benchmark", {}) or {}
                baseline_path = benchmark_cfg.get("baseline_path", "reports/benchmarks/baseline.json")
                result = compare_to_baseline(summary, load_baseline(baseline_path), thresholds_from_config(self.config))
                regression = result.to_dict()
            return {
                "run_id": "r1",
                "suite": run_config.suite,
                "status": "completed",
                "run_dir": str(tmp_path / "bench" / "fake" / "r1"),
                "report_markdown": "x.md",
                "report_html": "x.html",
                "summary": summary.to_dict(),
                "trials": [t.to_dict() for t in trials],
                "regression": regression,
            }

    monkeypatch.setattr("tools.benchmark_cli.BenchmarkRunner", _PatchedRunner)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_benchmark_list(fake_suite, capsys):
    from tools.benchmark_cli import _print_suite_list

    rc = _print_suite_list()
    assert rc == 0
    out = capsys.readouterr().out
    assert "fake" in out
    assert "s1" in out


def test_cli_run_benchmark(tmp_path, monkeypatch, fake_suite, capsys):
    _patch_runner(
        monkeypatch,
        tmp_path,
        [MissionResult(agent_claimed_success=True, telemetry=TrialTelemetry(tool_calls=1))],
    )
    rc = run_benchmark_cli(_args(trials=2))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Verified:" in out
    assert "100.0%" in out or "100%" in out


def test_cli_renders_unavailable_rates_for_only_infra_and_skipped_trials(tmp_path, monkeypatch, fake_suite, capsys):
    import yaml

    from tools.benchmark.metrics import compute_run_summary
    from tools.benchmark.models import TrialResult, TrialStatus

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(_config(tmp_path)), encoding="utf-8")

    class _Runner:
        def __init__(self, config, path):
            pass

        async def run(self, run_config, **kwargs):
            trials = [
                TrialResult(
                    run_id="r-empty",
                    suite="fake",
                    scenario_id="s1",
                    status=TrialStatus.INFRASTRUCTURE_ERROR.value,
                ),
                TrialResult(
                    run_id="r-empty",
                    suite="fake",
                    scenario_id="s1",
                    status=TrialStatus.SKIPPED.value,
                ),
            ]
            summary = compute_run_summary(trials, run_id="r-empty", suite="fake")
            return {
                "run_id": "r-empty",
                "summary": summary.to_dict(),
                "report_markdown": "report.md",
                "regression": None,
            }

    monkeypatch.setattr("tools.benchmark_cli.BenchmarkRunner", _Runner)

    rc = run_benchmark_cli(_args(config=config_path, trials=2))

    assert rc == 0
    output = capsys.readouterr().out
    assert "Verified: 0/0 completed (n/a); 2 total trials" in output
    assert "False positives: n/a" in output


def test_cli_run_benchmark_invalid_config(tmp_path, monkeypatch, fake_suite):
    """A broken config file is a usage error (exit 2), never a hang."""
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("benchmark: [unclosed\n  broken", encoding="utf-8")
    rc = run_benchmark_cli(_args(config=config_path))
    assert rc == 2


def test_cli_trials_out_of_range(fake_suite):
    rc = run_benchmark_cli(_args(trials=99))
    assert rc == 2


def test_cli_timeout_below_supported_minimum_is_usage_error(fake_suite):
    rc = run_benchmark_cli(_args(timeout_seconds=29))
    assert rc == 2


def test_cli_hard_regression_exit_code(tmp_path, monkeypatch, fake_suite, capsys):
    """--check-regression against a stronger baseline must exit non-zero."""
    _patch_runner(monkeypatch, tmp_path, [MissionResult(agent_claimed_success=False)])
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        '{"run_id": "b0", "suite": "fake", "trials_total": 10, "verified_success_rate": 0.9, '
        '"false_positive_rate": 0.0, "median_solve_time": null, "median_tool_actions": null, '
        '"estimated_cost": null, "scenarios": {"s1": {"success_probability": 1.0, "verified": 1, '
        '"trials": 1, "trials_completed": 1}}}',
        encoding="utf-8",
    )
    config = _config(tmp_path)
    config["benchmark"]["baseline_path"] = str(baseline_path)
    config_path = tmp_path / "config.yaml"
    import json as _json

    config_path.write_text(_json.dumps(config), encoding="utf-8")

    # load_validated_config expects YAML; feed a YAML-shaped config instead.
    config_path.write_text(
        "benchmark:\n"
        f"  output_dir: {str(tmp_path / 'bench')}\n"
        "  sandbox_required: false\n"
        "  trials: 1\n"
        f"  baseline_path: {baseline_path}\n"
        "models:\n  default_alias: glm\n"
        "mcp:\n  http_port: 8001\n",
        encoding="utf-8",
    )
    args = _args(config=config_path, check_regression=True)
    rc = run_benchmark_cli(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "REGRESSION" in out


# ---------------------------------------------------------------------------
# Service (API layer)
# ---------------------------------------------------------------------------


def test_service_start_and_status(tmp_path, monkeypatch):
    seed_fake_suite([_scenario("s1")])
    config = _config(tmp_path)

    class _FakeRunner:
        def __init__(self, config, config_path, **kw):
            pass

        async def run(self, run_config, cancel=None, progress=None):
            if progress is not None:
                progress({"type": "trial_start", "run_id": "fake-run-1", "scenario_id": "s1", "trial": 1, "trials": 1})
                progress({"type": "trial_start", "run_id": "fake-run-1", "scenario_id": "s1", "trial": 1, "trials": 1})
            return {
                "run_id": "fake-run-1",
                "suite": run_config.suite,
                "status": "completed",
                "summary": {"solved": 1},
            }

    monkeypatch.setattr("tools.benchmark.service.BenchmarkRunner", _FakeRunner)
    service = BenchmarkService(config, Path("config.yaml"))

    async def start_and_drain():
        result = await service.start_run({"suite": "fake"})
        task = service._active_task
        if task is not None:
            await task
        return result

    result = asyncio.run(start_and_drain())
    assert "error" not in result
    assert result["run_id"] == "fake-run-1"
    assert service.status()["state"] == "completed"


def test_service_rejects_concurrent_run(tmp_path, monkeypatch):
    seed_fake_suite([_scenario("s1")])
    config = _config(tmp_path)

    class _SlowRunner:
        def __init__(self, config, config_path, **kw):
            pass

        async def run(self, run_config, cancel=None, progress=None):
            await asyncio.sleep(10)
            return {"run_id": "slow", "suite": run_config.suite, "status": "completed", "summary": {}}

    monkeypatch.setattr("tools.benchmark.service.BenchmarkRunner", _SlowRunner)
    service = BenchmarkService(config, Path("config.yaml"))
    loop = asyncio.new_event_loop()
    try:
        first = loop.run_until_complete(service.start_run({"suite": "fake"}))
        assert "error" not in first
        second = loop.run_until_complete(service.start_run({"suite": "fake"}))
        assert "error" in second
    finally:
        loop.run_until_complete(service.shutdown())
        loop.close()


def test_service_run_config_from_request(tmp_path, monkeypatch):
    captured: dict[str, Any] = {}

    class _CaptureRunner:
        def __init__(self, config, config_path, **kw):
            captured["model_alias"] = kw.get("model_alias", "")

        async def run(self, run_config, cancel=None, progress=None):
            captured["run_config"] = run_config
            return {"run_id": "x", "suite": run_config.suite, "status": "completed", "summary": {}}

    monkeypatch.setattr("tools.benchmark.service.BenchmarkRunner", _CaptureRunner)
    service = BenchmarkService(_config(tmp_path), Path("config.yaml"))

    async def start_and_drain():
        result = await service.start_run(
            {
                "suite": "fake",
                "trials": 3,
                "model": "kimi",
                "tags": ["web"],
                "check_regression": True,
                "timeout_seconds": 321,
            }
        )
        task = service._active_task
        if task is not None:
            await task
        return result

    result = asyncio.run(start_and_drain())
    assert "error" not in result
    rc: RunConfig = captured["run_config"]
    assert rc.trials == 3
    assert rc.timeout_seconds == 321
    assert rc.model_alias == "kimi"
    assert rc.tags == ["web"]
    assert rc.check_regression is True
    assert captured["model_alias"] == "kimi"
