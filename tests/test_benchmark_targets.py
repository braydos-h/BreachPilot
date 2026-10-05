"""Benchmark target reset contracts."""

from __future__ import annotations

import subprocess

import pytest

from tools.benchmark.models import BenchmarkScenario
from tools.benchmark.targets import TargetManager, TargetProvisionError


def _host_scenario(*, reset_strategy: str = "none") -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id="static-lab",
        target_type="host",
        target_host="127.0.0.1",
        reset_strategy=reset_strategy,
    )


def test_static_host_target_cannot_be_reset_between_trials() -> None:
    manager = TargetManager()
    scenario = _host_scenario()

    snapshot = manager.provision(scenario)

    assert snapshot.reset_strategy == "none"
    with pytest.raises(TargetProvisionError, match="cannot provide an independent repeated trial"):
        manager.reset(scenario)


def test_host_target_with_reset_request_fails_instead_of_reusing_state() -> None:
    manager = TargetManager()
    scenario = _host_scenario(reset_strategy="recreate")

    snapshot = manager.provision(scenario)

    assert snapshot.reset_strategy == "none"
    with pytest.raises(TargetProvisionError, match="host-managed targets cannot be reset automatically"):
        manager.reset(scenario)


def test_docker_target_with_no_reset_strategy_fails_before_reuse(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []
    image_id = f"sha256:{'a' * 64}"

    def fake_docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "inspect":
            return subprocess.CompletedProcess(["docker", *args], 0, stdout=f"{image_id}\n", stderr="")
        return subprocess.CompletedProcess(["docker", *args], 0, stdout="container-1\n", stderr="")

    manager = TargetManager(docker=fake_docker)
    scenario = BenchmarkScenario(
        suite="fake",
        scenario_id="stateful",
        target_type="docker",
        target_image="lab:latest",
        reset_strategy="none",
    )

    snapshot = manager.provision(scenario)
    assert snapshot.image_digest == image_id
    with pytest.raises(TargetProvisionError, match="cannot provide an independent repeated trial"):
        manager.reset(scenario)

    assert len(calls) == 2
    assert calls[0][0] == "run"
    assert calls[1] == ("inspect", "--format", "{{.Image}}", "container-1")
