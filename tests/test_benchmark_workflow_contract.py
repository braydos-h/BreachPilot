"""Hermetic regression coverage for the scheduled live benchmark workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.benchmark.skip import write_skipped_benchmark_report
from tools.benchmark.targets import TargetManager

REPO = Path(__file__).resolve().parent.parent


def _workflow() -> dict[str, Any]:
    payload = yaml.load((REPO / ".github/workflows/benchmark.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict)
    return payload


def _step(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(step for step in steps if step.get("name") == name)


def test_missing_provider_key_writes_skipped_artifact_without_provisioning(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)

    def fail_if_target_is_started(*args, **kwargs):
        raise AssertionError("a skipped benchmark must not provision a target")

    monkeypatch.setattr(TargetManager, "provision", fail_if_target_is_started)
    reason = "OPENCODE_GO_API_KEY is not configured; live benchmark was not run."
    config = {
        "models": {
            "provider": "opencode_go",
            "default_alias": "glm",
            "registry": {"glm": "glm-5.2:cloud"},
        },
        "providers": {"opencode_go": {"api_key_env": "OPENCODE_GO_API_KEY"}},
        "benchmark": {"output_dir": str(tmp_path / "benchmarks")},
        "sandbox": {"enabled": True},
    }

    run_dir = write_skipped_benchmark_report(
        config,
        suite="xben",
        trials=5,
        reason=reason,
        scenario_ids=["scenario-one"],
        run_id="provider-key-missing",
    )

    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert run["status"] == "SKIPPED"
    assert run["skip_reason"] == reason
    assert run["trials"] == []
    assert run["scenario_ids"] == ["scenario-one"]
    assert run["environment"]["model_provider"] == "opencode_go"
    assert summary["status"] == "SKIPPED"
    assert summary["skip_reason"] == reason
    assert summary["trials_total"] == summary["trials_completed"] == 0
    assert "No model requests" in (run_dir / "report.md").read_text(encoding="utf-8")
    assert "No target containers were started" in (run_dir / "report.md").read_text(encoding="utf-8")
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    skipped = next(event for event in events if event["type"] == "run_skipped")
    assert skipped["payload"]["targets_started"] == 0
    assert not any(event["type"] == "target_ready" for event in events)
    index = json.loads((tmp_path / "benchmarks" / "xben" / "runs_index.json").read_text(encoding="utf-8"))
    assert index[0]["status"] == "SKIPPED"


def test_skipped_report_refuses_to_hide_an_available_provider_key(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-only-value")
    config = {
        "models": {"provider": "opencode_go"},
        "providers": {"opencode_go": {"api_key_env": "OPENCODE_GO_API_KEY"}},
    }

    with pytest.raises(ValueError, match="refusing to write a missing-key skip report"):
        write_skipped_benchmark_report(
            config,
            suite="xben",
            trials=5,
            reason="missing key",
            output_dir=tmp_path,
            scenario_ids=["scenario-one"],
            run_id="must-not-exist",
        )
    assert not (tmp_path / "xben" / "must-not-exist").exists()


def test_live_benchmark_workflow_skips_before_target_start_and_uses_scoped_provider() -> None:
    workflow = _workflow()
    assert workflow["on"]["schedule"] == [{"cron": "17 3 * * *"}]
    job = workflow["jobs"]["nightly-live-benchmark"]
    assert job["if"] == (
        "github.ref == 'refs/heads/main' && "
        "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')"
    )
    steps = job["steps"]
    provider_check = _step(steps, "Check OpenCode Go provider key")
    skipped = _step(steps, "Write SKIPPED report when provider key is missing")
    prepare_config = _step(steps, "Prepare contained local-lab config")
    start_targets = _step(steps, "Start eval target suite (loopback only)")
    run_benchmark = _step(steps, "Run benchmark suite")
    stop_targets = _step(steps, "Stop target suite")
    upload = _step(steps, "Upload benchmark reports")

    assert steps.index(provider_check) < steps.index(skipped) < steps.index(prepare_config) < steps.index(start_targets)
    assert provider_check["env"]["OPENCODE_GO_API_KEY"] == "${{ secrets.OPENCODE_GO_API_KEY }}"
    assert skipped["if"] == "steps.provider-key.outputs.available == 'false'"
    assert "tools.benchmark.skip" in skipped["run"]
    assert start_targets["if"] == "steps.provider-key.outputs.available == 'true'"
    assert prepare_config["if"] == "steps.provider-key.outputs.available == 'true'"
    assert "prepare_ci_lab_config.py" in prepare_config["run"]
    assert run_benchmark["if"] == "steps.provider-key.outputs.available == 'true'"
    assert "--config reports/ci-local-lab.yaml" in run_benchmark["run"]
    assert stop_targets["if"] == "always() && steps.provider-key.outputs.available == 'true'"
    assert run_benchmark["env"]["OPENCODE_GO_API_KEY"] == "${{ secrets.OPENCODE_GO_API_KEY }}"
    assert job["env"]["EXPLOIT_ALLOWED_TARGETS"] == "127.0.0.1"
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "reports/benchmarks/"

    config = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    assert config["models"]["provider"] == "opencode_go"
    assert config["providers"]["opencode_go"]["api_key_env"] == "OPENCODE_GO_API_KEY"
