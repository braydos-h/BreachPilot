"""Honest replay-pin comparison tests."""

from __future__ import annotations

from copy import deepcopy

from tools.benchmark.models import BenchmarkScenario, TargetSnapshot, TrialResult
from tools.benchmark.replay import REPLAY_PIN_FIELDS, check_reproducibility
from tools.benchmark.runner import _observed_target_image_pins


def _complete_pins() -> dict[str, object]:
    return {
        "suite": "xben",
        "scenario_ids": ["scenario-1"],
        "tags": ["web"],
        "trials": 1,
        "timeout_seconds": 1800,
        "breachpilot_version": "0.70.0",
        "git_sha": "abc123",
        "git_dirty": False,
        "model_provider": "ollama",
        "model_alias": "glm",
        "model_id": "glm-5.2:cloud",
        "model_version": "cloud",
        "reasoning_config": {},
        "temperature": 0.2,
        "config_hash": "config-hash",
        "benchmark_config_hash": "benchmark-hash",
        "sandbox_image": "breachpilot-sandbox:latest",
        "sandbox_image_digest": f"sha256:{'c' * 64}",
        "sandbox_enabled": True,
        "sandbox_required": True,
        "target_images": {"scenario-1": f"lab@sha256:{'a' * 64}"},
        "platform": "Linux/test",
        "python_version": "3.12.0",
    }


def test_reproducibility_requires_every_documented_pin() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is True
    assert set(result["pinned"]) == set(REPLAY_PIN_FIELDS)
    assert all(pin["status"] == "match" for pin in result["pinned"].values())


def test_missing_or_unknown_pin_cannot_be_offset_by_matching_fields() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)
    recorded.pop("model_version")
    current["sandbox_image_digest"] = "unknown"

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is False
    assert result["pinned"]["model_version"]["status"] == "unknown"
    assert result["pinned"]["sandbox_image_digest"]["status"] == "unknown"
    assert all(
        pin["status"] == "match"
        for name, pin in result["pinned"].items()
        if name not in {"model_version", "sandbox_image_digest"}
    )


def test_run_shape_and_malformed_sandbox_digest_cannot_claim_reproducibility() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)
    current["scenario_ids"] = ["different-scenario"]
    current["sandbox_image_digest"] = "sha256:short"

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is False
    assert result["pinned"]["scenario_ids"]["status"] == "mismatch"
    assert result["pinned"]["sandbox_image_digest"]["status"] == "unknown"


def test_registry_repo_digest_is_a_valid_sandbox_image_pin() -> None:
    digest = f"sha256:{'d' * 64}"
    recorded = _complete_pins()
    current = deepcopy(recorded)
    recorded["sandbox_image_digest"] = f"ghcr.io/example/sandbox@{digest}"
    current["sandbox_image_digest"] = f"ghcr.io/example/sandbox@{digest}"

    result = check_reproducibility(recorded, current)

    assert result["pinned"]["sandbox_image_digest"]["status"] == "match"


def test_dirty_source_trees_are_not_exact_code_pins() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)
    recorded["git_dirty"] = True
    current["git_dirty"] = True

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is False
    assert result["pinned"]["git_dirty"]["status"] == "unknown"
    assert "contents are not pinned" in result["pinned"]["git_dirty"]["detail"]


def test_unknown_scenario_image_inside_target_pins_is_not_a_match() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)
    recorded["target_images"] = {"scenario-1": "unknown"}
    current["target_images"] = {"scenario-1": "unknown"}

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is False
    assert result["pinned"]["target_images"]["status"] == "unknown"


def test_mutable_target_image_tag_is_not_an_immutable_pin() -> None:
    recorded = _complete_pins()
    current = deepcopy(recorded)
    recorded["target_images"] = {"scenario-1": "lab:latest"}
    current["target_images"] = {"scenario-1": "lab:latest"}

    result = check_reproducibility(recorded, current)

    assert result["reproducible"] is False
    assert result["pinned"]["target_images"]["status"] == "unknown"


def test_runner_manifest_uses_only_complete_observed_target_image_ids() -> None:
    scenarios = [
        BenchmarkScenario(suite="fake", scenario_id="pinned"),
        BenchmarkScenario(suite="fake", scenario_id="missing"),
    ]
    digest = f"sha256:{'b' * 64}"
    trials = [
        TrialResult(scenario_id="pinned", trial_index=index, target=TargetSnapshot(image_digest=digest))
        for index in range(2)
    ]
    trials.append(TrialResult(scenario_id="missing", trial_index=0, target=TargetSnapshot()))

    pins = _observed_target_image_pins(scenarios, trials, expected_trials=2)

    assert pins == {"pinned": digest, "missing": "unknown"}
