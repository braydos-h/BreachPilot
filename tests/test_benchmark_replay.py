from __future__ import annotations

from tools.benchmark.models import RunConfig, RunEnvironment
from tools.benchmark.replay import REPLAY_PIN_FIELDS, build_replay_manifest, check_reproducibility


def _manifest(target_images: dict[str, str]) -> dict[str, object]:
    pins: dict[str, object] = {name: "fixed" for name in REPLAY_PIN_FIELDS}
    pins["git_dirty"] = False
    pins["target_images"] = target_images
    return pins


def test_replay_requires_matching_immutable_target_image_digests():
    target_images = {"scenario-a": "sha256:" + "a" * 64}

    result = check_reproducibility(_manifest(target_images), _manifest(dict(target_images)))

    assert result["pinned"]["target_images"]["status"] == "match"
    assert result["reproducible"] is True


def test_replay_reports_missing_or_mutable_target_image_pins_as_unknown():
    cases = [
        ({}, {}),
        ({"scenario-a": "unknown"}, {"scenario-a": "unknown"}),
        ({"scenario-a": "breachpilot-target:latest"}, {"scenario-a": "breachpilot-target:latest"}),
        ({"scenario-a": "sha256:short"}, {"scenario-a": "sha256:short"}),
    ]

    for recorded, current in cases:
        result = check_reproducibility(_manifest(recorded), _manifest(current))
        assert result["pinned"]["target_images"]["status"] == "unknown"
        assert result["reproducible"] is False


def test_replay_rejects_different_or_incomplete_scenario_image_maps():
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    cases = [
        ({"scenario-a": digest_a}, {"scenario-a": digest_b}),
        ({"scenario-a": digest_a, "scenario-b": digest_b}, {"scenario-a": digest_a}),
    ]

    for recorded, current in cases:
        result = check_reproducibility(_manifest(recorded), _manifest(current))
        assert result["pinned"]["target_images"]["status"] == "mismatch"
        assert result["reproducible"] is False


def test_replay_manifest_uses_environment_image_pins_by_default():
    digest = "sha256:" + "c" * 64
    config = RunConfig(suite="xben", scenario_ids=["scenario-a"])
    environment = RunEnvironment(target_images={"scenario-a": digest})

    manifest = build_replay_manifest("run-1", "xben", config, environment)

    assert manifest["target_images"] == {"scenario-a": digest}
