"""Deterministic mission replay support.

Every benchmark run stores a reproduction manifest (git SHA + dirty status,
model provider/id/version, reasoning config, temperature, config hash,
benchmark config hash, sandbox image + digest, target image per scenario).
:func:`build_replay_manifest` surfaces that manifest;
:func:`check_reproducibility` compares a stored run against the current
environment and reports which pins match — a run is only reproducible when
the recorded metadata pins it, and unknown metadata is reported as such.
"""

from __future__ import annotations

import re
from typing import Any

from tools.benchmark.models import RunConfig, RunEnvironment

__all__ = ["REPLAY_PIN_FIELDS", "build_replay_manifest", "check_reproducibility"]

_IMMUTABLE_IMAGE_PIN = re.compile(r"(?:[^@]+@)?sha256:[0-9a-f]{64}$")

#: Fields a stored run must pin (or record unknown) to be reproducible.
REPLAY_PIN_FIELDS = (
    "git_sha",
    "git_dirty",
    "model_provider",
    "model_alias",
    "model_id",
    "model_version",
    "config_hash",
    "benchmark_config_hash",
    "sandbox_image",
    "sandbox_image_digest",
    "target_images",
)


def build_replay_manifest(
    run_id: str,
    suite: str,
    config: RunConfig,
    environment: RunEnvironment,
    *,
    target_images: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The reproduction manifest stored inside run.json."""
    env = environment.to_dict()
    manifest: dict[str, Any] = {
        "run_id": run_id,
        "suite": suite,
        "breachpilot_version": env.get("breachpilot_version"),
        "git_sha": env.get("git_sha"),
        "git_dirty": env.get("git_dirty"),
        "git_branch": env.get("git_branch"),
        "model_provider": env.get("model_provider"),
        "model_alias": env.get("model_alias"),
        "model_id": env.get("model_id"),
        "model_version": env.get("model_version"),
        "reasoning_config": env.get("reasoning_config"),
        "temperature": env.get("temperature"),
        "config_hash": env.get("config_hash"),
        "benchmark_config_hash": env.get("benchmark_config_hash"),
        "sandbox_image": env.get("sandbox_image"),
        "sandbox_image_digest": env.get("sandbox_image_digest"),
        "sandbox_enabled": env.get("sandbox_enabled"),
        "target_images": dict(env.get("target_images", {}) if target_images is None else target_images),
        "trials": config.trials,
        "replay_command": _replay_command(suite, config),
    }
    return manifest


def _replay_command(suite: str, config: RunConfig) -> str:
    """The CLI command that reproduces this run's shape (not its randomness)."""
    parts = ["python main.py", "--benchmark", suite]
    for scenario_id in config.scenario_ids:
        parts += ["--scenario", scenario_id]
    for tag in config.tags:
        parts += ["--tag", tag]
    if config.trials != 1:
        parts += ["--trials", str(config.trials)]
    if config.model_alias:
        parts += ["--model", config.model_alias]
    return " ".join(parts)


def check_reproducibility(manifest: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare a stored manifest against a freshly collected environment dict.

    Returns a per-field match report: ``match`` | ``mismatch`` | ``unknown``.
    Unknown fields (either side) are honest gaps, never treated as matches.
    """
    report: dict[str, Any] = {"pinned": {}, "reproducible": False}
    all_match = True
    any_known = False
    for field_name in REPLAY_PIN_FIELDS:
        recorded = manifest.get(field_name)
        now = current.get(field_name)
        if field_name == "target_images":
            status = _compare_target_image_pins(recorded, now)
            report["pinned"][field_name] = {"recorded": recorded, "current": now, "status": status}
            if status != "match":
                all_match = False
            else:
                any_known = True
            continue
        if recorded in (None, "unknown") or now in (None, "unknown"):
            report["pinned"][field_name] = {"recorded": recorded, "current": now, "status": "unknown"}
            all_match = False
            continue
        any_known = True
        status = "match" if recorded == now else "mismatch"
        if status == "mismatch":
            all_match = False
        report["pinned"][field_name] = {"recorded": recorded, "current": now, "status": status}
    report["reproducible"] = all_match and any_known
    return report


def _compare_target_image_pins(recorded: Any, current: Any) -> str:
    """Compare complete per-scenario maps of immutable image digests."""
    for pins in (recorded, current):
        if not isinstance(pins, dict) or not pins:
            return "unknown"
        if any(
            not isinstance(scenario_id, str)
            or not scenario_id.strip()
            or not isinstance(pin, str)
            or _IMMUTABLE_IMAGE_PIN.fullmatch(pin.strip()) is None
            for scenario_id, pin in pins.items()
        ):
            return "unknown"
    if set(recorded) != set(current):
        return "mismatch"
    return "match" if recorded == current else "mismatch"
