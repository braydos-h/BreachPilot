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
from collections.abc import Mapping
from typing import Any

from tools.benchmark.models import RunConfig, RunEnvironment

__all__ = ["REPLAY_PIN_FIELDS", "build_replay_manifest", "check_reproducibility"]

#: Fields a stored run must pin (or record unknown) to be reproducible.
REPLAY_PIN_FIELDS = (
    "suite",
    "scenario_ids",
    "tags",
    "trials",
    "timeout_seconds",
    "breachpilot_version",
    "git_sha",
    "git_dirty",
    "model_provider",
    "model_alias",
    "model_id",
    "model_version",
    "reasoning_config",
    "temperature",
    "config_hash",
    "benchmark_config_hash",
    "sandbox_image",
    "sandbox_image_digest",
    "sandbox_enabled",
    "sandbox_required",
    "target_images",
    "platform",
    "python_version",
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
        "scenario_ids": list(config.scenario_ids),
        "tags": list(config.tags),
        "trials": config.trials,
        "timeout_seconds": config.timeout_seconds,
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
        "sandbox_required": env.get("sandbox_required"),
        "target_images": dict(target_images or {}),
        "platform": env.get("platform"),
        "python_version": env.get("python_version"),
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
    parts += ["--timeout-seconds", str(config.timeout_seconds)]
    if config.model_alias:
        parts += ["--model", config.model_alias]
    return " ".join(parts)


def check_reproducibility(manifest: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare a stored manifest against a complete environment and run-shape dict.

    Returns a per-field match report: ``match`` | ``mismatch`` | ``unknown``.
    Unknown fields (either side) are honest gaps, never treated as matches.
    """
    report: dict[str, Any] = {"pinned": {}, "reproducible": False}
    all_match = True
    for field_name in REPLAY_PIN_FIELDS:
        recorded = manifest.get(field_name)
        now = current.get(field_name)
        if _pin_is_unknown(field_name, recorded) or _pin_is_unknown(field_name, now):
            status = "unknown"
        elif field_name == "git_dirty" and (recorded is True or now is True):
            # The boolean says that uncommitted changes existed, but does not
            # identify their contents. Matching dirty flags are not a code pin.
            status = "unknown" if recorded == now else "mismatch"
        else:
            status = "match" if recorded == now else "mismatch"
        if status != "match":
            all_match = False
        pin: dict[str, Any] = {"recorded": recorded, "current": now, "status": status}
        if field_name == "git_dirty" and (recorded is True or now is True):
            pin["detail"] = "uncommitted source contents are not pinned"
        report["pinned"][field_name] = pin
    # A reproducibility claim requires every documented pin to be present and
    # equal. Matching just a subset is never enough to compensate for unknowns.
    report["reproducible"] = all_match and bool(REPLAY_PIN_FIELDS)
    return report


def _pin_is_unknown(field_name: str, value: Any) -> bool:
    """Whether a required reproduction pin is absent or only partly known."""
    if value is None:
        return True
    if field_name == "sandbox_image_digest":
        return not isinstance(value, str) or re.fullmatch(r"(?:.+@)?sha256:[0-9a-f]{64}", value.strip().lower()) is None
    if isinstance(value, str):
        return value.strip().lower() in {"", "unknown"}
    if field_name == "git_dirty":
        return not isinstance(value, bool)
    if field_name == "target_images":
        return (
            not isinstance(value, Mapping)
            or not value
            or any(not isinstance(image, str) or not _has_immutable_image_digest(image) for image in value.values())
        )
    if field_name == "reasoning_config":
        return not isinstance(value, Mapping)
    if field_name == "trials":
        return type(value) is not int or value < 1
    if field_name in {"scenario_ids", "tags"}:
        return not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value)
    return False


def _has_immutable_image_digest(image: str) -> bool:
    """A mutable tag is metadata, not a reproducible target-image pin."""
    return re.fullmatch(r"(?:.+@)?sha256:[0-9a-f]{64}", image.strip().lower()) is not None
