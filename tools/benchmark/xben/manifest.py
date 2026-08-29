"""XBEN manifest parsing: challenge JSON -> BenchmarkScenario.

A manifest is one JSON object per challenge file (or a top-level list) with
XBEN-style metadata::

    {
      "benchmark_id": "xben-001",
      "name": "SQL Injection Login Bypass",
      "description": "...",
      "target_image": "ghcr.io/xben/xben-001:latest",
      "target_ports": [8080],
      "goal": "initial_access",
      "expected_flags": ["flag{...}"],
      "oracle": {"flags": [...], "host_owned_when": "any"},
      "tags": ["web", "sqli"],
      "difficulty": "easy",
      "reset_strategy": "recreate",
      "timeout": 1800
    }

The oracle schema is exactly the graded-eval oracle v2 flag schema, executed
by the same independent executors (:mod:`tools.eval_checks`). Parsing is
defensive: invalid manifests are reported, never half-accepted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.benchmark.models import BenchmarkScenario

__all__ = ["ManifestError", "parse_manifest", "load_manifest_file"]


class ManifestError(ValueError):
    """A manifest is missing required fields or has invalid values."""


_REQUIRED = ("benchmark_id",)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def parse_manifest(data: dict[str, Any], *, suite: str = "xben", source: str = "") -> BenchmarkScenario:
    """Validate + convert one manifest dict into a BenchmarkScenario."""
    if not isinstance(data, dict):
        raise ManifestError(f"manifest {source!r}: expected a JSON object")
    for key in _REQUIRED:
        if not str(data.get(key, "") or "").strip():
            raise ManifestError(f"manifest {source!r}: missing required field {key!r}")
    scenario_id = str(data["benchmark_id"]).strip()
    oracle = data.get("oracle")
    if not isinstance(oracle, dict) or not (oracle.get("flags") or []):
        raise ManifestError(
            f"manifest {source!r}: oracle.flags must declare at least one independent check "
            "(agent claims never decide success)"
        )
    flags = [f for f in oracle.get("flags", []) if isinstance(f, dict)]
    if not flags:
        raise ManifestError(f"manifest {source!r}: oracle.flags contains no valid check objects")
    timeout = data.get("timeout", data.get("timeout_seconds", 1800))
    try:
        timeout_seconds = int(timeout)
    except (TypeError, ValueError):
        timeout_seconds = 1800
    ports: list[int] = []
    for p in _as_list(data.get("target_ports")):
        try:
            ports.append(int(p))
        except (TypeError, ValueError):
            continue
    return BenchmarkScenario(
        suite=suite,
        scenario_id=scenario_id,
        name=str(data.get("name", "") or scenario_id),
        description=str(data.get("description", "") or ""),
        target_type=str(data.get("target_type", "docker") or "docker"),
        target_image=str(data.get("target_image", "") or ""),
        target_host=str(data.get("target_host", "127.0.0.1") or "127.0.0.1"),
        target_ports=ports,
        goal=str(data.get("goal", "initial_access") or "initial_access"),
        expected_flags=_as_list(data.get("expected_flags")),
        oracle={"flags": flags, "host_owned_when": oracle.get("host_owned_when", "any")},
        tags=_as_list(data.get("tags")),
        difficulty=str(data.get("difficulty", "unknown") or "unknown"),
        reset_strategy=str(data.get("reset_strategy", "recreate") or "recreate"),
        timeout_seconds=timeout_seconds,
        source_manifest=source,
    )


def load_manifest_file(path: Path | str, *, suite: str = "xben") -> list[BenchmarkScenario]:
    """Load one manifest file (a single object or a top-level list of them)."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    entries = data if isinstance(data, list) else [data]
    return [parse_manifest(entry, suite=suite, source=str(path)) for entry in entries]
