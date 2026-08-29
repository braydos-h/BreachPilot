"""Environment capture for benchmark reproducibility.

Collects git SHA / dirty status, config hash, model metadata, and sandbox
image facts into a :class:`tools.benchmark.models.RunEnvironment`. Missing
metadata is recorded as ``"unknown"`` — never silently substituted — so a
stored run's reproducibility claim is always honest.

Subprocess seams (``_git``, ``_docker``) exist so tests monkeypatch them
instead of spawning real processes (same pattern as ``tools/snapshots.py``).
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.benchmark.models import RunEnvironment, unknown

__all__ = ["collect_environment", "config_hash", "resolve_model_metadata"]


def _git(*args: str, cwd: Path | str = ".") -> str:
    """Run one git command, returning stripped stdout (``""`` on any failure)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(cwd),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def config_hash(config: dict[str, Any] | None) -> str:
    """Stable short hash of the effective config (sorted keys, no secrets kept).

    Hashing only — the config itself is never copied into the run dir, so
    operator API keys in env-derived sections never leak into reports.
    """
    if not isinstance(config, dict):
        return "unknown"
    try:
        payload = json.dumps(config, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        return "unknown"
    return hashlib.sha256(payload).hexdigest()[:16]


def _docker(*args: str) -> str:
    """Run one docker command; returns stripped stdout (``""`` on failure)."""
    try:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def docker_image_digest(image: str) -> str:
    """Repo digest of a local docker image, or ``"unknown"``.

    ``docker image inspect`` returns ``RepoDigests`` entries like
    ``image@sha256:...``; when the image was built locally (never pushed) the
    list may be empty and we honestly report unknown.
    """
    if not image:
        return "unknown"
    out = _docker("image", "inspect", "--format", "{{json .RepoDigests}}", image)
    if not out:
        return "unknown"
    try:
        digests = json.loads(out)
    except json.JSONDecodeError:
        return "unknown"
    if isinstance(digests, list) and digests:
        return str(digests[0])
    # Fall back to the image ID (still pinned, just not a registry digest).
    image_id = _docker("image", "inspect", "--format", "{{.Id}}", image)
    return image_id or "unknown"


def resolve_model_metadata(config: dict[str, Any], model_alias: str) -> dict[str, str]:
    """Resolve provider/alias/model-id for the alias the run will actually use.

    Never guesses a substitute: when the alias/model id cannot be resolved the
    value stays ``"unknown"``. The caller passes the *effective* alias (the
    one the model router was asked for), so what runs is what gets recorded.
    """
    from tools.config_manager import get_ai_provider

    models_cfg = config.get("models", {}) or {}
    registry = models_cfg.get("registry", {}) or {}
    alias = model_alias or str(models_cfg.get("default_alias", "") or "")
    model_id = "unknown"
    entry: Any = registry.get(alias) if isinstance(registry, dict) else None
    if isinstance(entry, str) and entry.strip():
        model_id = entry.strip()
    elif isinstance(entry, dict):
        candidate = entry.get("model") or entry.get("model_id") or entry.get("name")
        if isinstance(candidate, str) and candidate.strip():
            model_id = candidate.strip()
    # Cloud-hosted ollama ids carry the version in the tag (``family:tag``);
    # local daemon metadata needs a round-trip we do not require here, so the
    # version stays unknown unless it is embedded in the id.
    model_version = model_id.split(":", 1)[1] if ":" in model_id else "unknown"
    try:
        provider = get_ai_provider(config)
    except Exception:  # noqa: BLE001 -- provider resolution must never abort a run
        provider = "unknown"
    return {
        "model_alias": unknown(alias),
        "model_id": unknown(model_id),
        "model_version": unknown(model_version),
        "model_provider": unknown(provider),
    }


def collect_environment(
    config: dict[str, Any],
    *,
    model_alias: str = "",
    benchmark_config: dict[str, Any] | None = None,
    sandbox_enabled: bool = False,
    sandbox_required: bool = True,
) -> RunEnvironment:
    """Capture everything needed to reproduce a run (or record it unknown)."""
    env = RunEnvironment()
    try:
        from main import __version__ as version  # noqa: PLC0415 -- avoids a heavy import at module load

        env.netattack_version = unknown(version)
    except Exception:  # noqa: BLE001
        env.netattack_version = "unknown"

    sha = _git("rev-parse", "HEAD")
    env.git_sha = sha or "unknown"
    dirty_raw = _git("status", "--porcelain")
    env.git_dirty = bool(dirty_raw) if (sha or dirty_raw != "") else None
    env.git_branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "unknown"

    meta = resolve_model_metadata(config, model_alias)
    env.model_provider = meta["model_provider"]
    env.model_alias = meta["model_alias"]
    env.model_id = meta["model_id"]
    env.model_version = meta["model_version"]
    env.reasoning_config = dict(config.get("reasoning", {}) or {})
    temp = (config.get("ollama", {}) or {}).get("temperature")
    env.temperature = float(temp) if isinstance(temp, (int, float)) else None

    env.config_hash = config_hash(config)
    env.benchmark_config_hash = config_hash(benchmark_config)
    env.sandbox_enabled = sandbox_enabled
    env.sandbox_required = sandbox_required
    sandbox_image = str(((config.get("sandbox", {}) or {}).get("image", "")) or "netattackai-sandbox:latest")
    env.sandbox_image = unknown(sandbox_image)
    env.sandbox_image_digest = docker_image_digest(sandbox_image)
    env.platform = f"{platform.system()}/{platform.release()}"
    env.python_version = sys.version.split(" ", 1)[0]
    return env
