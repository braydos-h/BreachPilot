"""Browser doctor check — canonical Playwright-SDK-missing contract.

Extracted from :mod:`tools.doctor` (god-file budget: ``tools/doctor.py`` must
not grow). ``tools.doctor._check_browser`` is a thin shim over
:func:`check_browser` here.

- The sandbox browser-worker image and Docker daemon are required for browser
  execution. If they are unavailable the check is **SKIP**, not a failure of
  the base installation: ``ok`` remains true, ``status="skip"`` marks the
  optional capability, and the hint explains how to build the worker.
- Still FAIL (fail closed): ``browser.enabled`` with ``backend: none``,
  unknown backends, invalid sandbox configuration, and browser-subsystem
  import failures. Host Playwright/Chromium never substitutes for the worker.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "SKIP_STATUS",
    "SDK_SKIP_NOTE",
    "SDK_SKIP_HINT",
    "CHROMIUM_SKIP_NOTE",
    "CHROMIUM_SKIP_HINT",
    "WORKER_SKIP_NOTE_TEMPLATE",
    "worker_skip_hint",
    "check_browser",
]

#: Status marker for skipped browser rows (doctor ``ok`` stays True).
SKIP_STATUS = "skip"

#: Exact SKIP note/hint when the Playwright SDK is absent. The hint is shared
#: verbatim with the live-integration skip message so both agree exactly.
SDK_SKIP_NOTE = "Playwright SDK not installed — browser check skipped (optional 'browser' extra)"
SDK_SKIP_HINT = 'Install the optional extra: python -m pip install -e ".[browser]"'

#: Exact SKIP note/hint when the SDK is present but no Chromium runtime is.
CHROMIUM_SKIP_NOTE = "Chromium runtime missing — browser check skipped"
CHROMIUM_SKIP_HINT = "Install it: python -m playwright install chromium"

#: Note template for a missing browser worker image (formatted with image).
WORKER_SKIP_NOTE_TEMPLATE = "browser worker image {image!r} not built — browser check skipped"


def worker_skip_hint(image: str) -> str:
    """Exact SKIP hint for a missing browser worker image."""
    return f"Build it: docker build -t {image} -f docker/sandbox/Dockerfile.browser docker/sandbox"


def check_browser(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Browser-agent readiness: config, SDK, Chromium, worker image.

    Never launches a browser or touches a target — the worker image is a
    Docker metadata lookup. When
    ``browser.enabled`` is false this is an informational pass (stock installs
    stay green). Distinguishes: disabled / backend none / unknown backend /
    SDK missing (SKIP) / Chromium missing (SKIP) / worker image missing (SKIP)
    / ready.
    """
    from tools.sandbox.models import SandboxConfig as _SandboxConfig

    browser_cfg = (config or {}).get("browser", {}) or {}
    enabled = bool(browser_cfg.get("enabled", False))
    backend = str(browser_cfg.get("backend", "none") or "none")
    result: dict[str, Any] = {"name": "browser", "enabled": enabled, "backend": backend}
    if not enabled:
        result["ok"] = True
        result["note"] = "browser disabled -- no browser capability (enable with browser.enabled: true)"
        return result
    if backend in ("", "none"):
        result["ok"] = False
        result["error"] = "browser.enabled is true but browser.backend is 'none'"
        result["hint"] = "Set browser.backend: playwright (and install the optional browser extra)."
        return result
    if backend != "playwright":
        result["ok"] = False
        result["error"] = f"unknown browser backend {backend!r} (expected 'playwright' or 'none')"
        result["hint"] = "Set browser.backend: playwright, or disable with browser.enabled: false."
        return result
    try:
        sandbox_config = _SandboxConfig.from_config(config)
        sandbox_enabled = bool(sandbox_config.enabled)
    except (TypeError, ValueError) as exc:
        result["ok"] = False
        result["error"] = f"invalid sandbox configuration: {exc}"
        return result
    if not sandbox_enabled:  # defensive; SandboxConfig currently rejects this posture
        result["ok"] = False
        result["error"] = "browser execution requires sandbox containment"
        return result

    from tools.browser.sandbox_launcher import browser_worker_image

    worker_image = browser_worker_image(config)
    if sandbox_config.image != worker_image:
        result["ok"] = False
        result["error"] = (
            f"browser requires sandbox.image={worker_image!r}; "
            f"the session worker is configured as {sandbox_config.image!r}"
        )
        result["hint"] = f"Set sandbox.image: {worker_image} and rebuild that image if needed."
        return result
    daemon_ok = False
    worker_ok = False
    daemon_reason = "Docker daemon unavailable"
    try:
        from tools.sandbox.docker_backend import docker_image_exists, docker_version

        daemon_ok, daemon_reason = docker_version()
        if daemon_ok:
            worker_ok = bool(docker_image_exists(worker_image))
    except Exception as exc:  # noqa: BLE001 -- probe failure means not runnable
        daemon_reason = str(exc)
    result["subchecks"] = [
        {"name": "docker_daemon", "ok": bool(daemon_ok)},
        {"name": "browser_worker_image", "ok": bool(worker_ok), "value": worker_image},
    ]
    if worker_ok:
        result["ok"] = True
        result["value"] = worker_image
        result["note"] = "browser execution runs inside the sandbox worker"
        return result
    # Optional-capability SKIP (not FAIL): base installs work without browser
    # tooling, while browser execution remains unavailable and fail-closed.
    result["ok"] = True
    result["skipped"] = True
    result["status"] = SKIP_STATUS
    result["note"] = WORKER_SKIP_NOTE_TEMPLATE.format(image=worker_image)
    result["hint"] = worker_skip_hint(worker_image)
    if not daemon_ok:
        result["detail"] = str(daemon_reason)
    result["value"] = worker_image
    return result
