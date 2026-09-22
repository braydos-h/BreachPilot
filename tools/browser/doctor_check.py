"""Browser doctor check — canonical Playwright-SDK-missing contract.

Extracted from :mod:`tools.doctor` (god-file budget: ``tools/doctor.py`` must
not grow). ``tools.doctor._check_browser`` is a thin shim over
:func:`check_browser` here.

Canonical contract (pinned by ``tests/test_doctor_browser.py``):

- missing Playwright SDK (with no contained fallback) = **SKIP** with an
  install hint, NOT a FAIL. ``ok`` is True so ``bp --doctor`` stays green on
  stock installs; ``skipped``/``status="skip"`` marks the row, and ``hint``
  names the optional ``browser`` extra. Live-Chromium integration tests skip
  with the same hint (``tests/test_browser_integration.py``), so the doctor
  message and the job assertion match exactly.
- Same SKIP treatment for a missing Chromium runtime and a missing browser
  worker image when neither host nor contained execution is runnable: the
  browser capability is optional and stock installs keep working (capabilities
  report unavailable).
- Still FAIL (fail closed): ``browser.enabled`` with ``backend: none``,
  unknown backends, and browser-subsystem import failures. Execution itself
  always blocks without the SDK (``BrowserBackendUnavailable``) — the SKIP
  only keeps the *doctor report* green, it never grants execution.
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

    Never launches a browser or touches a target — SDK/Chromium presence are
    file probes and the worker image is a Docker metadata lookup. When
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
        from tools.browser._pw_probe import browser_health, chromium_present, playwright_present
    except Exception as exc:  # noqa: BLE001 -- doctor must never crash on import
        result["ok"] = False
        result["error"] = f"browser subsystem import failed: {exc}"
        return result
    sdk_ok = bool(playwright_present())
    chromium_ok = bool(chromium_present(executable_path=str(browser_cfg.get("executable_path") or "")))
    health = browser_health(config)
    subchecks: list[dict[str, Any]] = [
        {"name": "playwright_sdk", "ok": sdk_ok},
        {"name": "chromium_runtime", "ok": chromium_ok},
    ]
    sandbox_enabled = bool(_SandboxConfig.from_config(config).enabled)
    worker_image: str | None = None
    worker_ok: bool | None = None
    if sandbox_enabled:
        from tools.browser.sandbox_launcher import browser_worker_image

        worker_image = browser_worker_image(config)
        try:
            from tools.sandbox.docker_backend import docker_image_exists, docker_version

            daemon_ok, _reason = docker_version()
            if daemon_ok:
                worker_ok = bool(docker_image_exists(worker_image))
            else:
                worker_ok = False
        except Exception:  # noqa: BLE001 -- image probe failure means not runnable
            worker_ok = False
        subchecks.append({"name": "browser_worker_image", "ok": bool(worker_ok), "value": worker_image or ""})
    result["subchecks"] = subchecks
    result["health"] = health.get("detail", "")
    host_ready = bool(sdk_ok and chromium_ok)
    contained_ready = bool(sandbox_enabled and worker_ok)
    if host_ready or contained_ready:
        result["ok"] = True
        result["value"] = worker_image or "host playwright + chromium"
        if contained_ready and not host_ready:
            result["note"] = "host SDK/chromium absent — browser runs contained in the sandbox worker"
        return result
    # Optional-capability SKIP (not FAIL): without the SDK/runtime/worker the
    # browser simply reports unavailable and execution blocks fail-closed at
    # the backend; the doctor row stays green with an install hint.
    result["ok"] = True
    result["skipped"] = True
    result["status"] = SKIP_STATUS
    if not sdk_ok:
        result["note"] = SDK_SKIP_NOTE
        result["hint"] = SDK_SKIP_HINT
    elif not chromium_ok:
        result["note"] = CHROMIUM_SKIP_NOTE
        result["hint"] = CHROMIUM_SKIP_HINT
    elif sandbox_enabled and not worker_ok:
        result["note"] = WORKER_SKIP_NOTE_TEMPLATE.format(image=worker_image)
        result["hint"] = worker_skip_hint(str(worker_image))
    else:  # pragma: no cover - defensive; subchecks above cover the real cases
        result["ok"] = False
        result.pop("skipped", None)
        result.pop("status", None)
        result["error"] = "browser backend not ready"
        result["hint"] = str(health.get("detail", ""))
    result["value"] = worker_image or ""
    return result
