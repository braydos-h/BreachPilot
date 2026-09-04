"""Playwright runtime probes — import-safe availability checks (never launches).

All Playwright/Chromium detection lives here (plus the backend adapter and the
sandbox worker script) so the rest of BreachPilot never imports a browser
package. Every function is side-effect free: no browser is launched, no socket
is opened, no target is touched — safe for ``--doctor``, ``/capabilities``,
and capability gating on machines without Playwright installed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

__all__ = [
    "MISSING_DEP_MSG",
    "playwright_present",
    "playwright_version",
    "chromium_present",
    "browser_health",
]

MISSING_DEP_MSG = (
    "Playwright is not installed. Browser execution needs the optional "
    "'browser' extra: python -m pip install -e \".[browser]\" "
    "and the Chromium runtime (python -m playwright install chromium) for "
    "host-side dev, or the sandbox browser worker image "
    "(docker/sandbox/Dockerfile.browser) for contained runs. "
    "Installs without it keep working (browser capabilities report unavailable)."
)


def playwright_present() -> bool:
    """Whether the Playwright Python SDK is importable (no launch)."""
    try:
        import importlib.util

        return importlib.util.find_spec("playwright") is not None
    except Exception:  # noqa: BLE001 — probe must never raise
        return False


def playwright_version() -> str:
    """Installed SDK version, or ``""`` when absent."""
    try:
        from importlib.metadata import version

        return version("playwright")
    except Exception:  # noqa: BLE001 — probe must never raise
        return ""


def _browsers_dir() -> Path:
    """Playwright browser-download root (respects PLAYWRIGHT_BROWSERS_PATH)."""
    override = (os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "") or "").strip()
    if override:
        return Path(override)
    return Path.home() / ".cache" / "ms-playwright"


def chromium_present(*, executable_path: str = "") -> bool:
    """Whether a Chromium runtime looks installed (file probe, no launch).

    Checks an explicit ``browser.executable_path`` override first, then the
    standard Playwright download layout (``chromium-*/chrome-linux/chrome``).
    A missing SDK always reports absent — the heuristic only runs when the
    package that owns the layout is installed.
    """
    try:
        if executable_path.strip() and Path(executable_path.strip()).is_file():
            return True
        if not playwright_present():
            return False
        root = _browsers_dir()
        if not root.is_dir():
            return False
        for candidate in sorted(root.glob("chromium-*/chrome-linux/chrome")):
            if candidate.is_file():
                return True
        for candidate in sorted(root.glob("chromium-*/chrome-win/chrome.exe")):
            if candidate.is_file():
                return True
        return False
    except Exception:  # noqa: BLE001 — probe must never raise
        return False


def browser_health(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Doctor-shaped browser runtime report (metadata only, no side effects)."""
    browser_cfg = (config or {}).get("browser", {}) or {}
    sdk = playwright_present()
    chromium = chromium_present(executable_path=str(browser_cfg.get("executable_path") or ""))
    ok = bool(sdk and chromium)
    if ok:
        detail = f"playwright {playwright_version() or 'unknown'} + chromium runtime present"
    elif not sdk:
        detail = "playwright SDK not installed (optional 'browser' extra)"
    else:
        detail = "playwright SDK present but no chromium runtime (run: python -m playwright install chromium)"
    return {
        "name": "browser_backend_playwright",
        "ok": ok,
        "detail": detail,
        "playwright_present": sdk,
        "playwright_version": playwright_version(),
        "chromium_present": chromium,
    }
