"""No-Playwright regression tests — the "Playwright is optional" acceptance gate.

Mirrors ``tests/test_no_ollama_regression.py``: the Playwright SDK may only be
imported inside the browser engine boundary (``tools/browser/`` engine files).
Everywhere else — manager, capabilities, MCP tools, planner, API, doctor —
must work with the package absent (stock installs report unavailable, never
crash), and selecting the playwright backend without the SDK raises an
ACTIONABLE error naming the extra.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Engine boundary: the ONLY tools/ modules allowed to import the playwright SDK.
_ALLOWED_PLAYWRIGHT_IMPORTERS = {
    "tools/browser/playwright_backend.py",
    "tools/browser/sandbox_launcher.py",
    "tools/browser/_pw_probe.py",
}

_IMPORT_PLAYWRIGHT_RE = re.compile(
    r"^\s*(?:import\s+playwright\b|from\s+playwright\b|import_module\(\s*['\"]playwright)",
    re.MULTILINE,
)


def test_playwright_sdk_import_is_isolated_to_the_engine():
    """A generic ``import playwright`` outside tools/browser/* fails this guard."""
    offenders: list[str] = []
    for path in (REPO_ROOT / "tools").rglob("*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in _ALLOWED_PLAYWRIGHT_IMPORTERS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file is not an importer
            continue
        if _IMPORT_PLAYWRIGHT_RE.search(text):
            offenders.append(rel)
    assert offenders == [], (
        "Generic playwright SDK imports found — isolate them in tools/browser/playwright_backend.py: "
        + ", ".join(offenders)
    )


_BLOCKED_IMPORT_BOOTSTRAP = """
import builtins, sys
_real = builtins.__import__
def _blocked(name, *args, **kwargs):
    if name == "playwright" or name.startswith("playwright."):
        raise ImportError("playwright blocked by test_no_playwright_regression")
    return _real(name, *args, **kwargs)
builtins.__import__ = _blocked
sys.modules.pop("playwright", None)
"""


def _run_without_playwright(body: str) -> subprocess.CompletedProcess[str]:
    script = _BLOCKED_IMPORT_BOOTSTRAP + "\n" + body + '\nprint("SUBPROCESS_OK")\n'
    return subprocess.run(  # noqa: S603 -- fixed argv, test-controlled script
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_browser_seam_importable_without_playwright_sdk():
    body = """
import tools.browser  # noqa: F401
from tools.browser.capabilities import browser_available, browser_capabilities
from tools.browser.manager import BrowserManager

assert browser_available({"browser": {"enabled": True, "backend": "playwright"}}) is False
assert BrowserManager(None).available() is False
assert all(c["available"] is False for c in browser_capabilities({}))

from tools.browser._pw_probe import browser_health, chromium_present, playwright_present
assert playwright_present() is False
assert chromium_present() is False
assert browser_health({})["ok"] is False
"""
    proc = _run_without_playwright(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout


def test_missing_playwright_sdk_error_is_actionable():
    """Backend start without the SDK raises a typed error naming the extra."""
    body = """
import asyncio
from tools.browser.capabilities import BACKEND_REGISTRY, register_playwright_backend
from tools.browser.errors import BrowserBackendUnavailable

assert register_playwright_backend({}) is True
backend = BACKEND_REGISTRY["playwright"]
assert backend.is_configured({"browser": {"enabled": True, "backend": "playwright"}}) is False
try:
    asyncio.run(backend.start_session(target="10.0.0.50", run_id="r1"))
except BrowserBackendUnavailable as exc:
    assert "browser" in str(exc).lower()
    assert "playwright" in str(exc).lower()
else:
    raise SystemExit("expected BrowserBackendUnavailable")
"""
    proc = _run_without_playwright(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout
