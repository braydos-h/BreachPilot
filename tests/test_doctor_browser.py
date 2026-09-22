"""Doctor browser-check tests (no launches, no network, no Docker needed).

Canonical contract (see tools/browser/doctor_check.py): a missing Playwright
SDK with no contained fallback is SKIP with an install hint, NOT a FAIL —
``bp --doctor`` stays green on stock installs while execution itself still
blocks fail-closed at the backend. The SKIP hint strings are shared verbatim
with the live-integration skip messages (tests/test_browser_integration.py)
so the doctor message and the job assertion match exactly.
"""

from __future__ import annotations

from tools.browser.doctor_check import (
    CHROMIUM_SKIP_HINT,
    CHROMIUM_SKIP_NOTE,
    SDK_SKIP_HINT,
    SDK_SKIP_NOTE,
    SKIP_STATUS,
)
from tools.doctor import _check_browser


def test_browser_disabled_is_informational_pass():
    for config in (None, {}, {"browser": {"enabled": False}}):
        check = _check_browser(config)
        assert check["name"] == "browser"
        assert check["ok"] is True
        assert "disabled" in check.get("note", "")


def test_browser_enabled_without_backend_fails():
    check = _check_browser({"browser": {"enabled": True, "backend": "none"}})
    assert check["ok"] is False
    assert "backend" in check["error"]
    assert check["hint"]


def test_browser_unknown_backend_fails():
    check = _check_browser({"browser": {"enabled": True, "backend": "selenium"}})
    assert check["ok"] is False
    assert "selenium" in check["error"]


def test_browser_playwright_missing_sdk_skips_with_hint(monkeypatch):
    """SDK absent + host-only = SKIP (ok), not FAIL, with the exact hint."""
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: False)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": False}}
    check = _check_browser(config)
    assert check["name"] == "browser"
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == SDK_SKIP_NOTE
    assert check["hint"] == SDK_SKIP_HINT  # exact: shared with the live-integration skip
    assert check["subchecks"][0] == {"name": "playwright_sdk", "ok": False}
    assert "browser" in check["hint"]


def test_browser_playwright_sdk_present_but_chromium_missing_skips(monkeypatch):
    """SDK present + no Chromium + host-only = SKIP with the Chromium hint."""
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: True)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": False}}
    check = _check_browser(config)
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == CHROMIUM_SKIP_NOTE
    assert check["hint"] == CHROMIUM_SKIP_HINT
    assert check["subchecks"][0] == {"name": "playwright_sdk", "ok": True}
    assert check["subchecks"][1] == {"name": "chromium_runtime", "ok": False}


def test_browser_worker_image_missing_skips(monkeypatch):
    """Sandbox enabled but neither host nor worker runnable = SKIP, not FAIL."""
    import tools.browser._pw_probe as _probe
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_probe, "playwright_present", lambda: False)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: False)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": True}}
    check = _check_browser(config)
    # SDK-missing branch fires first when the host SDK is absent.
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS


def test_browser_chromium_missing_with_sandbox_still_skips_chromium_hint(monkeypatch):
    """SDK present, Chromium absent, worker absent: Chromium SKIP wins (branch order)."""
    import tools.browser._pw_probe as _probe
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_probe, "playwright_present", lambda: True)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: False)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": True}}
    check = _check_browser(config)
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == CHROMIUM_SKIP_NOTE
    assert check["hint"] == CHROMIUM_SKIP_HINT


def test_browser_playwright_ready_when_sdk_and_chromium(monkeypatch):
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: True)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: True)
    # Explicit host-mode fixture: absent section now means contained (BP-02),
    # which would append a (failing, unmocked-Docker) worker subcheck.
    check = _check_browser({"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": False}})
    assert check["ok"] is True
    assert check.get("skipped", False) is False
    assert all(s["ok"] for s in check["subchecks"])


def test_browser_contained_ready_without_host_sdk(monkeypatch):
    """Sandbox worker with the image counts as ready even with no host SDK."""
    import tools.browser._pw_probe as _probe
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_probe, "playwright_present", lambda: False)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: True)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": True}}
    check = _check_browser(config)
    assert check["ok"] is True
    assert any(s["name"] == "browser_worker_image" and s["ok"] for s in check["subchecks"])


def test_browser_skip_never_grants_execution(monkeypatch):
    """SKIP keeps doctor green but the backend still blocks fail-closed."""
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: False)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": False}}
    check = _check_browser(config)
    assert check["ok"] is True and check.get("skipped") is True

    from tools.browser.capabilities import browser_runtime_available

    assert browser_runtime_available(config) is False
