"""Doctor browser-check tests (Docker calls are mocked; no launches/network).

The sandbox browser-worker image and Docker daemon are required for browser
execution. If unavailable, the optional capability is SKIP, while launch still
fails closed. Host Playwright/Chromium installations cannot replace the worker.
"""

from __future__ import annotations

import pytest

from tools.browser.doctor_check import (
    SKIP_STATUS,
    WORKER_SKIP_NOTE_TEMPLATE,
    worker_skip_hint,
)
from tools.doctor import _check_browser


def _make_worker_unavailable(monkeypatch):
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_docker, "docker_version", lambda: (False, "daemon unavailable"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda _image: False)


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


def test_browser_worker_unavailable_skips_with_build_hint(monkeypatch):
    """Unavailable Docker produces an optional SKIP and worker build hint."""
    _make_worker_unavailable(monkeypatch)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:browser"},
    }
    check = _check_browser(config)
    assert check["name"] == "browser"
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == WORKER_SKIP_NOTE_TEMPLATE.format(image="breachpilot-sandbox:browser")
    assert check["hint"] == worker_skip_hint("breachpilot-sandbox:browser")
    assert check["subchecks"] == [
        {"name": "docker_daemon", "ok": False},
        {"name": "browser_worker_image", "ok": False, "value": "breachpilot-sandbox:browser"},
    ]
    assert check["detail"] == "daemon unavailable"


def test_invalid_sandbox_config_fails_doctor_check():
    check = _check_browser({"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": False}})
    assert check["ok"] is False
    assert "invalid sandbox configuration" in check["error"]
    assert "sandbox.enabled=false is unsafe" in check["error"]


def test_browser_worker_image_missing_skips(monkeypatch):
    """Missing worker image yields the actionable build hint."""
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: False)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:browser"},
    }
    check = _check_browser(config)
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == WORKER_SKIP_NOTE_TEMPLATE.format(image="breachpilot-sandbox:browser")
    assert check["hint"] == worker_skip_hint("breachpilot-sandbox:browser")


def test_host_sdk_and_chromium_do_not_bypass_missing_worker(monkeypatch):
    """Local browser packages never turn an unavailable worker into ready."""
    import tools.browser._pw_probe as _probe
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_probe, "playwright_present", lambda: True)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: True)
    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: False)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:browser"},
    }
    check = _check_browser(config)
    assert check["ok"] is True
    assert check.get("skipped") is True
    assert check.get("status") == SKIP_STATUS
    assert check["note"] == WORKER_SKIP_NOTE_TEMPLATE.format(image="breachpilot-sandbox:browser")
    assert check["hint"] == worker_skip_hint("breachpilot-sandbox:browser")
    assert check["subchecks"] == [
        {"name": "docker_daemon", "ok": True},
        {"name": "browser_worker_image", "ok": False, "value": "breachpilot-sandbox:browser"},
    ]


def test_browser_worker_image_ready(monkeypatch):
    """The contained worker image is the only browser execution prerequisite."""
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda image: True)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:browser"},
    }
    check = _check_browser(config)
    assert check["ok"] is True
    assert check.get("skipped", False) is False
    assert check["value"] == "breachpilot-sandbox:browser"
    assert check["subchecks"] == [
        {"name": "docker_daemon", "ok": True},
        {"name": "browser_worker_image", "ok": True, "value": "breachpilot-sandbox:browser"},
    ]


def test_mismatched_session_worker_image_is_unavailable(monkeypatch):
    """Doctor cannot report ready when the session worker is not the browser image."""
    import tools.sandbox.docker_backend as _docker

    monkeypatch.setattr(_docker, "docker_version", lambda: (True, "ok"))
    monkeypatch.setattr(_docker, "docker_image_exists", lambda _image: True)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:latest"},
    }
    check = _check_browser(config)
    assert check["ok"] is False
    assert "sandbox.image='breachpilot-sandbox:browser'" in check["error"]
    assert "breachpilot-sandbox:latest" in check["error"]
    assert "sandbox.image: breachpilot-sandbox:browser" in check["hint"]


def test_browser_skip_never_grants_execution(monkeypatch):
    """SKIP keeps doctor green but unavailable browser execution still blocks."""
    _make_worker_unavailable(monkeypatch)
    config = {
        "browser": {"enabled": True, "backend": "playwright"},
        "sandbox": {"enabled": True, "image": "breachpilot-sandbox:browser"},
    }
    check = _check_browser(config)
    assert check["ok"] is True and check.get("skipped") is True

    from types import SimpleNamespace

    from tools.browser.sandbox_launcher import resolve_browser_launcher

    launcher, block = resolve_browser_launcher(SimpleNamespace(), config)
    assert launcher is None
    assert "SANDBOX_UNAVAILABLE" in block
