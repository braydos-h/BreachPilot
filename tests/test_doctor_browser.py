"""Doctor browser-check tests (no launches, no network, no Docker needed)."""

from __future__ import annotations

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


def test_browser_playwright_missing_sdk_fails_with_hint(monkeypatch):
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: False)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: False)
    check = _check_browser({"browser": {"enabled": True, "backend": "playwright"}})
    assert check["ok"] is False
    assert check["subchecks"][0] == {"name": "playwright_sdk", "ok": False}
    assert "browser" in check["hint"]


def test_browser_playwright_ready_when_sdk_and_chromium(monkeypatch):
    import tools.browser._pw_probe as _probe

    monkeypatch.setattr(_probe, "playwright_present", lambda: True)
    monkeypatch.setattr(_probe, "chromium_present", lambda **kwargs: True)
    check = _check_browser({"browser": {"enabled": True, "backend": "playwright"}})
    assert check["ok"] is True
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
