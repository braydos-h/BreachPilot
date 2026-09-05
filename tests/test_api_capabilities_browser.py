"""API capability-status metadata for the browser seam (architecture-only build).

``/api/v1/capabilities`` gains a ``browser`` block — status metadata ONLY.
There are no browser endpoints; ``available`` is hard-coded False and every
capability record reports unavailable, so no API client (or WebUI) can ever
mistake declared browser capabilities for working ones.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, *, browser_block: dict | None = None) -> TestClient:
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token-0123456789abcdef01234567")
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools import config_cli as _config_cli

    config = _config_cli.load_config(config_path)
    if browser_block is not None:
        config["browser"] = browser_block
    from app import create_app

    return TestClient(create_app(config_path=config_path, config=config))


def _capabilities_headers():
    return {"Authorization": "Bearer test-token-0123456789abcdef01234567"}


def test_capabilities_reports_browser_unavailable(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers=_capabilities_headers())
    assert resp.status_code == 200
    browser = resp.json()["browser"]
    assert browser["available"] is False
    assert browser["enabled"] is False
    assert browser["backend"] == "none"
    names = {c["name"] for c in browser["capabilities"]}
    assert "browser.navigate" in names
    assert all(c["available"] is False for c in browser["capabilities"])


def test_capabilities_never_lies_even_with_browser_enabled(tmp_path, monkeypatch):
    """A config flipping browser.enabled can NOT make the API report availability.

    The route reports metadata (enabled/backend), availability stays False —
    no endpoint pretends a browser works.
    """
    client = _make_client(
        tmp_path,
        monkeypatch,
        browser_block={
            "enabled": True,
            "backend": "playwright",
            "headless": True,
            "max_sessions": 2,
            "session_timeout_seconds": 300,
            "navigation_timeout_seconds": 30,
            "capture_screenshots": True,
            "capture_network": True,
            "capture_console": False,
            "persist_storage": False,
        },
    )
    resp = client.get("/api/v1/capabilities", headers=_capabilities_headers())
    browser = resp.json()["browser"]
    assert browser["enabled"] is True
    assert browser["backend"] == "playwright"
    assert browser["available"] is False
    assert all(c["available"] is False for c in browser["capabilities"])
