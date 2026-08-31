"""Smoke tests for the optional bundled WebUI served by the API daemon.

These tests are skipped when ``webui/dist/index.html`` is absent — the build is
not a test dependency. When the build is present, they verify that:

* ``serve_webui: true`` mounts the SPA at ``/`` and serves ``index.html``.
* Deep-link paths (``/runs/123``, ``/system``) return the SPA (client-side routing).
* ``/api/v1/health``, ``/docs``, and ``/openapi.json`` remain reachable.
* ``serve_webui: false`` (default) leaves ``/`` as 404.
* The in-memory ``config`` override reaches the factory without writing to disk.
* Asset path traversal is blocked.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

WEBUI_DIST = Path(__file__).resolve().parents[1] / "webui" / "dist"
INDEX_HTML = WEBUI_DIST / "index.html"

skip_if_no_build = pytest.mark.skipif(
    not INDEX_HTML.exists(),
    reason="webui/dist/index.html not built — run `cd webui && npm install && npm run build`",
)


def _make_client(tmp_path, monkeypatch, *, serve_webui: bool, callables=None):
    """Create a TestClient with a known token and an in-memory serve_webui flag."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token")
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
    config.setdefault("api", {})["serve_webui"] = serve_webui
    from app import create_app

    if callables is None:
        app = create_app(config_path=config_path, config=config)
    else:
        app = create_app(config_path=config_path, config=config, callables=callables)
    return TestClient(app)


@skip_if_no_build
def test_serve_webui_returns_index_html(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch, serve_webui=True)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    body = resp.text
    assert '<div id="root"></div>' in body
    assert "BreachPilot" in body or "root" in body


@skip_if_no_build
def test_serve_webui_deep_link_returns_spa(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch, serve_webui=True)
    for path in ("/runs/123", "/runs/abc/artifacts", "/system", "/runs/new"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        assert '<div id="root"></div>' in resp.text


@skip_if_no_build
def test_serve_webui_does_not_shadow_api(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch, serve_webui=True)
    client2 = TestClient(client.app, raise_server_exceptions=False)
    # Health (no auth).
    resp = client2.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True
    # Docs (FastAPI's Swagger UI).
    resp = client2.get("/docs")
    assert resp.status_code == 200
    # A protected API route still requires auth (not shadowed by SPA).
    resp = client2.get("/api/v1/capabilities")
    assert resp.status_code == 401
    # OpenAPI schema endpoint must return 200 (not 500, not shadowed by the
    # SPA fallback). Previously the bare ``Response`` return annotation on the
    # SSE stream route made schema generation raise PydanticUserError -> 500.
    resp = client2.get("/openapi.json")
    assert resp.status_code == 200, f"openapi.json returned {resp.status_code} (expected 200)"
    assert "/api/v1/runs" in resp.json().get("paths", {})


@skip_if_no_build
def test_serve_webui_off_leaves_root_404(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch, serve_webui=False)
    resp = client.get("/")
    assert resp.status_code == 404


@skip_if_no_build
def test_serve_webui_in_memory_override_does_not_persist(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\napi:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    _make_client(tmp_path, monkeypatch, serve_webui=True)
    after = config_path.read_text(encoding="utf-8")
    assert "serve_webui" not in after, "In-memory serve_webui override must not write to config.yaml"


@skip_if_no_build
def test_serve_webui_asset_traversal_blocked(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch, serve_webui=True)
    # The SPA fallback's resolved-path guard blocks traversal outside
    # webui/dist. A path with encoded traversal that the router passes
    # through should not resolve to a file outside the dist directory.
    resp = client.get("/../../etc/passwd", follow_redirects=False)
    # The TestClient normalizes ../ in the URL path, so this either lands on
    # the SPA fallback (200, index.html) or is blocked. Both are safe — no
    # filesystem traversal occurs because the guard resolves and checks.
    assert resp.status_code in (200, 400, 404)
    # Critical: the response must never contain /etc/passwd content.
    assert "root:" not in resp.text


@skip_if_no_build
def test_serve_webui_traversal_probes_do_not_crash(tmp_path, monkeypatch):
    """Real-world traversal probes (seen from an in-lab web scan of the daemon)
    must return 4xx, never raise. On Windows, decoded probes like
    "//../../../boot.ini" become "\\..\\..\\boot.ini" — pathlib treats the
    leading backslashes as a rooted UNC path, so the old code's
    (webui_dist / full_path).resolve() raised PermissionError [WinError 31]
    ("A device attached to the system is not functioning") and returned 500.
    """
    client = TestClient(_make_client(tmp_path, monkeypatch, serve_webui=True).app, raise_server_exceptions=False)
    probes = [
        # Percent-encoded backslash traversal (decodes to //..\..\..\boot.ini).
        "/%2F%2F..%5C..%5C..%5Cboot.ini",
        # Leading-slash blob followed by ../ (decodes rooted/UNC-looking input).
        "/..%5C..%5C..%5C..%5C..%5Cboot.ini",
        # Backslash-only traversal.
        "/..%5C..%5Cboot.ini",
        # Drive-letter absolute path.
        # Drive-letter absolute path.
        "/C:%5Cboot.ini",
        "/C:%5CWindows%5Cwin.ini",
        # NUL byte inside the path (realpath raises ValueError/OSError).
        "/%00boot.ini",
    ]
    for probe in probes:
        resp = client.get(probe, follow_redirects=False)
        assert resp.status_code in (200, 400, 404), f"{probe} returned {resp.status_code} (expected 4xx-safe)"
        assert resp.status_code != 500, f"{probe} leaked a server exception"
    # Sanity: normal deep links still serve the SPA after the guard tightened.
    resp = client.get("/runs/123", follow_redirects=False)
    assert resp.status_code == 200 and '<div id="root"></div>' in resp.text


def test_serve_webui_missing_build_is_noop(tmp_path, monkeypatch):
    """When dist/index.html is absent, serve_webui: true does not mount anything."""
    if INDEX_HTML.exists():
        pytest.skip("webui/dist exists — cannot test the missing-build path here.")
    client = _make_client(tmp_path, monkeypatch, serve_webui=True)
    resp = client.get("/")
    assert resp.status_code == 404
