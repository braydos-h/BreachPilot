"""Regression test for multi-app isolation (router factory).

Two simultaneously alive FastAPI apps created via create_app() must not share
mutable route-module globals. Creating a second app must not overwrite the
dependencies used by routes belonging to the first app.

Tests:
- Authentication isolation: token A works only for app A, token B only for B.
- Persistence isolation: a run created via app A does not appear via app B,
  and vice versa (separate report dirs / ApiPersistence instances).

Both apps remain alive at the same time; the test fails if shared globals
leak one app's state into the other.
"""

from __future__ import annotations

import pathlib
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _make_config(tmp_path: pathlib.Path, token: str) -> dict:
    return {
        "api": {"host": "127.0.0.1", "port": 8765, "token_file": str(tmp_path / ".token"), "event_buffer_size": 256},
        "reports_dir": str(tmp_path / "reports"),
        "ollama": {"host": "http://localhost:11434"},
        "models": {"default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}},
        "exploit": {"permission": "read_only"},
    }


def _fake_callables(tmp_path: pathlib.Path):
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    def _fake_build_router(*a, **kw):
        return _FakeRouter()

    async def _fake_run_session(**kwargs):
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    return Callables(build_router=_fake_build_router, run_session=_fake_run_session)


def test_multi_app_auth_isolation(tmp_path, monkeypatch):
    from app import create_app

    # Two separate dirs for two apps
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")
    (dir_b / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")

    config_a = _make_config(dir_a, "token-a-0123456789abcdef01234567")
    config_b = _make_config(dir_b, "token-b-0123456789abcdef01234567")

    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-a-0123456789abcdef01234567")
    app_a = create_app(config_path=dir_a / "config.yaml", config=config_a, callables=_fake_callables(dir_a))
    # Do not destroy app_a; keep it alive while creating app_b
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-b-0123456789abcdef01234567")
    app_b = create_app(config_path=dir_b / "config.yaml", config=config_b, callables=_fake_callables(dir_b))

    client_a = TestClient(app_a)
    client_b = TestClient(app_b)

    # Token A works only for app A
    assert (
        client_a.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
        ).status_code
        == 200
    )
    assert (
        client_a.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
        ).status_code
        == 401
    )
    # Token B works only for app B
    assert (
        client_b.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
        ).status_code
        == 200
    )
    assert (
        client_b.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
        ).status_code
        == 401
    )

    # Creating app_b must not have altered app_a's auth: re-check
    assert (
        client_a.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
        ).status_code
        == 200
    )
    assert (
        client_a.get(
            "/api/v1/capabilities", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
        ).status_code
        == 401
    )


def test_multi_app_persistence_isolation(tmp_path, monkeypatch):
    from app import create_app

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")
    (dir_b / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")

    config_a = _make_config(dir_a, "token-a-0123456789abcdef01234567")
    config_b = _make_config(dir_b, "token-b-0123456789abcdef01234567")

    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-a-0123456789abcdef01234567")
    app_a = create_app(config_path=dir_a / "config.yaml", config=config_a, callables=_fake_callables(dir_a))
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-b-0123456789abcdef01234567")
    app_b = create_app(config_path=dir_b / "config.yaml", config=config_b, callables=_fake_callables(dir_b))

    client_a = TestClient(app_a)
    client_b = TestClient(app_b)

    # Create a run via app_a
    resp_a = client_a.post(
        "/api/v1/runs",
        json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"},
        headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"},
    )
    assert resp_a.status_code == 201
    run_id_a = resp_a.json()["run_id"]

    # It should be visible via app_a but not via app_b
    assert (
        client_a.get(
            f"/api/v1/runs/{run_id_a}", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
        ).status_code
        == 200
    )
    assert (
        client_b.get(
            f"/api/v1/runs/{run_id_a}", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
        ).status_code
        == 404
    )

    # List runs: app_a has 1, app_b has 0
    list_a = client_a.get("/api/v1/runs", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}).json()
    list_b = client_b.get("/api/v1/runs", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}).json()
    assert any(r["id"] == run_id_a for r in list_a["runs"])
    assert not any(r["id"] == run_id_a for r in list_b["runs"])

    # Create a run via app_b, ensure it doesn't appear in app_a
    resp_b = client_b.post(
        "/api/v1/runs",
        json={"target": "10.0.0.51", "mode": "attack", "goal": "recon_only"},
        headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"},
    )
    assert resp_b.status_code == 201
    run_id_b = resp_b.json()["run_id"]
    assert (
        client_b.get(
            f"/api/v1/runs/{run_id_b}", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
        ).status_code
        == 200
    )
    assert (
        client_a.get(
            f"/api/v1/runs/{run_id_b}", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
        ).status_code
        == 404
    )


def test_multi_app_simultaneous_liveness(tmp_path, monkeypatch):
    """Ensure both apps stay correctly isolated while both are alive (no sequential create/destroy)."""
    from app import create_app

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")
    (dir_b / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")

    config_a = _make_config(dir_a, "token-a-0123456789abcdef01234567")
    config_b = _make_config(dir_b, "token-b-0123456789abcdef01234567")

    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-a-0123456789abcdef01234567")
    app_a = create_app(config_path=dir_a / "config.yaml", config=config_a, callables=_fake_callables(dir_a))
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "token-b-0123456789abcdef01234567")
    app_b = create_app(config_path=dir_b / "config.yaml", config=config_b, callables=_fake_callables(dir_b))

    client_a = TestClient(app_a)
    client_b = TestClient(app_b)

    # Interleaved requests to prove no cross-talk
    for _ in range(3):
        assert (
            client_a.get(
                "/api/v1/capabilities", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
            ).status_code
            == 200
        )
        assert (
            client_b.get(
                "/api/v1/capabilities", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
            ).status_code
            == 200
        )
        assert (
            client_a.get(
                "/api/v1/capabilities", headers={"Authorization": "Bearer token-b-0123456789abcdef01234567"}
            ).status_code
            == 401
        )
        assert (
            client_b.get(
                "/api/v1/capabilities", headers={"Authorization": "Bearer token-a-0123456789abcdef01234567"}
            ).status_code
            == 401
        )
