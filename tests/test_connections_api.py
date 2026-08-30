"""Tests for Connections / Access API — /api/v1/connections."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="conn-test-token"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n  workspace_dir: exploit_workspace\n"
        "operator_connection:\n  workspace_dir: exploit_workspace\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    def _fake_build_router(*a, **kw):
        return _FakeRouter()

    async def _fake_run_session(**kwargs):
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    callables = Callables(build_router=_fake_build_router, run_session=_fake_run_session)
    from app import create_app

    app = create_app(config_path=config_path, callables=callables)
    return TestClient(app)


def _auth(token="conn-test-token"):
    return {"Authorization": f"Bearer {token}"}


def _reset_connections():
    from tools.operator_connection.manager import reset_connection_manager

    reset_connection_manager()
    from tools.persistent_session_manager import reset_session_manager

    reset_session_manager()


def test_list_connections_empty(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/connections", headers=_auth())
    assert r.status_code == 200
    data = r.json()
    assert data["connections"] == []
    assert data["total"] == 0
    assert data["active"] == 0


def test_list_connections_with_records_and_filters(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    c1 = mgr.create_connection(
        target_ip="10.0.0.5",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-5-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    c2 = mgr.create_connection(
        target_ip="10.0.0.6",
        method="windows_schtask",
        callback_host="127.0.0.1",
        callback_port=4445,
        listener_name="persist-10-0-0-6-win",
        mitre_technique="T1053.005",
        os_family="windows",
    )
    # mark c2 stale
    mgr.mark_check(c2.connection_id, "no listener", False)
    _reset_connections()

    # list all
    r = client.get("/api/v1/connections", headers=_auth())
    assert r.status_code == 200
    assert r.json()["total"] == 2
    assert r.json()["active"] == 1
    assert r.json()["stale"] == 1

    # filter by status
    r = client.get("/api/v1/connections?status=active", headers=_auth())
    assert r.status_code == 200
    assert r.json()["total"] == 1
    assert all(c["status"] == "active" for c in r.json()["connections"])

    # filter by target
    r = client.get("/api/v1/connections?target=10.0.0.5", headers=_auth())
    assert r.status_code == 200
    assert r.json()["total"] == 1
    assert r.json()["connections"][0]["target_ip"] == "10.0.0.5"

    # combined
    r = client.get("/api/v1/connections?target=10.0.0.6&status=stale", headers=_auth())
    assert r.json()["total"] == 1

    # invalid status
    r = client.get("/api/v1/connections?status=invalid", headers=_auth())
    assert r.status_code == 400


def test_get_connection_existing_and_404(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    rec = mgr.create_connection(
        target_ip="10.0.0.15",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-15-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    _reset_connections()
    r = client.get(f"/api/v1/connections/{rec.connection_id}", headers=_auth())
    assert r.status_code == 200
    assert r.json()["connection_id"] == rec.connection_id

    r = client.get("/api/v1/connections/conn-notfound", headers=_auth())
    assert r.status_code == 404


def test_malformed_connection_id(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    # Path traversal attempt via encoded slash -> FastAPI will 404 before validation,
    # but a plain invalid pattern with hyphen still triggers 400.
    r = client.get("/api/v1/connections/..%2Fetc", headers=_auth())
    # Either 400 or 404 is acceptable for malformed — just not 500/200
    assert r.status_code in (400, 404)

    r = client.get("/api/v1/connections/conn-!invalid!", headers=_auth())
    assert r.status_code == 400


def test_auth_required(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/connections")
    assert r.status_code == 401
    r = client.get("/api/v1/connections/conn-abc", headers=_auth("wrong-token"))
    assert r.status_code == 401


def test_health_check_success_and_stale(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    rec = mgr.create_connection(
        target_ip="10.0.0.15",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-15-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    _reset_connections()

    # Mock listener as running -> healthy
    mock_sess = MagicMock()
    mock_sess.read_listener_output.return_value = {"output": "beacon", "running": True}
    mock_sess.list_all_sessions.return_value = [{"name": rec.listener_name, "running": True}]
    with patch("tools.persistent_session_manager.get_session_manager", return_value=mock_sess):
        r = client.post(f"/api/v1/connections/{rec.connection_id}/check", headers=_auth())
        assert r.status_code == 200
        assert r.json()["status"] == "active"
        assert r.json()["last_check"] is not None

    # Mock listener not running -> stale
    mock_sess.read_listener_output.return_value = {"output": "LOG_NOT_FOUND: /tmp/x", "running": False}
    mock_sess.list_all_sessions.return_value = []
    with patch("tools.persistent_session_manager.get_session_manager", return_value=mock_sess):
        r = client.post(f"/api/v1/connections/{rec.connection_id}/check", headers=_auth())
        assert r.status_code == 200
        assert r.json()["status"] == "stale"


def test_health_check_404(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    r = client.post("/api/v1/connections/conn-notfound/check", headers=_auth())
    assert r.status_code == 404


def test_listener_output_bounded_and_unavailable(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    rec = mgr.create_connection(
        target_ip="10.0.0.15",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-15-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    _reset_connections()

    # Without mock -> LOG_NOT_FOUND style (unavailable but not 500)
    r = client.get(f"/api/v1/connections/{rec.connection_id}/listener", headers=_auth())
    assert r.status_code == 200
    assert "connection_id" in r.json()
    assert "listener_name" in r.json()
    assert "output" in r.json()
    assert "updated_at" in r.json()

    # Bounded lines param - over limit -> 422
    r = client.get(f"/api/v1/connections/{rec.connection_id}/listener?lines=1000", headers=_auth())
    assert r.status_code == 422

    # Valid lines
    r = client.get(f"/api/v1/connections/{rec.connection_id}/listener?lines=10", headers=_auth())
    assert r.status_code == 200

    # 404 for unknown connection
    r = client.get("/api/v1/connections/conn-notfound/listener", headers=_auth())
    assert r.status_code == 404


def test_listener_output_mocked_success(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    rec = mgr.create_connection(
        target_ip="10.0.0.15",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-15-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    _reset_connections()
    mock_sess = MagicMock()
    mock_sess.read_listener_output.return_value = {"output": "hello\nworld\n", "running": True}
    with patch("tools.persistent_session_manager.get_session_manager", return_value=mock_sess):
        r = client.get(f"/api/v1/connections/{rec.connection_id}/listener", headers=_auth())
        assert r.status_code == 200
        assert "hello" in r.json()["output"]
        assert r.json()["running"] is True


def test_remove_connection_lifecycle(tmp_path, monkeypatch):
    _reset_connections()
    client = _make_client(tmp_path, monkeypatch)
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    from tools.operator_connection.manager import get_connection_manager

    mgr = get_connection_manager(ws)
    rec = mgr.create_connection(
        target_ip="10.0.0.15",
        method="linux_cron",
        callback_host="127.0.0.1",
        callback_port=4444,
        listener_name="persist-10-0-0-15-linux-cron",
        mitre_technique="T1053.003",
        os_family="linux",
    )
    _reset_connections()
    # Mock stop_listener to succeed
    mock_sess = MagicMock()
    mock_sess.stop_listener.return_value = {"success": True}
    mock_sess.stop_background_job.return_value = {"success": False}
    with patch("tools.persistent_session_manager.get_session_manager", return_value=mock_sess):
        r = client.post(f"/api/v1/connections/{rec.connection_id}/remove", headers=_auth())
        assert r.status_code == 200
        assert r.json()["removed"] is True
        assert r.json()["connection"]["status"] == "removed"
        assert r.json()["listener_stopped"] is True

    # Verify get shows removed
    r = client.get(f"/api/v1/connections/{rec.connection_id}", headers=_auth())
    assert r.status_code == 200
    assert r.json()["status"] == "removed"

    # Remove unknown -> 404
    r = client.post("/api/v1/connections/conn-notfound/remove", headers=_auth())
    assert r.status_code == 404

    # Auth required
    r = client.post(f"/api/v1/connections/{rec.connection_id}/remove")
    assert r.status_code == 401
