"""Tests for GET /system/sandbox (todo p1-04-security-observable).

The endpoint is the read-only surface behind the WebUI Sandbox/Firewall
card: it must always return the mode/docker/network/resources keys the card
renders, whether Docker is up, down, or the sandbox is disabled. All
subprocess / Docker calls are mocked; no live daemon is touched.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from tools.sandbox import docker_backend as _db


def _make_client(tmp_path, monkeypatch, token="test-token-0123456789abcdef01234567"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "sandbox:\n  enabled: true\n  image: breachpilot-sandbox:latest\n"
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
    from fastapi.testclient import TestClient

    return TestClient(app)


def _auth(token="test-token-0123456789abcdef01234567"):
    return {"Authorization": f"Bearer {token}"}


def test_sandbox_status_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/system/sandbox")
    assert resp.status_code == 401


def _assert_card_keys(data):
    assert data["mode"] in ("disabled", "contained", "native_fallback", "blocked")
    assert isinstance(data["docker_available"], bool)
    assert isinstance(data["docker_error"], str)
    assert data["image_present"] in (True, False, None)
    for key in ("enforce", "fail_closed", "allow_dns", "extra_allow_cidrs", "map_host_loopback"):
        assert key in data["network"], f"network.{key} missing"
    for key in ("memory_mb", "cpus", "pids", "timeout_seconds", "output_max_bytes"):
        assert key in data["resources"], f"resources.{key} missing"
    assert "fallback_native" in data
    assert "fallback_reason" in data
    assert "backend" in data and "image" in data and "user" in data
    assert "read_only_rootfs" in data


def test_sandbox_status_contained_keys(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    resp = client.get("/api/v1/system/sandbox", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    _assert_card_keys(data)
    assert data["mode"] == "contained"
    assert data["image_present"] is True


def test_sandbox_status_docker_down_keys(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"))
    resp = client.get("/api/v1/system/sandbox", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    _assert_card_keys(data)
    assert data["docker_available"] is False
    assert data["image_present"] is None
    assert data["docker_error"] == "daemon unreachable"
