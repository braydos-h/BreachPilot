"""Tests for multi-operator WebUI: user accounts + annotations (D4).

D4 adds user accounts (stdlib ``hashlib.pbkdf2_hmac`` + ``secrets`` — no new
dep) and per-run annotations for pair-testing collaboration. The loopback bind
is NOT weakened — ``assert_api_loopback`` still refuses non-loopback hosts.

These tests verify:
- User creation, login (correct + wrong password), duplicate-username 409.
- Annotation attachment to a run + list + delete.
- The loopback bind is unchanged (non-loopback still refused).
- Password hashing uses PBKDF2 (stdlib only, no new dep).
- ``api.multi_operator: false`` (default) → user routes not mounted.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tools.api.auth import (
    assert_api_loopback,
    hash_password,
    verify_password,
)

# ── Password hashing (stdlib only) ───────────────────────────────────────────


def test_hash_password_returns_hash_and_salt():
    h, s = hash_password("hunter2")
    assert len(h) == 64  # SHA-256 hex
    assert len(s) == 32  # 16-byte salt hex
    assert h != s


def test_hash_password_different_salt_each_call():
    h1, s1 = hash_password("same")
    h2, s2 = hash_password("same")
    assert s1 != s2  # fresh salt
    assert h1 != h2  # different salt → different hash


def test_verify_password_correct():
    h, s = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h, s) is True


def test_verify_password_wrong():
    h, s = hash_password("correct")
    assert verify_password("wrong", h, s) is False


def test_verify_password_empty_rejected():
    h, s = hash_password("x")
    assert verify_password("", h, s) is False


def test_hash_password_empty_rejected():
    with pytest.raises(ValueError):
        hash_password("")


# ── Loopback bind unchanged ──────────────────────────────────────────────────


def test_loopback_still_enforced():
    """D4 must NOT weaken the loopback bind."""
    for host in ("127.0.0.1", "localhost", "::1"):
        assert_api_loopback(host)  # must not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.1", "example.com"])
def test_non_loopback_still_refused(host):
    with pytest.raises(ValueError, match="loopback"):
        assert_api_loopback(host)


# ── User accounts + annotations via the API ─────────────────────────────────


def _make_multi_operator_client(tmp_path, monkeypatch, token="test-token"):
    """Create a TestClient with ``api.multi_operator: true`` so user routes mount."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n  multi_operator: true\n",
        encoding="utf-8",
    )
    from app import create_app

    return TestClient(create_app(config_path=config_path))


def _make_legacy_client(tmp_path, monkeypatch, token="test-token"):
    """Create a TestClient with default config (multi_operator absent/false)."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from app import create_app

    return TestClient(create_app(config_path=config_path))


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_create_user(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/users", json={"username": "alice", "password": "secret"}, headers=_auth())
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "alice"
    assert "id" in data
    # Password hash is never returned.
    assert "password_hash" not in data
    assert "password_salt" not in data


def test_create_duplicate_user_409(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    client.post("/api/v1/users", json={"username": "bob", "password": "p1"}, headers=_auth())
    resp = client.post("/api/v1/users", json={"username": "bob", "password": "p2"}, headers=_auth())
    assert resp.status_code == 409


def test_login_correct_password(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    client.post("/api/v1/users", json={"username": "carol", "password": "correct"}, headers=_auth())
    resp = client.post("/api/v1/users/login", json={"username": "carol", "password": "correct"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["username"] == "carol"


def test_login_wrong_password_401(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    client.post("/api/v1/users", json={"username": "dave", "password": "right"}, headers=_auth())
    resp = client.post("/api/v1/users/login", json={"username": "dave", "password": "wrong"}, headers=_auth())
    assert resp.status_code == 401


def test_login_unknown_user_401(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/users/login", json={"username": "nobody", "password": "x"}, headers=_auth())
    assert resp.status_code == 401


def test_list_users_no_password_hashes(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    client.post("/api/v1/users", json={"username": "eve", "password": "p"}, headers=_auth())
    resp = client.get("/api/v1/users", headers=_auth())
    assert resp.status_code == 200
    users = resp.json()
    assert any(u["username"] == "eve" for u in users)
    for u in users:
        assert "password_hash" not in u
        assert "password_salt" not in u


def test_annotation_attach_and_list(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    # Create a user.
    user_resp = client.post("/api/v1/users", json={"username": "frank", "password": "p"}, headers=_auth())
    user_id = user_resp.json()["id"]
    # Create a run (minimal — we just need a run_id for the annotation).
    # Use the persistence layer directly to insert a run row without the full
    # AssessmentService prepare() path (which needs Ollama).
    from tools.api.persistence import ApiPersistence

    persistence = ApiPersistence(tmp_path / "reports")
    persistence.create_run(run_id="run-test1", request={"target": "10.0.0.50"}, preview={})
    # Attach an annotation.
    resp = client.post(
        "/api/v1/runs/run-test1/annotations",
        json={"body": "confirmed SQLi in /login", "finding_ref": "F-001", "user_id": user_id, "username": "frank"},
        headers=_auth(),
    )
    assert resp.status_code == 201
    ann = resp.json()
    assert ann["body"] == "confirmed SQLi in /login"
    assert ann["username"] == "frank"
    assert ann["finding_ref"] == "F-001"
    # List annotations.
    list_resp = client.get("/api/v1/runs/run-test1/annotations", headers=_auth())
    assert list_resp.status_code == 200
    anns = list_resp.json()
    assert len(anns) == 1
    assert anns[0]["body"] == "confirmed SQLi in /login"


def test_annotation_delete(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    user_resp = client.post("/api/v1/users", json={"username": "grace", "password": "p"}, headers=_auth())
    user_id = user_resp.json()["id"]
    from tools.api.persistence import ApiPersistence

    persistence = ApiPersistence(tmp_path / "reports")
    persistence.create_run(run_id="run-test2", request={"target": "10.0.0.50"}, preview={})
    ann_resp = client.post(
        "/api/v1/runs/run-test2/annotations",
        json={"body": "todo: retest", "user_id": user_id, "username": "grace"},
        headers=_auth(),
    )
    ann_id = ann_resp.json()["id"]
    del_resp = client.delete(f"/api/v1/annotations/{ann_id}", headers=_auth())
    assert del_resp.status_code == 204
    # Second delete → 404.
    del2 = client.delete(f"/api/v1/annotations/{ann_id}", headers=_auth())
    assert del2.status_code == 404


def test_annotation_unknown_run_404(tmp_path, monkeypatch):
    client = _make_multi_operator_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs/nonexistent/annotations",
        json={"body": "x", "user_id": "u1", "username": "x"},
        headers=_auth(),
    )
    assert resp.status_code == 404


# ── Legacy mode: multi_operator false → user routes NOT mounted ─────────────


def test_legacy_mode_user_routes_not_mounted(tmp_path, monkeypatch):
    """With ``api.multi_operator`` absent/false, user routes are not mounted."""
    client = _make_legacy_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/users", json={"username": "x", "password": "y"}, headers=_auth())
    # 404 = route not mounted (legacy mode).
    assert resp.status_code == 404


def test_legacy_mode_annotations_not_mounted(tmp_path, monkeypatch):
    client = _make_legacy_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/whatever/annotations", headers=_auth())
    assert resp.status_code == 404
