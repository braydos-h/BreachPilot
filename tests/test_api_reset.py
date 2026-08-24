"""Tests for POST /api/v1/system/reset (wipe all past work)."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    """Create a TestClient with a known token + minimal config (no Ollama needed)."""
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
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

    callables = Callables(
        build_router=_fake_build_router,
        run_session=_fake_run_session,
    )
    from app import create_app

    app = create_app(config_path=config_path, callables=callables)
    return TestClient(app)


def _auth_headers(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_reset_wipes_runs_and_workspaces(tmp_path, monkeypatch):
    """Reset deletes run history rows and the reports/exploit/research/swarm dirs."""
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    ).json()
    run_id = created["run_id"]
    client.post(f"/api/v1/runs/{run_id}/cancel", headers=_auth_headers())
    (tmp_path / "reports" / run_id).mkdir(parents=True, exist_ok=True)
    (tmp_path / "reports" / run_id / "session_summary.md").write_text("x", encoding="utf-8")
    (tmp_path / "exploit_workspace").mkdir(exist_ok=True)
    (tmp_path / "research_workspace").mkdir(exist_ok=True)
    (tmp_path / "swarm_workspace").mkdir(exist_ok=True)
    # Seed research.db with a mission row so the reset has data to clear.
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "research_workspace" / "research.db"))
    try:
        conn.execute("CREATE TABLE missions (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO missions VALUES ('M-0001')")
        conn.commit()
    finally:
        conn.close()

    resp = client.post("/api/v1/system/reset", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["runs_deleted"] >= 1

    assert not (tmp_path / "reports" / run_id).exists()
    assert not (tmp_path / "exploit_workspace").exists()
    assert not (tmp_path / "swarm_workspace").exists()
    assert data["research_cleared"] is True
    rw = tmp_path / "research_workspace"
    assert rw.exists()
    # research.db (+ its WAL/SHM journal files) stays — the Flow B singleton
    # holds it open — but all mission data is gone.
    assert not any(p.name.startswith("M-") for p in rw.iterdir())
    import sqlite3

    conn = sqlite3.connect(str(rw / "research.db"))
    try:
        n = conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0]
        assert n == 0
    finally:
        conn.close()

    listed = client.get("/api/v1/runs", headers=_auth_headers()).json()
    assert listed["total"] == 0


def test_reset_refuses_while_run_active(tmp_path, monkeypatch):
    """An active (awaiting_confirmation) run blocks the reset with 409."""
    client = _make_client(tmp_path, monkeypatch)
    client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    resp = client.post("/api/v1/system/reset", headers=_auth_headers())
    assert resp.status_code == 409
    assert "active" in resp.json()["error"]["message"]
