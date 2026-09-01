"""Tests for built-in demo session seeding."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n  graph_route: true\n",
        encoding="utf-8",
    )
    from unittest.mock import MagicMock

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
    return app, config_path


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_demo_seeded_fresh(tmp_path, monkeypatch):
    from tools.api.demo_seed import DEMO_RUN_ID, DEMO_TITLE
    from tools.api.persistence import ApiPersistence
    from tools.api.demo_seed import ensure_demo_seed

    p = ApiPersistence(tmp_path / "reports")
    assert p.get_run(DEMO_RUN_ID) is None
    created = ensure_demo_seed(p, tmp_path / "reports")
    assert created is True
    run = p.get_run(DEMO_RUN_ID)
    assert run is not None
    assert run["is_demo"] == 1
    assert run["title"] == DEMO_TITLE
    assert run["state"] == "completed"
    # preview/request carry marker
    assert run["preview_json"].get("is_demo") is True
    assert run["request_json"].get("is_demo") is True
    # artifacts
    assert (tmp_path / "reports" / DEMO_RUN_ID / "recon_assessment.json").exists()
    assert (tmp_path / "reports" / DEMO_RUN_ID / "enhanced" / "enhanced_report.json").exists()
    assert (tmp_path / "reports" / DEMO_RUN_ID / "exploit_audit.jsonl").exists()
    assert (tmp_path / "reports" / DEMO_RUN_ID / "events.jsonl").exists()


def test_demo_seed_idempotent(tmp_path, monkeypatch):
    from tools.api.demo_seed import DEMO_RUN_ID, ensure_demo_seed
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path / "reports")
    assert ensure_demo_seed(p, tmp_path / "reports") is True
    assert ensure_demo_seed(p, tmp_path / "reports") is False
    assert ensure_demo_seed(p, tmp_path / "reports") is False
    runs = p.list_runs(limit=100)
    demo = [r for r in runs if r["id"] == DEMO_RUN_ID]
    assert len(demo) == 1


def test_demo_tombstone_prevents_recreate(tmp_path, monkeypatch):
    from tools.api.demo_seed import DEMO_RUN_ID, ensure_demo_seed
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path / "reports")
    ensure_demo_seed(p, tmp_path / "reports")
    assert p.delete_run(DEMO_RUN_ID) is True
    assert p.is_demo_tombstoned() is True
    assert p.get_run(DEMO_RUN_ID) is None
    # ensure should NOT recreate
    assert ensure_demo_seed(p, tmp_path / "reports") is False
    assert p.get_run(DEMO_RUN_ID) is None


def test_demo_restore_clears_tombstone(tmp_path, monkeypatch):
    from tools.api.demo_seed import DEMO_RUN_ID, ensure_demo_seed, restore_demo
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path / "reports")
    ensure_demo_seed(p, tmp_path / "reports")
    p.delete_run(DEMO_RUN_ID)
    assert p.is_demo_tombstoned()
    restored = restore_demo(p, tmp_path / "reports")
    assert restored is True
    assert not p.is_demo_tombstoned()
    # after restore, demo exists and second restore is still idempotent
    assert p.get_run(DEMO_RUN_ID) is not None
    assert restore_demo(p, tmp_path / "reports") is True
    assert len([r for r in p.list_runs(limit=100) if r["id"] == DEMO_RUN_ID]) == 1


def test_demo_appears_via_api_and_graph(tmp_path, monkeypatch):
    app, _ = _make_client(tmp_path, monkeypatch)
    with TestClient(app) as client:
        runs = client.get("/api/v1/runs", headers=_auth()).json()
        assert runs["total"] >= 1
        demo = next(r for r in runs["runs"] if r["id"] == "demo-session-v1")
        assert demo["is_demo"] is True
        # fetch by id
        detail = client.get("/api/v1/runs/demo-session-v1", headers=_auth()).json()
        assert detail["is_demo"] is True
        assert detail["state"] == "completed"
        # graph
        graph = client.get("/api/v1/runs/demo-session-v1/graph", headers=_auth()).json()
        assert len(graph["nodes"]) >= 10
        assert len(graph["edges"]) >= 10
        # enhanced report artifact
        art = client.get("/api/v1/runs/demo-session-v1/artifacts/enhanced/enhanced_report.json", headers=_auth())
        assert art.status_code == 200
        report = art.json()
        assert len(report["technical_findings"]) == 18
        assert len(report["exploitation_chains"]) == 3
        assert len(report["attack_timeline"]) >= 10
        # severity breakdown
        from collections import Counter

        c = Counter(f["severity"] for f in report["technical_findings"])
        assert c["Critical"] == 3
        assert c["High"] == 6
        assert c["Medium"] == 5
        assert c["Low"] == 4
        # recon
        recon = client.get("/api/v1/runs/demo-session-v1/artifacts/recon_assessment.json", headers=_auth()).json()
        assert recon["overall_risk_score"] == 93
        assert len(recon["services"]) >= 3
        # events
        ev = client.get("/api/v1/runs/demo-session-v1/events?after=0", headers=_auth()).json()
        assert len(ev["events"]) >= 15
        # explorer graph
        explorer = client.get("/api/v1/graph/runs/demo-session-v1", headers=_auth()).json()
        assert len(explorer["nodes"]) >= 10


def test_demo_deletion_via_api_tombstone_and_recreate(tmp_path, monkeypatch):
    app, _ = _make_client(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # precondition demo exists
        assert any(r["id"] == "demo-session-v1" for r in client.get("/api/v1/runs", headers=_auth()).json()["runs"])
        # delete via API
        resp = client.delete("/api/v1/runs/demo-session-v1?purge=true", headers=_auth())
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True
        # disappears
        assert client.get("/api/v1/runs/demo-session-v1", headers=_auth()).status_code == 404
        assert not any(r["id"] == "demo-session-v1" for r in client.get("/api/v1/runs", headers=_auth()).json()["runs"])
        # restart must not recreate
        from app import create_app

        app2 = create_app(config_path=tmp_path / "config.yaml", callables=app.state if hasattr(app, "state") else None)
        # Need same callables fake router; easiest recreate via same helper
        app2, _ = _make_client(tmp_path, monkeypatch)
        with TestClient(app2) as client2:
            runs2 = client2.get("/api/v1/runs", headers=_auth()).json()
            assert not any(r["id"] == "demo-session-v1" for r in runs2["runs"])
            # restore explicitly
            rest = client2.post("/api/v1/runs/demo/restore", headers=_auth()).json()
            assert rest["run_id"] == "demo-session-v1"
            runs3 = client2.get("/api/v1/runs", headers=_auth()).json()
            assert any(r["id"] == "demo-session-v1" for r in runs3["runs"])


def test_demo_does_not_affect_real_runs(tmp_path, monkeypatch):
    app, _ = _make_client(tmp_path, monkeypatch)
    with TestClient(app) as client:
        demo_before = client.get("/api/v1/runs", headers=_auth()).json()["total"]
        # create a real run
        resp = client.post("/api/v1/runs", json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"}, headers=_auth())
        assert resp.status_code == 201
        real_id = resp.json()["run_id"]
        runs = client.get("/api/v1/runs", headers=_auth()).json()
        assert runs["total"] == demo_before + 1
        # delete demo
        client.delete("/api/v1/runs/demo-session-v1?purge=true", headers=_auth())
        runs2 = client.get("/api/v1/runs", headers=_auth()).json()
        assert any(r["id"] == real_id for r in runs2["runs"])
        assert not any(r["id"] == "demo-session-v1" for r in runs2["runs"])
        # real run still fetchable
        assert client.get(f"/api/v1/runs/{real_id}", headers=_auth()).status_code == 200


def test_is_demo_helper(tmp_path, monkeypatch):
    from tools.api.demo_seed import is_demo_run

    assert is_demo_run({"id": "demo-session-v1", "is_demo": 1}) is True
    assert is_demo_run({"id": "demo-session-v1"}) is True
    assert is_demo_run({"id": "other", "is_demo": 0}) is False
    assert is_demo_run(None) is False
