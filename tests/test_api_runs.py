"""Tests for API run lifecycle: create, confirm, cancel, 409, list, get."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token-0123456789abcdef01234567"):
    """Create a TestClient with a known token + minimal config (no Ollama needed)."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    # Write a minimal config so prepare() doesn't need Ollama.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    # Build fake Callables with a mock router so prepare() doesn't hit Ollama.
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
    # Use TestClient as a context manager to ensure lifespan (warmup + demo seed) runs correctly.
    # Without `with`, the async lifespan isn't entered and background prepare tasks get cancelled.
    client = TestClient(app)
    client.__enter__()
    return client


def _auth_headers(token="test-token-0123456789abcdef01234567"):
    return {"Authorization": f"Bearer {token}"}


def _wait_state(client, run_id: str, states: set[str], attempts: int = 100) -> dict:
    """Poll until the run reaches one of ``states`` (background preparation)."""
    import time

    last: dict = {}
    for _ in range(attempts):
        run = client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).json()
        last = run
        if run.get("state") in states:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} never reached {states} (last state: {last.get('state')})")


def _wait_decision(client, run_id: str, attempts: int = 100) -> dict:
    """Poll until background preparation creates the pending start_confirm decision."""
    import time

    last: list[dict] = []
    for _ in range(attempts):
        resp = client.get(f"/api/v1/runs/{run_id}/decisions", headers=_auth_headers())
        assert resp.status_code == 200
        last = resp.json()["decisions"]
        for row in last:
            if row["kind"] == "start_confirm" and row["status"] == "pending":
                return row
        time.sleep(0.02)
    raise AssertionError(f"no pending start_confirm decision for {run_id} (got {last})")


def test_create_run_returns_preview(tmp_path, monkeypatch):
    """POST /runs returns immediately (state preparing); preparation completes
    in the background and fills the preview + start_confirm decision."""
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "run_id" in data
    assert data["state"] == "preparing"
    assert data["preview"] is None
    assert "decision" not in data

    run = _wait_state(client, data["run_id"], {"awaiting_confirmation"})
    assert run["preview"]["target_ip"] == "10.0.0.50"
    decision = _wait_decision(client, data["run_id"])
    assert decision["kind"] == "start_confirm"


def test_list_runs(tmp_path, monkeypatch):
    """GET /runs returns run history."""
    client = _make_client(tmp_path, monkeypatch)
    # Create a run first.
    client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    resp = client.get("/api/v1/runs", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["runs"]) >= 1


def test_get_run_not_found(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/nonexistent", headers=_auth_headers())
    assert resp.status_code == 404


def test_get_run_after_create(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    run_id = create_resp.json()["run_id"]
    run = _wait_state(client, run_id, {"awaiting_confirmation"})
    assert run["id"] == run_id
    assert run["state"] == "awaiting_confirmation"


def test_get_artifact_enhanced_missing_returns_404_not_500(tmp_path, monkeypatch):
    """A run that never produced an enhanced report has no ``enhanced/`` dir.
    GET /artifacts/enhanced/<file> must return a clean 404, not a 500 from
    FileNotFoundError on ``(run_dir / "enhanced").iterdir()`` (regression guard
    for the WinError 3 trace seen in the --web log)."""
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert create_resp.status_code == 201
    run_id = create_resp.json()["run_id"]
    resp = client.get(
        f"/api/v1/runs/{run_id}/artifacts/enhanced/enhanced_report.json",
        headers=_auth_headers(),
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["error"]["message"] == "Artifact not found"


def test_second_run_returns_409(tmp_path, monkeypatch):
    """One active run at a time — a second returns 409."""
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
    resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.51",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 409


def test_cancel_run(tmp_path, monkeypatch):
    """POST /runs/{id}/cancel transitions to cancelled."""
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    run_id = create_resp.json()["run_id"]
    resp = client.post(f"/api/v1/runs/{run_id}/cancel", headers=_auth_headers())
    assert resp.status_code == 200


def test_events_replay(tmp_path, monkeypatch):
    """GET /runs/{id}/events?after=0 replays events."""
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    run_id = create_resp.json()["run_id"]
    resp = client.get(f"/api/v1/runs/{run_id}/events?after=0", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data


def test_decisions_list(tmp_path, monkeypatch):
    """GET /runs/{id}/decisions lists pending decisions (after preparation)."""
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    run_id = create_resp.json()["run_id"]
    _wait_state(client, run_id, {"awaiting_confirmation"})
    resp = client.get(f"/api/v1/runs/{run_id}/decisions", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "decisions" in data
    assert len(data["decisions"]) >= 1


def test_answer_decision_wrong_confirmation(tmp_path, monkeypatch):
    """Destructive start_confirm requires exact ALLOW <target> text."""
    client = _make_client(tmp_path, monkeypatch)
    create_resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    run_id = create_resp.json()["run_id"]
    _wait_state(client, run_id, {"awaiting_confirmation"})
    decision_id = _wait_decision(client, run_id)["id"]
    resp = client.post(
        f"/api/v1/runs/{run_id}/decisions/{decision_id}",
        json={"answer": "wrong text"},
        headers=_auth_headers(),
    )
    assert resp.status_code == 400


def test_answer_start_confirmation_schedules_execution(tmp_path, monkeypatch):
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
    _wait_state(client, created["run_id"], {"awaiting_confirmation"})
    decision_id = _wait_decision(client, created["run_id"])["id"]
    response = client.post(
        f"/api/v1/runs/{created['run_id']}/decisions/{decision_id}",
        json={"answer": "yes"},
        headers=_auth_headers(),
    )
    assert response.status_code == 200
    run = _wait_state(client, created["run_id"], {"queued", "running", "completed"})
    assert run["state"] != "awaiting_confirmation"


def test_yes_starts_without_a_decision(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    response = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
            "yes": True,
        },
        headers=_auth_headers(),
    )
    assert response.status_code == 201
    assert response.json()["state"] == "preparing"
    assert "decision" not in response.json()
    # yes=true still queues correctly once preparation completes.
    run = _wait_state(client, response.json()["run_id"], {"queued", "running", "completed"})
    assert run["state"] in {"queued", "running", "completed"}


def test_cancel_before_start_releases_active_slot(tmp_path, monkeypatch):
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
    cancelled = client.post(
        f"/api/v1/runs/{created['run_id']}/cancel",
        headers=_auth_headers(),
    )
    assert cancelled.status_code == 200
    run = client.get(
        f"/api/v1/runs/{created['run_id']}",
        headers=_auth_headers(),
    ).json()
    assert run["state"] == "cancelled"
    assert run["cancelled_at"]
    second = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.51",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert second.status_code == 201


def test_resume_persists_parent_and_request_flags(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    original = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
            "critic": True,
        },
        headers=_auth_headers(),
    ).json()
    client.post(
        f"/api/v1/runs/{original['run_id']}/cancel",
        headers=_auth_headers(),
    )
    resumed = client.post(
        f"/api/v1/runs/{original['run_id']}/resume",
        headers=_auth_headers(),
    )
    assert resumed.status_code == 200
    run = client.get(
        f"/api/v1/runs/{resumed.json()['run_id']}",
        headers=_auth_headers(),
    ).json()
    assert run["resumed_from"] == original["run_id"]
    assert run["request"]["critic"] is True


def test_concurrent_create_keeps_one_active_run(tmp_path, monkeypatch):
    from tools.api.errors import APIError
    from tools.api.event_broker import EventBrokerRegistry
    from tools.api.persistence import ApiPersistence
    from tools.api.run_manager import RunManager
    from tools.run_service.models import RunPreview, RunRequest

    class FakeService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request, *, run_id=None, progress=None):
            await asyncio.sleep(0.01)
            return RunPreview(
                run_id=f"run-{request.target}",
                reports_dir=tmp_path / request.target,
                config_path=tmp_path / "config.yaml",
                target_ip=request.target,
                original_target=request.target,
                resolved_ip=None,
                resolved_domain=None,
                mode="attack",
                goal_name="recon_only",
                goal_description="test",
                model_alias="glm",
                model_label="glm",
                transport_summary="http",
                permission="read_only",
                attack_mode=True,
                swarm=False,
                parallel_swarm=False,
                multi_model=False,
                destructive=False,
                required_confirmation_text="",
            )

    monkeypatch.setattr("tools.run_service.AssessmentService", FakeService)
    persistence = ApiPersistence(tmp_path / "reports")
    manager = RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config={},
        config_path=tmp_path / "config.yaml",
    )

    async def _run():
        results = await asyncio.gather(
            manager.create_run(RunRequest(target="10.0.0.50")),
            manager.create_run(RunRequest(target="10.0.0.51")),
            return_exceptions=True,
        )
        assert sum(isinstance(result, APIError) for result in results) == 1
        assert manager.has_active is True
        assert manager.active.request.config_path == tmp_path / "config.yaml"
        assert manager.active.request.reports_dir == tmp_path / "reports"
        await manager.cancel_run(manager.active.run_id)

    asyncio.run(_run())


def test_prepare_raise_marks_failed_and_error_event(tmp_path, monkeypatch):
    """prepare() raising (e.g. DNS) must mark the run failed with an error event."""
    client = _make_client(tmp_path, monkeypatch)

    class _Boom:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, *args, **kwargs):
            raise ValueError("Could not resolve domain: nonexistent.invalid")

    monkeypatch.setattr("tools.run_service.AssessmentService", _Boom)
    run_id = client.post(
        "/api/v1/runs",
        json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"},
        headers=_auth_headers(),
    ).json()["run_id"]
    run = _wait_state(client, run_id, {"failed"})
    assert "Could not resolve" in (run.get("error") or "")
    events = client.get(f"/api/v1/runs/{run_id}/events?after=0", headers=_auth_headers()).json()["events"]
    assert any(e["type"] == "error" for e in events)


def test_run_session_raise_marks_failed_and_error_event(tmp_path, monkeypatch):
    """A failing _fake_run_session must mark the run failed with an error event."""
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
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    async def _boom_session(**kwargs):
        raise RuntimeError("session exploded")

    callables = Callables(
        build_router=lambda *a, **kw: _FakeRouter(),
        run_session=_boom_session,
    )
    from app import create_app

    app = create_app(config_path=config_path, callables=callables)
    client = TestClient(app)
    client.__enter__()
    run_id = client.post(
        "/api/v1/runs",
        json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"},
        headers=_auth_headers(),
    ).json()["run_id"]
    _wait_state(client, run_id, {"awaiting_confirmation"})
    decision_id = _wait_decision(client, run_id)["id"]
    resp = client.post(
        f"/api/v1/runs/{run_id}/decisions/{decision_id}",
        json={"answer": "yes"},
        headers=_auth_headers(),
    )
    assert resp.status_code == 200
    run = _wait_state(client, run_id, {"failed", "completed"})
    assert run["state"] == "failed"
    events = client.get(f"/api/v1/runs/{run_id}/events?after=0", headers=_auth_headers()).json()["events"]
    assert any(e["type"] == "error" for e in events)
