"""Tests for AI session titler and run-title persistence/sort.

Covers:
- ``tools.api.session_titler`` prompt building, response cleaning, and
  best-effort failure contract (never raises).
- ``ApiPersistence`` v2 migration (``title`` column added) and
  ``update_run_title`` + ``list_runs(sort=...)`` ordering.
- ``POST /runs/{id}/title`` route: explicit set, AI regen, 404, no-op.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from tools.api.persistence import ApiPersistence
from tools.api.session_titler import (
    _build_prompt,
    _clean_title,
    generate_session_title,
    generate_session_title_sync,
)

# ── Titler: prompt + cleaning ─────────────────────────────────────────────


def test_build_prompt_includes_core_fields():
    prompt = _build_prompt(
        {
            "target_ip": "10.0.0.50",
            "mode": "attack",
            "goal_name": "recon_only",
            "total_actions": 12,
            "outcome_summary": "Found 3 open ports: 22, 80, 443",
            "active_skills": [{"name": "nmap-advanced"}, {"name": "web-recon"}],
        },
        {"target": "10.0.0.50"},
    )
    assert "10.0.0.50" in prompt
    assert "recon_only" in prompt
    assert "12" in prompt
    assert "nmap-advanced" in prompt
    assert "Title:" in prompt


def test_build_prompt_caps_long_outcome():
    long_outcome = "a" * 5000
    prompt = _build_prompt(
        {"outcome_summary": long_outcome, "target_ip": "1.2.3.4"},
        {"target": "1.2.3.4"},
    )
    assert len(prompt) < 6000
    assert "a" in prompt  # still present, just clipped


def test_build_prompt_includes_error_when_present():
    prompt = _build_prompt(
        {"error": "Ollama unreachable", "target_ip": "1.2.3.4"},
        {"target": "1.2.3.4"},
    )
    assert "Ollama unreachable" in prompt


def test_clean_title_strips_prefix_quotes_and_trailing_punct():
    assert _clean_title("Title: Recon scan of 10.0.0.50") == "Recon scan of 10.0.0.50"
    assert _clean_title('"SMB exploit attempt"') == "SMB exploit attempt"
    assert _clean_title("**Failed SSH brute force**.") == "Failed SSH brute force"
    assert _clean_title("Multi-line\nsecond line") == "Multi-line"
    assert _clean_title("   ") == ""
    assert _clean_title(None) == ""


def test_clean_title_caps_at_60_chars():
    long = "A" * 80
    cleaned = _clean_title(long)
    assert len(cleaned) <= 60


# ── Titler: best-effort failures never raise ──────────────────────────────


def test_generate_sync_returns_empty_when_ollama_missing(monkeypatch):
    monkeypatch.setattr("tools.api.session_titler.OllamaClient", None)
    out = generate_session_title_sync({"target_ip": "1.2.3.4"}, {"target": "1.2.3.4"})
    assert out == ""


def test_generate_sync_swallows_client_error(monkeypatch):
    failing_client = MagicMock()
    failing_client.chat.side_effect = RuntimeError("network down")
    monkeypatch.setattr(
        "tools.api.session_titler.OllamaClient",
        lambda *a, **kw: failing_client,
    )
    out = generate_session_title_sync({"target_ip": "1.2.3.4"}, {"target": "1.2.3.4"})
    assert out == ""


def test_generate_sync_extracts_content_from_response(monkeypatch):
    fake_client = MagicMock()
    fake_client.chat.return_value = {"message": {"content": "Recon scan of 10.0.0.50"}}
    monkeypatch.setattr(
        "tools.api.session_titler.OllamaClient",
        lambda *a, **kw: fake_client,
    )
    out = generate_session_title_sync(
        {"target_ip": "10.0.0.50", "mode": "recon", "total_actions": 5},
        {"target": "10.0.0.50"},
    )
    assert out == "Recon scan of 10.0.0.50"
    # Verify the right model was used.
    args, kwargs = fake_client.chat.call_args
    assert kwargs["model"] == "gemma4:31b-cloud"


def test_generate_async_returns_empty_on_missing_pkg(monkeypatch):
    monkeypatch.setattr("tools.api.session_titler.OllamaClient", None)

    async def _run():
        return await generate_session_title({"target_ip": "1.2.3.4"}, {"target": "1.2.3.4"})

    assert asyncio.run(_run()) == ""


# ── Persistence: title column + sort ──────────────────────────────────────


def test_v2_migration_adds_title_column(tmp_path):
    """A fresh persistence gets the title column; get_run returns it as ""."""
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-1", request={"target": "10.0.0.50"}, preview={})
    run = p.get_run("r-1")
    assert "title" in run
    assert run["title"] == ""


def test_update_run_title_persists(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-2", request={}, preview={})
    assert p.update_run_title("r-2", "Recon scan of 10.0.0.50") is True
    assert p.get_run("r-2")["title"] == "Recon scan of 10.0.0.50"


def test_update_run_title_rejects_empty(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-3", request={}, preview={})
    assert p.update_run_title("r-3", "   ") is False
    assert p.get_run("r-3")["title"] == ""


def test_update_run_title_caps_at_200_chars(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-4", request={}, preview={})
    long = "X" * 300
    p.update_run_title("r-4", long)
    assert len(p.get_run("r-4")["title"]) == 200


def test_update_run_title_unknown_run(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    assert p.update_run_title("nonexistent", "whatever") is False


def test_list_runs_sort_by_title(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-a", request={}, preview={})
    p.create_run(run_id="r-b", request={}, preview={})
    p.create_run(run_id="r-c", request={}, preview={})
    p.update_run_title("r-a", "Zebra recon")
    p.update_run_title("r-b", "Alpha exploit")
    # r-c has no title (empty string)

    asc = [r["id"] for r in p.list_runs(sort="title_asc")]
    # Empty titles come first under ASC, then Alpha, then Zebra.
    assert asc[0] == "r-c"
    assert asc[1] == "r-b"
    assert asc[2] == "r-a"

    desc = [r["id"] for r in p.list_runs(sort="title_desc")]
    assert desc[0] == "r-a"
    assert desc[-1] == "r-c"


def test_list_runs_sort_by_created(tmp_path):
    import time

    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-old", request={}, preview={})
    time.sleep(0.01)
    p.create_run(run_id="r-new", request={}, preview={})

    desc = [r["id"] for r in p.list_runs(sort="created_desc")]
    assert desc == ["r-new", "r-old"]
    asc = [r["id"] for r in p.list_runs(sort="created_asc")]
    assert asc == ["r-old", "r-new"]


def test_list_runs_unknown_sort_falls_back(tmp_path):
    p = ApiPersistence(tmp_path / "reports")
    p.create_run(run_id="r-x", request={}, preview={})
    # Unknown sort value should not raise; falls back to created_desc.
    rows = p.list_runs(sort="bogus_value")
    assert len(rows) == 1
    assert rows[0]["id"] == "r-x"


# ── Route: POST /runs/{id}/title ──────────────────────────────────────────


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
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

    callables = Callables(
        build_router=lambda *a, **kw: _FakeRouter(),
        run_session=lambda **kw: {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""},
    )
    from app import create_app

    app = create_app(config_path=config_path, callables=callables)
    return TestClient(app)


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_set_title_explicit(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth(),
    ).json()
    resp = client.post(
        f"/api/v1/runs/{created['run_id']}/title",
        json={"title": "Manual title"},
        headers=_auth(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Manual title"
    # Verify it persisted.
    detail = client.get(f"/api/v1/runs/{created['run_id']}", headers=_auth()).json()
    assert detail["title"] == "Manual title"


def test_set_title_regen_uses_titler(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth(),
    ).json()
    with patch(
        "tools.api.session_titler.generate_session_title_sync",
        return_value="AI-generated title",
    ):
        resp = client.post(
            f"/api/v1/runs/{created['run_id']}/title",
            json={"regen": True},
            headers=_auth(),
        )
    assert resp.status_code == 200
    assert resp.json()["title"] == "AI-generated title"
    assert resp.json()["regenerated"] is True


def test_set_title_regen_falls_back_to_current_when_titler_empty(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth(),
    ).json()
    # Set an explicit title first.
    client.post(
        f"/api/v1/runs/{created['run_id']}/title",
        json={"title": "Existing"},
        headers=_auth(),
    )
    # Regen returns empty (simulating ollama unreachable).
    with patch(
        "tools.api.session_titler.generate_session_title_sync",
        return_value="",
    ):
        resp = client.post(
            f"/api/v1/runs/{created['run_id']}/title",
            json={"regen": True},
            headers=_auth(),
        )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Existing"
    assert resp.json()["regenerated"] is False


def test_set_title_404_for_unknown_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs/nonexistent/title",
        json={"title": "whatever"},
        headers=_auth(),
    )
    assert resp.status_code == 404


def test_list_runs_includes_title(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth(),
    ).json()
    client.post(
        f"/api/v1/runs/{created['run_id']}/title",
        json={"title": "My Recon Session"},
        headers=_auth(),
    )
    resp = client.get("/api/v1/runs", headers=_auth())
    runs = resp.json()["runs"]
    match = [r for r in runs if r["id"] == created["run_id"]][0]
    assert match["title"] == "My Recon Session"


def test_list_runs_returns_sort_key(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs?sort=title_asc", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["sort"] == "title_asc"


def test_list_runs_rejects_invalid_sort(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs?sort=bogus", headers=_auth())
    assert resp.status_code == 422
