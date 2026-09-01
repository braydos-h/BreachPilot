"""Tests for RunManager multi-target concurrency + per-run allowlist scoping.

D3 (``api.max_concurrent_runs``): lifts the one-active-run limit to N concurrent
runs for authorized wide-scope assessments. The highest-risk safety property is
the per-run allowlist lock — Run A's target must NEVER appear in Run B's
allowlist, even when both are live. These tests verify:

1. With ``max_concurrent_runs: 1`` (default) the legacy 409-on-second-run
   behavior is preserved byte-for-byte.
2. With ``max_concurrent_runs > 1`` N runs coexist and the (N+1)th gets 409.
3. Per-run allowlist scoping: Run A's target is in Run A's allowlist and NOT in
   Run B's, and vice versa (no cross-run target leakage).
4. The legacy single-run path (``has_active`` / ``active``) is unchanged.
"""

from __future__ import annotations

import pytest

from tools.api.errors import APIError
from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunManager, _snapshot_allowlist
from tools.run_service.models import RunPreview, RunRequest


def _preview(run_id: str, target: str, tmp_path) -> RunPreview:
    return RunPreview(
        run_id=run_id,
        reports_dir=tmp_path / target,
        config_path=tmp_path / "config.yaml",
        target_ip=target,
        original_target=target,
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


class _FakeService:
    """Minimal AssessmentService stub that returns a deterministic preview."""

    def __init__(self, **kwargs):
        pass

    async def prepare(self, request, *, run_id=None, progress=None):
        # Use the target as the run_id so each run is distinguishable.
        return _preview(run_id or f"run-{request.target}", request.target, _tmp)


_tmp_path = None


@pytest.fixture(autouse=True)
def _capture_tmp(request):
    global _tmp
    _tmp = request.getfixturevalue("tmp_path")
    yield


def _make_manager(tmp_path, monkeypatch, *, max_concurrent_runs: int = 1):
    """Build a RunManager with a fake AssessmentService and given cap."""
    monkeypatch.setattr("tools.run_service.AssessmentService", _FakeService)
    persistence = ApiPersistence(tmp_path / "reports")
    config = {"api": {"max_concurrent_runs": max_concurrent_runs}}
    return RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config=config,
        config_path=tmp_path / "config.yaml",
    )


# ── Legacy single-run path (max_concurrent_runs == 1) ────────────────────────


@pytest.mark.asyncio
async def test_default_cap_is_one(tmp_path, monkeypatch):
    """``api.max_concurrent_runs`` defaults to 1 (legacy behavior)."""
    manager = _make_manager(tmp_path, monkeypatch)
    assert manager.max_concurrent_runs == 1


@pytest.mark.asyncio
async def test_second_run_409_when_cap_is_one(tmp_path, monkeypatch):
    """With cap=1, a second create_run while one is live raises 409."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=1)
    await manager.create_run(RunRequest(target="10.0.0.50"))
    with pytest.raises(APIError) as exc:
        await manager.create_run(RunRequest(target="10.0.0.51"))
    assert exc.value.status_code == 409
    await manager.cancel_run(manager.active.run_id)


@pytest.mark.asyncio
async def test_legacy_has_active_and_active(tmp_path, monkeypatch):
    """``has_active`` / ``active`` still work with cap=1 (legacy compat)."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=1)
    assert manager.has_active is False
    assert manager.active is None
    run_id, _preview, _decision = await manager.create_run(RunRequest(target="10.0.0.50"))
    assert manager.has_active is True
    assert manager.active is not None
    assert manager.active.run_id == run_id
    await manager.cancel_run(manager.active.run_id)


# ── Multi-run path (max_concurrent_runs > 1) ─────────────────────────────────


@pytest.mark.asyncio
async def test_cap_two_allows_two_runs(tmp_path, monkeypatch):
    """With cap=2, two runs coexist and a third gets 409."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=2)
    await manager.create_run(RunRequest(target="10.0.0.50"))
    await manager.create_run(RunRequest(target="10.0.0.51"))
    assert len(manager.active_run_ids) == 2
    with pytest.raises(APIError) as exc:
        await manager.create_run(RunRequest(target="10.0.0.52"))
    assert exc.value.status_code == 409
    # Cancel both.
    for rid in manager.active_run_ids:
        await manager.cancel_run(rid)


@pytest.mark.asyncio
async def test_per_run_allowlist_scoping_no_cross_leak(tmp_path, monkeypatch):
    """Run A's target is in Run A's allowlist and NOT in Run B's, and vice versa.

    This is the highest-risk D3 safety property: the allowlist IS the lock, and
    each concurrent run must carry its own allowlist snapshot so Run A's target
    never leaks into Run B's MCP subprocess scope.
    """
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=3)
    run_a, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    run_b, _, _ = await manager.create_run(RunRequest(target="10.0.0.51"))
    # The allowlist snapshot is frozen at prepare() time — wait for the
    # background preparation to settle before asserting on it.
    await manager.wait_for_prepared(run_a)
    await manager.wait_for_prepared(run_b)

    handle_a = manager.active_for(run_a)
    handle_b = manager.active_for(run_b)
    assert handle_a is not None and handle_b is not None

    # Run A's target is in its own allowlist.
    assert "10.0.0.50" in handle_a.allowlist
    # Run B's target is NOT in Run A's allowlist (no cross-leak).
    assert "10.0.0.51" not in handle_a.allowlist

    # And vice versa.
    assert "10.0.0.51" in handle_b.allowlist
    assert "10.0.0.50" not in handle_b.allowlist

    for rid in manager.active_run_ids:
        await manager.cancel_run(rid)


@pytest.mark.asyncio
async def test_snapshot_allowlist_unions_config_targets(tmp_path):
    """``_snapshot_allowlist`` unions config ``exploit.allowed_targets`` + target."""
    config = {"exploit": {"allowed_targets": ["127.0.0.1", "10.0.0.99"]}}
    snap = _snapshot_allowlist(config, "10.0.0.50")
    assert "127.0.0.1" in snap
    assert "10.0.0.99" in snap
    assert "10.0.0.50" in snap


@pytest.mark.asyncio
async def test_snapshot_allowlist_no_duplicate(tmp_path):
    """If the target is already in config allowed_targets, no duplicate."""
    config = {"exploit": {"allowed_targets": ["10.0.0.50"]}}
    snap = _snapshot_allowlist(config, "10.0.0.50")
    assert snap.count("10.0.0.50") == 1


@pytest.mark.asyncio
async def test_cancel_removes_from_active(tmp_path, monkeypatch):
    """Cancelling a run removes it from the active dict (slot frees up)."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=2)
    run_a, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    run_b, _, _ = await manager.create_run(RunRequest(target="10.0.0.51"))
    assert len(manager.active_run_ids) == 2
    await manager.cancel_run(run_a)
    assert run_a not in manager.active_run_ids
    assert len(manager.active_run_ids) == 1
    # The freed slot now accepts a new run.
    await manager.create_run(RunRequest(target="10.0.0.52"))
    assert len(manager.active_run_ids) == 2
    for rid in list(manager.active_run_ids):
        await manager.cancel_run(rid)


@pytest.mark.asyncio
async def test_zero_or_negative_cap_clamps_to_one(tmp_path, monkeypatch):
    """A non-positive ``max_concurrent_runs`` falls back to 1 (legacy)."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=0)
    assert manager.max_concurrent_runs == 1
    manager2 = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=-5)
    assert manager2.max_concurrent_runs == 1


@pytest.mark.asyncio
async def test_concurrent_create_run_ids_differ(tmp_path, monkeypatch):
    """Two concurrent runs get distinct run_ids (no collision)."""
    manager = _make_manager(tmp_path, monkeypatch, max_concurrent_runs=2)
    await manager.create_run(RunRequest(target="10.0.0.50"))
    await manager.create_run(RunRequest(target="10.0.0.51"))
    ids = manager.active_run_ids
    assert len(set(ids)) == 2
    for rid in ids:
        await manager.cancel_run(rid)
