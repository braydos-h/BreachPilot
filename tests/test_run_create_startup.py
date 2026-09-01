"""Run-creation startup tests: bounded DNS, prepare timings/progress, and the
asynchronous ``preparing`` lifecycle introduced so POST /runs returns fast.

Covers:
- ``resolve_target_bounded`` never hangs on DNS (TimeoutError instead).
- ``prepare`` reports per-stage timings + emits progress stages.
- Warm preparation is fast (regression guard for the 3.9s router rebuild).
- RunManager: create returns immediately in ``preparing``; preparation
  failures mark the run failed with an actionable error; cancellation during
  preparation settles correctly; confirmation during preparation conflicts.
- Persistence recovery covers the ``preparing`` state.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.api.errors import APIError
from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunManager
from tools.run_service.models import RunPreview, RunRequest
from tools.validation_utils import resolve_target_bounded

# ── Bounded DNS resolution ───────────────────────────────────────────────────


def test_resolve_target_bounded_ip_literal_skips_dns():
    ip, domain = resolve_target_bounded("127.0.0.1", timeout_seconds=5.0)
    assert ip == "127.0.0.1"
    assert domain is None


def test_resolve_target_bounded_resolves_domain():
    ip, domain = resolve_target_bounded("example.test", timeout_seconds=2.0, resolver_fn=lambda host: ["93.184.216.34"])
    assert ip == "93.184.216.34"
    assert domain == "example.test"


def test_resolve_target_bounded_times_out_instead_of_hanging():
    """A stalled resolver must raise TimeoutError within the budget, never
    block run creation for minutes."""

    def _slow_resolver(host):
        time.sleep(5.0)
        return ["93.184.216.34"]

    start = time.perf_counter()
    with pytest.raises(TimeoutError):
        resolve_target_bounded("slow.test", timeout_seconds=0.2, resolver_fn=_slow_resolver)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"timeout took {elapsed:.2f}s — DNS was not bounded"


def test_resolve_target_bounded_invalid_host():
    assert resolve_target_bounded("not a domain", timeout_seconds=1.0) == (None, None)
    assert resolve_target_bounded("", timeout_seconds=1.0) == (None, None)


def test_prepare_maps_dns_timeout_to_actionable_error(tmp_path, monkeypatch):
    """A DNS timeout during preparation surfaces an actionable ValueError."""
    import tools.validation_utils as vu
    from tools.run_service.service import AssessmentService

    def _timeout(host, **kw):
        raise TimeoutError("DNS resolution timed out after 5s for unreachable.invalid")

    monkeypatch.setattr(vu, "resolve_target_bounded", _timeout)

    service = AssessmentService(config={})
    request = RunRequest(target="unreachable.invalid", mode="recon")
    request.config_path = tmp_path / "config.yaml"
    request.reports_dir = tmp_path / "reports"

    async def _run():
        with pytest.raises(ValueError, match="Could not resolve target"):
            await service.prepare(request)

    asyncio.run(_run())


# ── Prepare: stage timings + progress + warm speed ───────────────────────────


class _FakeRouter:
    _clients = {"glm": MagicMock()}

    def get_client(self, name):
        return self._clients[name]


def _make_service(tmp_path, monkeypatch) -> object:
    from tools.run_service.service import AssessmentService, Callables

    callables = Callables(build_router=lambda *a, **kw: _FakeRouter())
    return AssessmentService(config={}, callables=callables)


def _request(tmp_path, **kw) -> RunRequest:
    request = RunRequest(target="127.0.0.1", mode="attack", goal_name="recon_only", **kw)
    request.config_path = tmp_path / "config.yaml"
    request.reports_dir = tmp_path / "reports"
    return request


EXPECTED_STAGES = {
    "config",
    "plugins",
    "router",
    "model",
    "target_validate",
    "target_resolve",
    "goals",
    "exploit_settings",
    "skills",
    "filesystem",
}


def test_prepare_reports_stage_timings(tmp_path, monkeypatch):
    service = _make_service(tmp_path, monkeypatch)
    preview = asyncio.run(service.prepare(_request(tmp_path), run_id="t-timing"))
    assert set(preview.timings) == EXPECTED_STAGES
    assert all(isinstance(v, (int, float)) and v >= 0 for v in preview.timings.values())
    assert sum(preview.timings.values()) > 0


def test_prepare_emits_progress_stages(tmp_path, monkeypatch):
    service = _make_service(tmp_path, monkeypatch)
    stages: list[str] = []
    asyncio.run(service.prepare(_request(tmp_path), run_id="t-progress", progress=lambda s, m: stages.append(s)))
    assert stages == [
        "config",
        "plugins",
        "router",
        "model",
        "target_validate",
        "target_resolve",
        "goals",
        "exploit_settings",
        "skills",
        "filesystem",
    ]


def test_prepare_progress_survives_a_raising_callback(tmp_path, monkeypatch):
    service = _make_service(tmp_path, monkeypatch)

    def _bad(_stage, _msg):
        raise RuntimeError("progress consumer exploded")

    preview = asyncio.run(service.prepare(_request(tmp_path), run_id="t-badcb", progress=_bad))
    assert preview.run_id == "t-badcb"


def test_warm_prepare_is_fast(tmp_path, monkeypatch):
    """Regression guard: warm preparation must stay well under 1s.

    The original bug: every run creation re-built the model router (~3.9s of
    SSL-context + YAML parsing on Windows) and re-scanned plugins. Cached,
    the warm path should be tens of milliseconds.
    """
    service = _make_service(tmp_path, monkeypatch)
    asyncio.run(service.prepare(_request(tmp_path), run_id="perf-cold"))  # warm the caches
    start = time.perf_counter()
    preview = asyncio.run(service.prepare(_request(tmp_path), run_id="perf-warm"))
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"warm prepare took {elapsed:.2f}s — a cold-start cost leaked back in"
    assert sum(preview.timings.values()) < 1000.0


def test_prepare_uses_caller_supplied_run_id(tmp_path, monkeypatch):
    service = _make_service(tmp_path, monkeypatch)
    preview = asyncio.run(service.prepare(_request(tmp_path), run_id="20260101_000000_000001"))
    assert preview.run_id == "20260101_000000_000001"
    assert preview.reports_dir == tmp_path / "reports" / "20260101_000000_000001"


# ── RunManager: asynchronous preparing lifecycle ─────────────────────────────


class _SlowService:
    """AssessmentService stub with controllable preparation latency."""

    def __init__(self, **kwargs):
        pass

    async def prepare(self, request, *, run_id=None, progress=None):
        await asyncio.sleep(0.5)
        return _preview_for(run_id or f"run-{request.target}", request)


def _preview_for(run_id: str, request: RunRequest) -> RunPreview:
    return RunPreview(
        run_id=run_id,
        reports_dir=Path("reports") / run_id,
        config_path=Path("config.yaml"),
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


def _manager(tmp_path, monkeypatch, service_cls, config=None) -> RunManager:
    monkeypatch.setattr("tools.run_service.AssessmentService", service_cls)
    persistence = ApiPersistence(tmp_path / "reports")
    return RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config=config or {},
        config_path=tmp_path / "config.yaml",
    )


@pytest.mark.asyncio
async def test_create_run_returns_immediately_in_preparing_state(tmp_path, monkeypatch):
    """POST-equivalent create_run returns before preparation finishes; the run
    row is already persisted as ``preparing``."""
    manager = _manager(tmp_path, monkeypatch, _SlowService)
    start = time.perf_counter()
    run_id, preview, decision = await manager.create_run(RunRequest(target="10.0.0.50"))
    elapsed = time.perf_counter() - start

    assert preview is None and decision is None
    # Returned well before the 0.5s fake preparation finished.
    assert elapsed < 0.4, f"create_run blocked {elapsed:.2f}s on preparation"
    row = manager._persistence.get_run(run_id)
    assert row is not None
    assert row["state"] == "preparing"
    assert manager.has_active is True

    await manager.cancel_run(run_id)


@pytest.mark.asyncio
async def test_preparation_completes_to_awaiting_confirmation(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _SlowService)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    handle = await manager.wait_for_prepared(run_id)
    assert handle.preview is not None
    assert handle.preview.target_ip == "10.0.0.50"
    row = manager._persistence.get_run(run_id)
    assert row["state"] == "awaiting_confirmation"
    assert row["preview_json"].get("target_ip") == "10.0.0.50"
    # Allowlist snapshot frozen at prepare time.
    assert "10.0.0.50" in handle.allowlist
    await manager.cancel_run(run_id)


@pytest.mark.asyncio
async def test_preparation_failure_marks_failed_with_actionable_error(tmp_path, monkeypatch):
    class _FailingService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request, *, run_id=None, progress=None):
            raise ValueError("Could not resolve domain: nonexistent.invalid")

    manager = _manager(tmp_path, monkeypatch, _FailingService)
    run_id, _, _ = await manager.create_run(RunRequest(target="nonexistent.invalid"))
    with pytest.raises((TimeoutError, APIError)):
        await manager.wait_for_prepared(run_id)
    row = manager._persistence.get_run(run_id)
    assert row["state"] == "failed"
    assert "Could not resolve domain" in row["error"]
    assert manager.active_for(run_id) is None


@pytest.mark.asyncio
async def test_internal_preparation_error_is_sanitized(tmp_path, monkeypatch):
    class _ExplodingService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request, *, run_id=None, progress=None):
            raise RuntimeError("internal detail: sekret-token=abc123")

    manager = _manager(tmp_path, monkeypatch, _ExplodingService)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    for _ in range(100):
        row = manager._persistence.get_run(run_id)
        if row["state"] == "failed":
            break
        await asyncio.sleep(0.02)
    row = manager._persistence.get_run(run_id)
    assert row["state"] == "failed"
    assert "sekret-token" not in row["error"]
    assert "Run preparation failed" in row["error"]


@pytest.mark.asyncio
async def test_cancel_during_preparation_marks_cancelled(tmp_path, monkeypatch):
    class _HangingService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request, *, run_id=None, progress=None):
            await asyncio.sleep(30.0)
            return _preview_for(run_id or f"run-{request.target}", request)

    manager = _manager(tmp_path, monkeypatch, _HangingService)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    assert (manager._persistence.get_run(run_id) or {}).get("state") == "preparing"
    await manager.cancel_run(run_id)
    row = manager._persistence.get_run(run_id)
    assert row["state"] == "cancelled"
    assert manager.active_for(run_id) is None


@pytest.mark.asyncio
async def test_confirm_during_preparation_conflicts(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _SlowService)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    with pytest.raises(APIError) as exc:
        await manager.confirm_and_start(run_id, "no-decision-yet", "yes")
    assert exc.value.status_code == 409
    await manager.cancel_run(run_id)


@pytest.mark.asyncio
async def test_yes_run_starts_after_preparation(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _SlowService, config={"api": {"max_concurrent_runs": 1}})
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50", yes=True))
    # Execute starts via _execute_run; the fake has no session, so the run
    # will land in failed — what matters is it left preparing via queued.
    for _ in range(200):
        row = manager._persistence.get_run(run_id)
        if row and row["state"] != "preparing":
            break
        await asyncio.sleep(0.02)
    row = manager._persistence.get_run(run_id)
    assert row["state"] in {"queued", "running", "failed"}


@pytest.mark.asyncio
async def test_shutdown_cancels_in_flight_preparation(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _SlowService)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50"))
    await manager.shutdown()
    assert manager.active_for(run_id) is None


# ── Persistence: preparing recovery ──────────────────────────────────────────


def test_recover_interrupted_covers_preparing_state(tmp_path):
    """A daemon restart during preparation must not leave a zombie ``preparing`` run."""
    persistence = ApiPersistence(tmp_path / "reports")
    persistence.create_run(run_id="r-prep", request={}, preview={}, state="preparing")
    persistence.recover_interrupted()
    assert persistence.get_run("r-prep")["state"] == "interrupted"


def test_get_active_run_includes_preparing(tmp_path):
    persistence = ApiPersistence(tmp_path / "reports")
    persistence.create_run(run_id="r-prep", request={}, preview={}, state="preparing")
    active = persistence.get_active_run()
    assert active is not None
    assert active["id"] == "r-prep"
