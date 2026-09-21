"""p2-09: bounded campaign x module x agent x model retries."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tools.campaign import batch as batch_mod
from tools.campaign.state import AttackPhase, AttackState, AttackTask, RetryEngine, TaskStatus


def test_exhausted_strategy_returns_last_params_verbatim():
    last_ssh = {"timeout": 20, "threads": 16, "wordlist": "large", "aggressive": True}
    assert RetryEngine.get_retry_parameters("SSHBruteForce", 3) == last_ssh
    assert RetryEngine.get_retry_parameters("SSHBruteForce", 100) == last_ssh
    last_default = {"timeout": 120, "retries": 3, "aggressive": True}
    assert RetryEngine.get_retry_parameters("NoSuchModule", 99) == last_default
    # In-table attempts still return their own row (defensive copies).
    first = RetryEngine.get_retry_parameters("SSHBruteForce", 0)
    assert first == {"timeout": 10, "threads": 4}
    first["timeout"] = 9999
    assert RetryEngine.get_retry_parameters("SSHBruteForce", 0)["timeout"] == 10


def test_should_retry_permanent_and_budget():
    # Permanent classes never retry, even on first attempt.
    assert RetryEngine.should_retry("SQLInjection", "scope-blocked: denied", 0, 3) is False
    assert RetryEngine.should_retry("SQLInjection", "VULN_NOT_CONFIRMED", 0, 3) is False
    assert RetryEngine.should_retry("SQLInjection", "nmap: command not installed", 0, 3) is False
    # attempt >= max_attempts never retries.
    assert RetryEngine.should_retry("SQLInjection", "timeout", 3, 3) is False
    assert RetryEngine.should_retry("SQLInjection", "timeout", 10, 3) is False
    # Transient errors retry while budget remains.
    assert RetryEngine.should_retry("SQLInjection", "timeout", 0, 3) is True
    assert RetryEngine.should_retry("SQLInjection", "timeout", 2, 3) is True


def test_backoff_jitter_cap():
    for attempt in range(0, 12):
        delay = RetryEngine.compute_backoff(attempt)
        assert 0.0 <= delay <= 60.0
    # Huge attempts pin at the cap instead of exploding.
    assert RetryEngine.compute_backoff(100) <= 60.0
    assert RetryEngine.compute_backoff(100) >= 59.0
    # Small attempts stay near 2^attempt (+ up to 1s jitter).
    assert 1.0 <= RetryEngine.compute_backoff(0) <= 2.0
    assert 2.0 <= RetryEngine.compute_backoff(1) <= 3.0


def test_rate_limit_hook():
    RetryEngine.register_model_rate_limit_hook(None)
    try:
        assert RetryEngine.rate_limit_delay("") == 0.0
        assert RetryEngine.rate_limit_delay("gpt-x") == 0.0
        RetryEngine.record_rate_limited("gpt-x")
        RetryEngine.record_rate_limited("gpt-x")
        assert RetryEngine.rate_limit_delay("gpt-x") == pytest.approx(10.0)
        assert RetryEngine.rate_limit_delay("other-model") == 0.0
        RetryEngine.register_model_rate_limit_hook(lambda _model: 30.0)
        assert RetryEngine.rate_limit_delay("anything") == pytest.approx(30.0)
    finally:
        RetryEngine.register_model_rate_limit_hook(None)
        RetryEngine._MODEL_RATE_LIMIT_HITS.clear()


class _FakeExecutor:
    def __init__(self, error: str = "boom timeout") -> None:
        self.calls = 0
        self.error = error

    async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]:
        self.calls += 1
        task.status = TaskStatus.FAILED
        task.error = self.error
        return {"success": False, "error": self.error}


class _FakeOrchestrator:
    """Minimal surface tools/campaign/batch.py needs (no campaign import)."""

    def __init__(self, *, budget: int = 0, error: str = "boom timeout") -> None:
        self._max_campaign_retries = budget
        self._campaign_retries_used = 0
        self._mission: dict[str, Any] = {}
        self._tasks: dict[str, AttackTask] = {}
        self._executor = _FakeExecutor(error)

    def _maybe_schedule_prereq(self, task: AttackTask, state: AttackState, error: str) -> AttackTask | None:
        return None


def _make_task(**overrides: Any) -> AttackTask:
    kwargs: dict[str, Any] = {
        "task_id": "ATK-00001",
        "phase": AttackPhase.EXPLOITATION,
        "module_name": "SQLInjection",
        "target": "10.0.0.50",
        "max_retries": 2,
    }
    kwargs.update(overrides)
    return AttackTask(**kwargs)


@pytest.mark.asyncio
async def test_batch_stops_after_max_retries(monkeypatch):
    sleeps: list[float] = []

    async def _no_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    fake = _FakeOrchestrator(budget=0)  # unbounded campaign budget
    state = AttackState(target="10.0.0.50")
    task = _make_task(max_retries=2)
    await batch_mod._execute_task_batch(fake, [task], state)
    assert fake._executor.calls == 3  # initial + 2 retries, then stop
    assert task.retry_count == 2
    assert task.status == TaskStatus.FAILED
    assert len(sleeps) == 2
    assert all(0.0 <= d <= 60.0 for d in sleeps)
    # Retry accounting persisted + progress events emitted.
    assert task.last_error == "boom timeout"
    assert state.last_error == "boom timeout"
    assert state.total_retries == 2
    assert [e["event_type"] for e in state.timeline if e["event_type"] == "retry"].__len__() == 2


@pytest.mark.asyncio
async def test_batch_blocks_when_campaign_budget_spent(monkeypatch):
    sleeps: list[float] = []

    async def _no_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    fake = _FakeOrchestrator(budget=1)  # one campaign retry total
    state = AttackState(target="10.0.0.50")
    task = _make_task(max_retries=5)
    await batch_mod._execute_task_batch(fake, [task], state)
    assert fake._campaign_retries_used == 1
    assert task.retry_count == 1
    assert task.status == TaskStatus.BLOCKED
    assert "budget" in task.error
    assert len(sleeps) == 1
    assert any(e["event_type"] == "retry_budget_exhausted" for e in state.timeline)


@pytest.mark.asyncio
async def test_batch_honors_model_rate_limit_delay(monkeypatch):
    sleeps: list[float] = []

    async def _no_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    RetryEngine.register_model_rate_limit_hook(lambda _model: 30.0)
    try:
        fake = _FakeOrchestrator(budget=0)
        state = AttackState(target="10.0.0.50")
        task = _make_task(max_retries=1)
        await batch_mod._execute_task_batch(fake, [task], state)
        assert task.retry_count == 1
        assert sleeps and sleeps[0] >= 30.0
    finally:
        RetryEngine.register_model_rate_limit_hook(None)


@pytest.mark.asyncio
async def test_batch_never_retries_permanent_failure(monkeypatch):
    async def _no_sleep(delay: float) -> None:
        raise AssertionError("must not sleep when no retry happens")

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    fake = _FakeOrchestrator(budget=0, error="scope-blocked: denied by allowlist")
    state = AttackState(target="10.0.0.50")
    task = _make_task(max_retries=3)
    await batch_mod._execute_task_batch(fake, [task], state)
    assert fake._executor.calls == 1
    assert task.retry_count == 0
    assert fake._campaign_retries_used == 0


def test_retry_accounting_round_trips():
    task = _make_task()
    task.retry_count = 2
    task.last_error = "boom"
    task.failure_class = "timeout"
    back = AttackTask.from_dict(task.to_dict())
    assert (back.retry_count, back.last_error, back.failure_class) == (2, "boom", "timeout")
    state = AttackState(target="10.0.0.50")
    state.total_retries = 3
    state.last_error = "boom"
    back_state = AttackState.from_dict(state.to_dict())
    assert (back_state.total_retries, back_state.last_error) == (3, "boom")
