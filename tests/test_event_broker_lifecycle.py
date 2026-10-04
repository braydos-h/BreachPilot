"""Live run ownership and replay/live handoff regressions."""

from __future__ import annotations

import asyncio

from tools.api.event_broker import EventBrokerRegistry, RunEventBroker


async def test_archived_reads_preserve_owned_broker(tmp_path):
    registry = EventBrokerRegistry(tmp_path, max_brokers=2)
    live = registry.acquire("live")
    try:
        await live.emit("state", {"state": "running"})
        subscription = await live.subscribe(after=1)
        for index in range(12):
            await registry.get_or_create(f"archived-{index}").replay()

        assert registry.get("live") is live
        assert len(registry._brokers) == 3  # one owner plus two cached histories
        await live.emit("progress", {"round": 1})
        event = await asyncio.wait_for(anext(subscription), timeout=1)
        assert event["sequence"] == 2
        assert event["payload"] == {"round": 1}
        subscription.close()

        live.close()
        registry.release("live")
        assert len(registry._brokers) == 2
        assert registry.get("live") is None
    finally:
        registry.close_all()


def test_registry_preserves_broker_until_last_owner_releases(tmp_path):
    registry = EventBrokerRegistry(tmp_path, max_brokers=1)
    broker = registry.acquire("live")
    assert registry.acquire("live") is broker
    try:
        registry.get_or_create("archive-1")
        registry.release("live")
        registry.get_or_create("archive-2")
        assert registry.get("live") is broker
        assert not broker._closed

        registry.release("live")
        assert registry.get("live") is None
        assert broker._closed
    finally:
        registry.close_all()


async def test_recreated_evicted_broker_continues_persisted_sequence(tmp_path):
    registry = EventBrokerRegistry(tmp_path, max_brokers=1)
    subscription = None
    try:
        original = registry.acquire("run")
        await original.emit("state", {"state": "running"})
        await original.emit("progress", {"round": 1})
        last_sequence = 2

        registry.release("run")
        registry.get_or_create("archive")  # Evicts and closes the unowned run broker.
        assert registry.get("run") is None

        recreated = registry.get_or_create("run")
        subscription = await recreated.subscribe(after=last_sequence)
        await recreated.emit("progress", {"round": 2})

        event = await asyncio.wait_for(anext(subscription), timeout=1)
        assert event["sequence"] == last_sequence + 1
        assert event["payload"] == {"round": 2}
    finally:
        if subscription is not None:
            subscription.close()
        registry.close_all()


async def test_recreated_broker_reads_sequence_from_oversized_final_event(tmp_path):
    reports_dir = tmp_path / "run"
    reports_dir.mkdir()
    (reports_dir / "events.jsonl").write_text(
        '{"sequence":41,"type":"evidence","payload":{"text":"' + ("x" * 70_000) + '"}}\n',
        encoding="utf-8",
    )

    broker = RunEventBroker("run", reports_dir)
    subscription = None
    try:
        subscription = await broker.subscribe(after=41)
        event = await broker.emit("progress", {"round": 1})
        assert event["sequence"] == 42
        assert (await asyncio.wait_for(anext(subscription), timeout=1))["sequence"] == 42
    finally:
        if subscription is not None:
            subscription.close()
        broker.close()


async def test_subscription_does_not_duplicate_event_persisted_before_fanout(tmp_path, monkeypatch):
    broker = RunEventBroker("run", tmp_path)
    acknowledged = asyncio.Event()
    resume_emit = asyncio.Event()
    original_wait_for = asyncio.wait_for
    pause_first = True

    async def pause_acknowledgement(awaitable, timeout):
        nonlocal pause_first
        pause = pause_first
        pause_first = False
        value = await original_wait_for(awaitable, timeout=timeout)
        if pause:
            acknowledged.set()
            await resume_emit.wait()
        return value

    # Hold the first emitter after persistence, before subscriber fan-out.
    monkeypatch.setattr("tools.api.event_broker.asyncio.wait_for", pause_acknowledgement)
    emit_task = asyncio.create_task(broker.emit("state", {"state": "running"}))
    subscription = None
    try:
        await original_wait_for(acknowledged.wait(), timeout=1)
        subscription = await broker.subscribe()
        assert (await anext(subscription))["sequence"] == 1
        resume_emit.set()
        await original_wait_for(emit_task, timeout=1)
        await broker.emit("progress", {"round": 1})
        # The persisted event was already replayed; only the new event is live.
        assert (await original_wait_for(anext(subscription), timeout=1))["sequence"] == 2
        assert subscription._queue.empty()
    finally:
        resume_emit.set()
        if not emit_task.done():
            emit_task.cancel()
            await asyncio.gather(emit_task, return_exceptions=True)
        if subscription is not None:
            subscription.close()
        broker.close()


async def test_subscription_respects_cursor_ahead_of_current_history(tmp_path):
    broker = RunEventBroker("run", tmp_path)
    try:
        subscription = await broker.subscribe(after=2)
        await broker.emit("progress", {"round": 1})
        await broker.emit("progress", {"round": 2})
        await broker.emit("progress", {"round": 3})
        assert (await asyncio.wait_for(anext(subscription), timeout=1))["sequence"] == 3
        subscription.close()
    finally:
        broker.close()
