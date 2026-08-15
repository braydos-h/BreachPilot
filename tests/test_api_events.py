"""Tests for the event broker: ordering, sequence IDs, replay, persistence."""

from __future__ import annotations

import asyncio
import json

import pytest

from tools.api.event_broker import EventBrokerRegistry, RunEventBroker


@pytest.fixture
def broker(tmp_path):
    run_id = "test-run-001"
    reports_dir = tmp_path / "reports" / run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    return RunEventBroker(run_id, reports_dir, buffer_size=64)


def test_event_sequence_monotonic(broker):
    """Events get monotonically increasing sequence IDs."""
    async def _run():
        e1 = await broker.emit("state", {"v": 1})
        e2 = await broker.emit("state", {"v": 2})
        e3 = await broker.emit("progress", {"round": 1})
        assert e1["sequence"] == 1
        assert e2["sequence"] == 2
        assert e3["sequence"] == 3
        assert e1["run_id"] == "test-run-001"
        assert e1["type"] == "state"
    asyncio.run(_run())


def test_event_jsonl_persisted(broker):
    """Events are written to events.jsonl."""
    async def _run():
        await broker.emit("state", {"v": 1})
        await broker.emit("progress", {"round": 1})
        broker.close()
        events_path = broker._events_path
        assert events_path.exists()
        lines = events_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        e1 = json.loads(lines[0])
        assert e1["sequence"] == 1
        assert e1["type"] == "state"
    asyncio.run(_run())


def test_event_replay_cursor(broker):
    """Replay returns events with sequence > after."""
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        events = await broker.replay(after=2)
        assert len(events) == 3  # seq 3, 4, 5
        assert events[0]["sequence"] == 3
    asyncio.run(_run())


def test_event_ring_buffer_bounded(tmp_path):
    """The in-memory ring buffer is bounded to buffer_size."""
    run_id = "test-bounded"
    reports_dir = tmp_path / "reports" / run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    broker = RunEventBroker(run_id, reports_dir, buffer_size=3)

    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        assert len(broker._ring) == 3  # only last 3 retained
    asyncio.run(_run())


def test_event_sanitize_secrets(broker):
    """Events are sanitized — secret-looking keys are redacted."""
    async def _run():
        e = await broker.emit("test", {"api_key": "secret123", "normal": "ok"})
        assert e["payload"]["api_key"] == "[REDACTED]"
        assert e["payload"]["normal"] == "ok"
    asyncio.run(_run())


def test_registry_get_or_create(tmp_path):
    """EventBrokerRegistry creates one broker per run_id."""
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32)
    b1 = registry.get_or_create("run-1")
    b2 = registry.get_or_create("run-1")
    assert b1 is b2
    b3 = registry.get_or_create("run-2")
    assert b3 is not b1


def test_concurrent_event_order_matches_jsonl(broker):
    async def _run():
        await asyncio.gather(*(
            broker.emit("progress", {"i": i}) for i in range(20)
        ))
        replayed = await broker.replay()
        assert [event["sequence"] for event in replayed] == list(range(1, 21))
        persisted = [
            json.loads(line)["sequence"]
            for line in broker._events_path.read_text(encoding="utf-8").splitlines()
        ]
        assert persisted == list(range(1, 21))

    asyncio.run(_run())


def test_subscription_is_async_iterable_and_closes(broker):
    async def _run():
        await broker.emit("state", {"state": "running"})
        subscription = await broker.subscribe()
        assert (await anext(subscription))["sequence"] == 1
        broker.close()
        with pytest.raises(StopAsyncIteration):
            await anext(subscription)

    asyncio.run(_run())


def test_replay_page_tail(broker):
    """replay_page(tail=N) returns the newest N events ascending + metadata."""
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(tail=2)
        assert [e["sequence"] for e in page["events"]] == [4, 5]
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 5
        assert page["has_more_before"] is False  # oldest is seq 1

    asyncio.run(_run())


def test_replay_page_before_limit(broker):
    """replay_page(before=X, limit=N) pages older events newest-first."""
    async def _run():
        for i in range(10):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(before=8, limit=3)
        assert [e["sequence"] for e in page["events"]] == [7, 6, 5]
        assert page["has_more_before"] is True  # seq 1-4 still older
        assert page["latest_sequence"] == 10

    asyncio.run(_run())


def test_replay_page_before_limit_exhausted(broker):
    """When the page reaches the oldest event, has_more_before is False."""
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(before=6, limit=10)
        assert [e["sequence"] for e in page["events"]] == [5, 4, 3, 2, 1]
        assert page["has_more_before"] is False

    asyncio.run(_run())


def test_replay_page_after_metadata(broker):
    """replay_page(after=X) keeps ascending order and reports full-set bounds."""
    async def _run():
        for i in range(3):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(after=1)
        assert [e["sequence"] for e in page["events"]] == [2, 3]
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 3
        assert page["has_more_before"] is False

    asyncio.run(_run())


def test_replay_page_empty(broker):
    """An empty broker yields empty events and None bounds."""
    async def _run():
        page = await broker.replay_page(tail=5)
        assert page["events"] == []
        assert page["oldest_sequence"] is None
        assert page["latest_sequence"] is None
        assert page["has_more_before"] is False

    asyncio.run(_run())


def test_registry_lru_evicts_oldest(tmp_path):
    """EventBrokerRegistry evicts the least-recently-used broker past max_brokers."""
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32, max_brokers=2)
    registry.get_or_create("run-1")
    registry.get_or_create("run-2")
    assert len(registry._brokers) == 2
    registry.get_or_create("run-3")  # evicts run-1 (LRU)
    assert len(registry._brokers) == 2
    assert registry.get("run-1") is None
    assert registry.get("run-2") is not None
    assert registry.get("run-3") is not None


def test_registry_lru_touch_moves_to_mru(tmp_path):
    """Accessing an existing broker refreshes its recency."""
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32, max_brokers=2)
    registry.get_or_create("run-1")
    registry.get_or_create("run-2")
    registry.get_or_create("run-1")  # touch run-1 -> now MRU
    registry.get_or_create("run-3")  # evicts run-2 (now LRU)
    assert registry.get("run-1") is not None
    assert registry.get("run-2") is None
    assert registry.get("run-3") is not None
