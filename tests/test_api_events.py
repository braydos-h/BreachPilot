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
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        events = await broker.replay(after=2)
        assert len(events) == 3
        assert events[0]["sequence"] == 3

    asyncio.run(_run())


def test_event_ring_buffer_bounded(tmp_path):
    run_id = "test-bounded"
    reports_dir = tmp_path / "reports" / run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    broker = RunEventBroker(run_id, reports_dir, buffer_size=3)

    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        assert len(broker._ring) == 3

    asyncio.run(_run())


def test_event_sanitize_secrets(broker):
    async def _run():
        e = await broker.emit("test", {"api_key": "secret123", "normal": "ok"})
        assert e["payload"]["api_key"] == "[REDACTED]"
        assert e["payload"]["normal"] == "ok"

    asyncio.run(_run())


def test_registry_get_or_create(tmp_path):
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32)
    b1 = registry.get_or_create("run-1")
    b2 = registry.get_or_create("run-1")
    assert b1 is b2
    b3 = registry.get_or_create("run-2")
    assert b3 is not b1


def test_concurrent_event_order_matches_jsonl(broker):
    async def _run():
        await asyncio.gather(*(broker.emit("progress", {"i": i}) for i in range(20)))
        replayed = await broker.replay()
        assert [event["sequence"] for event in replayed] == list(range(1, 21))
        persisted = [
            json.loads(line)["sequence"] for line in broker._events_path.read_text(encoding="utf-8").splitlines()
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
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(tail=2)
        assert [e["sequence"] for e in page["events"]] == [4, 5]
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 5
        assert page["has_more_before"] is True
        assert page["omitted_before"] == 3
        assert page["first_returned_sequence"] == 4
        assert page["last_returned_sequence"] == 5
        assert page["next_before"] == 4

    asyncio.run(_run())


def test_replay_page_tail_larger_than_history(broker):
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(tail=10)
        assert [e["sequence"] for e in page["events"]] == [1, 2, 3, 4, 5]
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 5
        assert page["has_more_before"] is False
        assert page["omitted_before"] == 0
        assert page["first_returned_sequence"] == 1
        assert page["last_returned_sequence"] == 5
        assert page["next_before"] is None

    asyncio.run(_run())


def test_replay_page_tail_exactly_equal(broker):
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(tail=5)
        assert [e["sequence"] for e in page["events"]] == [1, 2, 3, 4, 5]
        assert page["has_more_before"] is False
        assert page["omitted_before"] == 0
        assert page["first_returned_sequence"] == 1
        assert page["last_returned_sequence"] == 5
        assert page["next_before"] is None

    asyncio.run(_run())


def test_replay_page_before_limit(broker):
    async def _run():
        for i in range(10):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(before=8, limit=3)
        assert [e["sequence"] for e in page["events"]] == [7, 6, 5]
        assert page["has_more_before"] is True
        assert page["omitted_before"] == 4
        assert page["first_returned_sequence"] == 5
        assert page["last_returned_sequence"] == 7
        assert page["next_before"] == 5
        assert page["latest_sequence"] == 10
        assert page["oldest_sequence"] == 1

    asyncio.run(_run())


def test_replay_page_before_limit_exhausted(broker):
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(before=6, limit=10)
        assert [e["sequence"] for e in page["events"]] == [5, 4, 3, 2, 1]
        assert page["has_more_before"] is False
        assert page["omitted_before"] == 0
        assert page["first_returned_sequence"] == 1
        assert page["last_returned_sequence"] == 5
        assert page["next_before"] is None

    asyncio.run(_run())


def test_replay_page_before_limit_partial_then_exhausted(broker):
    async def _run():
        for i in range(10):
            await broker.emit("state", {"i": i})
        p1 = await broker.replay_page(before=11, limit=4)
        assert [e["sequence"] for e in p1["events"]] == [10, 9, 8, 7]
        assert p1["has_more_before"] is True
        assert p1["omitted_before"] == 6
        assert p1["next_before"] == 7
        p2 = await broker.replay_page(before=p1["next_before"], limit=4)
        assert [e["sequence"] for e in p2["events"]] == [6, 5, 4, 3]
        assert p2["has_more_before"] is True
        assert p2["omitted_before"] == 2
        assert p2["next_before"] == 3
        p3 = await broker.replay_page(before=p2["next_before"], limit=4)
        assert [e["sequence"] for e in p3["events"]] == [2, 1]
        assert p3["has_more_before"] is False
        assert p3["omitted_before"] == 0
        assert p3["next_before"] is None

    asyncio.run(_run())


def test_replay_page_after_metadata(broker):
    async def _run():
        for i in range(3):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(after=1)
        assert [e["sequence"] for e in page["events"]] == [2, 3]
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 3
        assert page["has_more_before"] is False
        assert page["first_returned_sequence"] == 2
        assert page["last_returned_sequence"] == 3
        assert page["omitted_before"] == 0
        assert page["next_before"] is None

    asyncio.run(_run())


def test_replay_page_empty(broker):
    async def _run():
        page = await broker.replay_page(tail=5)
        assert page["events"] == []
        assert page["oldest_sequence"] is None
        assert page["latest_sequence"] is None
        assert page["has_more_before"] is False
        assert page["omitted_before"] == 0
        assert page["first_returned_sequence"] is None
        assert page["last_returned_sequence"] is None
        assert page["next_before"] is None
        page2 = await broker.replay_page(before=5, limit=2)
        assert page2["events"] == []
        assert page2["has_more_before"] is False
        assert page2["omitted_before"] == 0
        page3 = await broker.replay_page(after=0)
        assert page3["events"] == []
        assert page3["has_more_before"] is False

    asyncio.run(_run())


def test_replay_page_large_history_tail(broker):
    async def _run():
        for i in range(5000):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(tail=1000)
        assert len(page["events"]) == 1000
        assert [e["sequence"] for e in page["events"]][:3] == [4001, 4002, 4003]
        assert [e["sequence"] for e in page["events"]][-1] == 5000
        assert page["oldest_sequence"] == 1
        assert page["latest_sequence"] == 5000
        assert page["first_returned_sequence"] == 4001
        assert page["last_returned_sequence"] == 5000
        assert page["has_more_before"] is True
        assert page["omitted_before"] == 4000
        assert page["next_before"] == 4001
        page_full = await broker.replay_page(tail=6000)
        assert len(page_full["events"]) == 5000
        assert page_full["has_more_before"] is False
        assert page_full["omitted_before"] == 0

    asyncio.run(_run())


def test_replay_page_before_without_limit(broker):
    async def _run():
        for i in range(5):
            await broker.emit("state", {"i": i})
        page = await broker.replay_page(before=4)
        assert [e["sequence"] for e in page["events"]] == [3, 2, 1]
        assert page["has_more_before"] is False
        assert page["omitted_before"] == 0
        assert page["first_returned_sequence"] == 1
        assert page["last_returned_sequence"] == 3
        page2 = await broker.replay_page(before=4, limit=2)
        assert [e["sequence"] for e in page2["events"]] == [3, 2]
        assert page2["has_more_before"] is True
        assert page2["omitted_before"] == 1
        assert page2["next_before"] == 2

    asyncio.run(_run())


def test_registry_lru_evicts_oldest(tmp_path):
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32, max_brokers=2)
    registry.get_or_create("run-1")
    registry.get_or_create("run-2")
    assert len(registry._brokers) == 2
    registry.get_or_create("run-3")
    assert len(registry._brokers) == 2
    assert registry.get("run-1") is None
    assert registry.get("run-2") is not None
    assert registry.get("run-3") is not None


def test_registry_lru_touch_moves_to_mru(tmp_path):
    registry = EventBrokerRegistry(tmp_path / "reports", buffer_size=32, max_brokers=2)
    registry.get_or_create("run-1")
    registry.get_or_create("run-2")
    registry.get_or_create("run-1")
    registry.get_or_create("run-3")
    assert registry.get("run-1") is not None
    assert registry.get("run-2") is None
    assert registry.get("run-3") is not None
