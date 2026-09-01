"""Tests that the bounded webhook/event-broker dispatcher never blocks the loop.

These tests prove the architecture goals:

* slow webhook subscriber does not materially delay ``await broker.emit(...)``
* blocking subscriber does not block other coroutines (via ``asyncio.to_thread``)
* retry sleeps do not block the loop
* subscriber exceptions are isolated
* emit persistence order is preserved despite slow subscriber
* concurrency is bounded to ``max_workers``
* single worker preserves serial execution
* queue-full drops deterministically and logs
* successful webhook delivery via broker
* webhook retry still bounded via broker
* webhook retry succeeds on second attempt
* shutdown drain_timeout=0 discards pending
* shutdown bounded drain logs on timeout
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tools.api.event_broker import (
    RunEventBroker,
    _PluginEventDispatcher,
    _reset_plugin_dispatcher,
    _set_plugin_dispatcher,
    shutdown_plugin_dispatcher,
    wait_for_plugin_dispatcher_empty,
)
from tools.plugins import PluginRegistry


def _fresh_registry(monkeypatch) -> PluginRegistry:
    reg = PluginRegistry()
    monkeypatch.setattr("tools.plugins.PLUGIN_REGISTRY", reg)
    return reg


async def _drain(timeout: float = 2.0) -> bool:
    return await wait_for_plugin_dispatcher_empty(timeout=timeout)


@pytest.fixture(autouse=True)
def _clean_dispatcher():
    _reset_plugin_dispatcher()
    yield
    _reset_plugin_dispatcher()


def test_emit_does_not_block_on_slow_subscriber(tmp_path: Path, monkeypatch):
    """``emit()`` returns quickly even when subscriber sleeps 0.4 s."""
    reg = _fresh_registry(monkeypatch)
    calls: list[float] = []

    def slow(event: dict[str, Any]) -> None:
        calls.append(time.monotonic())
        time.sleep(0.4)
        calls.append(time.monotonic())

    reg.register_event_subscriber(slow)
    broker = RunEventBroker("run-slow", tmp_path / "slow" / "run-slow", buffer_size=8)

    async def _run() -> None:
        start = time.monotonic()
        await broker.emit("finding", {"v": 1})
        elapsed = time.monotonic() - start
        assert elapsed < 0.25, f"emit blocked {elapsed:.3f}s"
        assert await _drain(2.0)
        assert len(calls) == 2

    asyncio.run(_run())


def test_blocking_subscriber_does_not_block_other_coroutine(tmp_path: Path, monkeypatch):
    """Blocking subscriber must not stall a concurrent coroutine."""
    reg = _fresh_registry(monkeypatch)

    def blocker(event: dict[str, Any]) -> None:
        time.sleep(0.4)

    reg.register_event_subscriber(blocker)
    broker = RunEventBroker("run-block", tmp_path / "block" / "run-block", buffer_size=8)

    async def _run() -> None:
        await broker.emit("finding", {"v": 1})
        other_done = False

        async def other() -> None:
            nonlocal other_done
            await asyncio.sleep(0.05)
            other_done = True

        start = time.monotonic()
        await asyncio.gather(other(), broker.emit("finding", {"v": 2}))
        assert other_done
        assert time.monotonic() - start < 0.35
        assert await _drain(2.0)

    asyncio.run(_run())


def test_retry_sleeps_do_not_block_loop(tmp_path: Path, monkeypatch):
    """Webhook backoff ``time.sleep`` must run off-thread."""
    reg = _fresh_registry(monkeypatch)

    def retrying(event: dict[str, Any]) -> None:
        for _ in range(3):
            time.sleep(0.12)

    reg.register_event_subscriber(retrying)
    broker = RunEventBroker("run-retry-sleep", tmp_path / "retry-sleep" / "run-retry-sleep", buffer_size=8)

    async def _run() -> None:
        ticked: list[int] = []

        async def ticker() -> None:
            for _ in range(5):
                await asyncio.sleep(0.05)
                ticked.append(1)

        start = time.monotonic()
        await broker.emit("finding", {"v": 1})
        await asyncio.gather(ticker(), _drain(2.0))
        assert len(ticked) == 5
        assert time.monotonic() - start < 1.5

    asyncio.run(_run())


def test_subscriber_exception_does_not_propagate(tmp_path: Path, monkeypatch):
    """Subscriber exception must not propagate to emit or siblings."""
    reg = _fresh_registry(monkeypatch)
    good: list[dict[str, Any]] = []

    def bad(event: dict[str, Any]) -> None:
        raise RuntimeError("boom")

    reg.register_event_subscriber(bad)
    reg.register_event_subscriber(good.append)
    broker = RunEventBroker("run-exc", tmp_path / "exc" / "run-exc", buffer_size=8)

    async def _run() -> None:
        evt = await broker.emit("finding", {"v": 1})
        assert evt["type"] == "finding"
        assert await _drain(2.0)
        assert len(good) == 1
        await broker.emit("finding", {"v": 2})
        assert await _drain(2.0)
        assert len(good) == 2

    asyncio.run(_run())


def test_emit_persistence_order_preserved_despite_slow_subscriber(tmp_path: Path, monkeypatch):
    """JSONL persistence order stays monotonic despite slow dispatch."""
    reg = _fresh_registry(monkeypatch)

    def slow(event: dict[str, Any]) -> None:
        time.sleep(0.12)

    reg.register_event_subscriber(slow)
    broker = RunEventBroker("run-order", tmp_path / "order" / "run-order", buffer_size=16)

    async def _run() -> None:
        for i in range(5):
            await broker.emit("finding", {"i": i})
        assert await _drain(3.0)
        events = await broker.replay(after=0)
        assert [e["payload"]["i"] for e in events] == list(range(5))
        assert [e["sequence"] for e in events] == [1, 2, 3, 4, 5]
        path = tmp_path / "order" / "run-order" / "events.jsonl"
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        assert [e["sequence"] for e in lines] == [1, 2, 3, 4, 5]

    asyncio.run(_run())


def test_concurrency_is_bounded(tmp_path: Path, monkeypatch):
    """At most ``max_workers`` subscribers run concurrently."""
    reg = _fresh_registry(monkeypatch)
    concurrent = {"cur": 0, "peak": 0}

    def counting(event: dict[str, Any]) -> None:
        concurrent["cur"] += 1
        concurrent["peak"] = max(concurrent["peak"], concurrent["cur"])
        time.sleep(0.12)
        concurrent["cur"] -= 1

    reg.register_event_subscriber(counting)
    disp = _PluginEventDispatcher(max_queue_size=20, max_workers=2)
    _set_plugin_dispatcher(disp)
    broker = RunEventBroker("run-conc", tmp_path / "conc" / "run-conc", buffer_size=32)

    async def _run() -> None:
        for i in range(6):
            await broker.emit("finding", {"i": i})
        assert await _drain(5.0)
        assert concurrent["peak"] <= 2, f"peak {concurrent['peak']} exceeded 2"

    asyncio.run(_run())


def test_single_worker_preserves_serial_execution(tmp_path: Path, monkeypatch):
    """With ``max_workers=1`` events are dispatched serially."""
    reg = _fresh_registry(monkeypatch)
    seen: list[int] = []

    def collector(event: dict[str, Any]) -> None:
        seen.append(event["sequence"])
        time.sleep(0.04)

    reg.register_event_subscriber(collector)
    disp = _PluginEventDispatcher(max_queue_size=20, max_workers=1)
    _set_plugin_dispatcher(disp)
    broker = RunEventBroker("run-serial", tmp_path / "serial" / "run-serial", buffer_size=16)

    async def _run() -> None:
        for i in range(5):
            await broker.emit("finding", {"i": i})
        assert await _drain(3.0)
        assert seen == [1, 2, 3, 4, 5]

    asyncio.run(_run())


def test_queue_full_drops_deterministically_and_logs(tmp_path: Path, monkeypatch, caplog):
    """Queue-full must drop deterministically and log WARNING."""
    reg = _fresh_registry(monkeypatch)

    def slow(event: dict[str, Any]) -> None:
        time.sleep(0.2)

    reg.register_event_subscriber(slow)
    disp = _PluginEventDispatcher(max_queue_size=2, max_workers=1)
    _set_plugin_dispatcher(disp)
    broker = RunEventBroker("run-full", tmp_path / "full" / "run-full", buffer_size=8)

    async def _run() -> None:
        await broker.emit("finding", {"seq": 1})
        await asyncio.sleep(0.08)
        await broker.emit("finding", {"seq": 2})
        await broker.emit("finding", {"seq": 3})
        with caplog.at_level(logging.WARNING):
            await broker.emit("finding", {"seq": 99})
            await asyncio.sleep(0.15)
        events = await broker.replay(after=0)
        assert len(events) == 4
        await shutdown_plugin_dispatcher(drain_timeout=1.0)

    asyncio.run(_run())
    assert disp.dropped >= 1 or any("queue full" in r.message for r in caplog.records)


def test_successful_webhook_delivery_via_broker(tmp_path: Path, monkeypatch):
    """Webhook plugin delivers successfully via the bounded dispatcher."""
    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    cfg = {
        "webhook_notify": {
            "enabled": True,
            "url": "https://hooks.example.com/x",
            "events": ["finding"],
            "max_retries": 1,
            "backoff_seconds": 0.01,
        }
    }

    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    plugin = WebhookNotifyPlugin(config_loader=lambda: cfg)
    reg = _fresh_registry(monkeypatch)
    plugin.register(reg)
    broker = RunEventBroker("run-wh-ok", tmp_path / "wh-ok" / "run-wh-ok", buffer_size=8)

    async def _run() -> None:
        posts: list[Any] = []
        with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp())[1]):
            await broker.emit("finding", {"hello": "world"})
            assert await _drain(2.0)
            assert len(posts) == 1
            sent = json.loads(posts[0].data.decode())
            assert sent["type"] == "finding"

    asyncio.run(_run())


def test_webhook_retry_still_bounded_via_broker(tmp_path: Path, monkeypatch):
    """Webhook retry loop stays bounded/off-thread, emit stays fast."""
    import urllib.error

    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    cfg = {
        "webhook_notify": {
            "enabled": True,
            "url": "https://hooks.example.com/x",
            "events": ["finding"],
            "max_retries": 3,
            "backoff_seconds": 0.05,
        }
    }
    plugin = WebhookNotifyPlugin(config_loader=lambda: cfg)
    reg = _fresh_registry(monkeypatch)
    plugin.register(reg)
    broker = RunEventBroker("run-wh-retry", tmp_path / "wh-retry" / "run-wh-retry", buffer_size=8)

    async def _run() -> None:
        calls = {"n": 0}

        def fail(req, timeout=None):
            calls["n"] += 1
            raise urllib.error.URLError("down")

        with patch("urllib.request.urlopen", side_effect=fail):
            start = time.monotonic()
            await broker.emit("finding", {"v": 1})
            assert time.monotonic() - start < 0.25
            assert await _drain(3.0)
            assert calls["n"] == 3

    asyncio.run(_run())


def test_webhook_retry_succeeds_on_second_attempt(tmp_path: Path, monkeypatch):
    """Flaky webhook succeeds on second attempt after backoff."""
    import urllib.error

    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    cfg = {
        "webhook_notify": {
            "enabled": True,
            "url": "https://hooks.example.com/x",
            "events": ["finding"],
            "max_retries": 3,
            "backoff_seconds": 0.05,
        }
    }
    plugin = WebhookNotifyPlugin(config_loader=lambda: cfg)
    reg = _fresh_registry(monkeypatch)
    plugin.register(reg)
    broker = RunEventBroker("run-wh-flaky", tmp_path / "wh-flaky" / "run-wh-flaky", buffer_size=8)

    async def _run() -> None:
        calls = {"n": 0}

        class _FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def flaky(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.URLError("down")
            return _FakeResp()

        with patch("urllib.request.urlopen", side_effect=flaky):
            await broker.emit("finding", {"v": 1})
            assert await _drain(3.0)
            assert calls["n"] == 2

    asyncio.run(_run())


def test_shutdown_drain_timeout_zero_discards_pending(tmp_path: Path, monkeypatch, caplog):
    """``drain_timeout=0`` discards pending events without waiting."""
    reg = _fresh_registry(monkeypatch)

    def slow(event: dict[str, Any]) -> None:
        time.sleep(0.5)

    reg.register_event_subscriber(slow)
    disp = _PluginEventDispatcher(max_queue_size=10, max_workers=1)
    _set_plugin_dispatcher(disp)
    broker = RunEventBroker("run-zero", tmp_path / "zero" / "run-zero", buffer_size=8)

    async def _run() -> None:
        for i in range(3):
            await broker.emit("finding", {"i": i})
        await asyncio.sleep(0.05)
        with caplog.at_level(logging.WARNING):
            await shutdown_plugin_dispatcher(drain_timeout=0)
        assert disp.qsize == 0

    asyncio.run(_run())


def test_shutdown_bounded_drain_logs_on_timeout(tmp_path: Path, monkeypatch, caplog):
    """Bounded drain must time out, log WARNING, and discard remainder."""
    reg = _fresh_registry(monkeypatch)

    def slow(event: dict[str, Any]) -> None:
        time.sleep(0.6)

    reg.register_event_subscriber(slow)
    disp = _PluginEventDispatcher(max_queue_size=10, max_workers=1)
    _set_plugin_dispatcher(disp)
    broker = RunEventBroker("run-timeout", tmp_path / "timeout" / "run-timeout", buffer_size=8)

    async def _run() -> None:
        for i in range(3):
            await broker.emit("finding", {"i": i})
        with caplog.at_level(logging.WARNING):
            await shutdown_plugin_dispatcher(drain_timeout=0.1)
        assert disp.qsize == 0
        assert any("discard" in r.message.lower() or "timed out" in r.message.lower() for r in caplog.records)

    asyncio.run(_run())
