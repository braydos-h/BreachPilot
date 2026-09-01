"""Tests for the webhook_notify plugin and the PluginRegistry event-subscriber hook.

Hermetic: no real network. The HTTP POST is intercepted by monkeypatching
``urllib.request.urlopen`` so no real request leaves the process. The plugin
is verified to be default-OFF (no manifest opt-in) and the event filter is
respected (a ``finding`` event triggers a POST; a ``heartbeat`` event does
not).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from tools.plugins import PluginRegistry

# ── PluginRegistry event-subscriber hook ──────────────────────────────────────


def test_registry_register_event_subscriber():
    reg = PluginRegistry()
    seen: list[dict[str, Any]] = []
    reg.register_event_subscriber(seen.append)
    assert reg.event_subscribers == [seen.append]
    reg.event_subscribers[0]({"type": "finding"})
    assert seen == [{"type": "finding"}]


def test_registry_register_event_subscriber_rejects_non_callable():
    reg = PluginRegistry()
    with pytest.raises(TypeError):
        reg.register_event_subscriber("not callable")  # type: ignore[arg-type]


def test_registry_reset_clears_subscribers():
    reg = PluginRegistry()
    reg.register_event_subscriber(lambda _e: None)
    assert reg.event_subscribers
    reg.reset()
    assert not reg.event_subscribers


# ── Plugin manifest is default-OFF ─────────────────────────────────────────────


def test_webhook_plugin_manifest_default_off():
    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    plugin = WebhookNotifyPlugin(config_loader=lambda: {})
    assert plugin.manifest.enabled is False
    assert "event_subscriber" in plugin.manifest.capabilities


def test_webhook_plugin_manifest_name():
    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    plugin = WebhookNotifyPlugin(config_loader=lambda: {})
    assert plugin.manifest.name == "webhook_notify"


# ── Subscriber behavior ──────────────────────────────────────────────────────


def _make_plugin(config: dict[str, Any]):
    from plugins.webhook_notify.plugin import WebhookNotifyPlugin

    return WebhookNotifyPlugin(config_loader=lambda: config)


class _FakeResp:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_finding_event_triggers_post_when_enabled():
    cfg = {"webhook_notify": {"enabled": True, "url": "https://hooks.example.com/x", "events": ["finding"]}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)
    assert len(reg.event_subscribers) == 1

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "finding", "payload": {"v": 1}})
    assert len(posts) == 1
    # payload is JSON-encoded event
    sent = json.loads(posts[0].data.decode("utf-8"))
    assert sent["type"] == "finding"


def test_heartbeat_event_not_sent_when_not_in_filter():
    cfg = {"webhook_notify": {"enabled": True, "url": "https://hooks.example.com/x", "events": ["finding"]}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "heartbeat", "payload": {}})
    assert posts == []


def test_disabled_no_post():
    cfg = {"webhook_notify": {"enabled": False, "url": "https://hooks.example.com/x", "events": ["finding"]}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "finding", "payload": {}})
    assert posts == []


def test_missing_url_noop():
    cfg = {"webhook_notify": {"enabled": True, "url": "", "events": ["finding"]}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "finding", "payload": {}})
    assert posts == []


def test_empty_event_filter_sends_nothing():
    cfg = {"webhook_notify": {"enabled": True, "url": "https://hooks.example.com/x", "events": []}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "finding", "payload": {}})
    assert posts == []


def test_payload_capped():
    big = "x" * 10000
    cfg = {
        "webhook_notify": {
            "enabled": True,
            "url": "https://hooks.example.com/x",
            "events": ["finding"],
            "max_payload_chars": 100,
        }
    }
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "finding", "payload": {"big": big}})
    assert len(posts) == 1
    assert len(posts[0].data) <= 100


def test_retry_then_drop_does_not_raise():
    import urllib.error

    cfg = {
        "webhook_notify": {
            "enabled": True,
            "url": "https://hooks.example.com/x",
            "events": ["finding"],
            "max_retries": 2,
            "backoff_seconds": 0.0,
        }
    }
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    calls = {"n": 0}

    def fail(req, timeout=None):
        calls["n"] += 1
        raise urllib.error.URLError("down")

    with patch("urllib.request.urlopen", side_effect=fail):
        # must not raise
        reg.event_subscribers[0]({"type": "finding", "payload": {}})
    assert calls["n"] == 2  # retried up to max_retries


def test_state_event_in_default_filter():
    cfg = {"webhook_notify": {"enabled": True, "url": "https://hooks.example.com/x", "events": ["finding", "state"]}}
    plugin = _make_plugin(cfg)
    reg = PluginRegistry()
    plugin.register(reg)

    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout=None: (posts.append(req), _FakeResp(200))[1]):
        reg.event_subscribers[0]({"type": "state", "payload": {"state": "running"}})
    assert len(posts) == 1


# ── Event-broker fan-out ──────────────────────────────────────────────────────


def test_event_broker_fires_plugin_subscribers(tmp_path, monkeypatch):
    """RunEventBroker.emit() fires plugin event subscribers after JSONL write (via bounded dispatcher)."""
    from tools.api.event_broker import RunEventBroker, _reset_plugin_dispatcher, wait_for_plugin_dispatcher_empty

    _reset_plugin_dispatcher()
    reg = PluginRegistry()
    monkeypatch.setattr("tools.plugins.PLUGIN_REGISTRY", reg)
    seen: list[dict[str, Any]] = []
    reg.register_event_subscriber(seen.append)

    broker = RunEventBroker("run-1", tmp_path / "reports" / "run-1", buffer_size=8)
    import asyncio

    async def _run():
        await broker.emit("finding", {"v": 1})
        drained = await wait_for_plugin_dispatcher_empty(timeout=2.0)
        assert drained

    asyncio.run(_run())
    assert len(seen) == 1
    assert seen[0]["type"] == "finding"
    assert seen[0]["run_id"] == "run-1"
    _reset_plugin_dispatcher()


def test_event_broker_subscriber_failure_does_not_break_emit(tmp_path, monkeypatch):
    from tools.api.event_broker import RunEventBroker, _reset_plugin_dispatcher, wait_for_plugin_dispatcher_empty

    _reset_plugin_dispatcher()
    reg = PluginRegistry()
    monkeypatch.setattr("tools.plugins.PLUGIN_REGISTRY", reg)
    good: list[dict[str, Any]] = []

    def bad(_e):
        raise RuntimeError("boom")

    reg.register_event_subscriber(bad)
    reg.register_event_subscriber(good.append)

    broker = RunEventBroker("run-2", tmp_path / "reports" / "run-2", buffer_size=8)
    import asyncio

    async def _run():
        evt = await broker.emit("finding", {"v": 1})
        assert evt["type"] == "finding"
        drained = await wait_for_plugin_dispatcher_empty(timeout=2.0)
        assert drained

    asyncio.run(_run())
    # good subscriber still fired despite bad one raising — per-subscriber try/except in dispatcher
    assert len(good) == 1
    _reset_plugin_dispatcher()
