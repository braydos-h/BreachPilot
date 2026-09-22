"""P1-02: event durability mode fallback + policy behavior."""

from __future__ import annotations

import asyncio

from tools.api.event_broker import RunEventBroker


def test_unknown_mode_falls_back_to_balanced(tmp_path):
    b = RunEventBroker("r1", tmp_path, durability="ultrafast")
    assert b.durability == "balanced"


def test_explicit_modes_stick(tmp_path):
    assert RunEventBroker("r1", tmp_path, durability="strict").durability == "strict"
    assert RunEventBroker("r2", tmp_path, durability="fast").durability == "fast"
    assert RunEventBroker("r3", tmp_path).durability == "balanced"


def test_balanced_persists_important_and_tail(tmp_path):
    import json

    async def _run():
        b = RunEventBroker("r1", tmp_path, durability="balanced")
        for i in range(50):
            await b.emit("progress", {"i": i})
        await b.emit("state", {"state": "completed"})
        await b.close()
        lines = (tmp_path / "events.jsonl").read_text().splitlines()
        assert len(lines) == 51
        last = json.loads(lines[-1])
        assert last["type"] == "state"

    asyncio.run(_run())


def test_strict_and_fast_persist_all(tmp_path):
    async def _run():
        for mode in ("strict", "fast"):
            sub = tmp_path / mode
            sub.mkdir()
            b = RunEventBroker("r1", sub, durability=mode)
            for i in range(20):
                await b.emit("t", {"i": i})
            await b.close()
            assert len((sub / "events.jsonl").read_text().splitlines()) == 20

    asyncio.run(_run())
