"""P1-01: event broker burst ordering baseline (batched writer)."""

from __future__ import annotations

import asyncio
import json

from tools.api.event_broker import RunEventBroker


async def _burst(tmp_path):
    b = RunEventBroker("r1", tmp_path, buffer_size=10000)
    for i in range(2000):
        await b.emit("t", {"i": i})
    await b.close()
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    assert len(lines) == 2000
    seqs = [json.loads(line)["sequence"] for line in lines]
    assert seqs == sorted(seqs) and seqs[0] == 1 and seqs[-1] == 2000


def test_burst_persists_in_order(tmp_path):
    asyncio.run(_burst(tmp_path))
