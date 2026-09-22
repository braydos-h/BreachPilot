"""P2-01: indexed replay must not scan the full history for one page."""

from __future__ import annotations

import asyncio
import json

from tools.api.event_broker import RunEventBroker


def test_replay_page_does_not_scan_all(tmp_path):
    async def fill():
        b = RunEventBroker("r1", tmp_path)
        for i in range(10000):
            await b.emit("t", {"i": i})
        await b.close()

    asyncio.run(fill())
    import tools.api.event_broker as eb

    calls = {"n": 0}
    real_loads = json.loads

    def counting(s, *a, **k):
        calls["n"] += 1
        return real_loads(s, *a, **k)

    eb.json.loads = counting
    try:

        async def page():
            b2 = RunEventBroker("r1", tmp_path)
            return await b2.replay_page(before=5200, limit=500)

        res = asyncio.run(page())
    finally:
        eb.json.loads = real_loads
    assert len(res["events"]) == 500 and calls["n"] < 2000, f"parsed {calls['n']} rows for 500-row page"
