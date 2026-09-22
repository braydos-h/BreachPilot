"""P1-03: concurrent emit keeps file order == sequence order (writer-side sequencing)."""

from __future__ import annotations

import asyncio
import json

from tools.api.event_broker import RunEventBroker


async def _hammer(b):
    await asyncio.gather(*[b.emit("t", {"i": i}) for i in range(500)])


def test_concurrent_emit_stays_ordered(tmp_path):
    async def main():
        b = RunEventBroker("r1", tmp_path)
        await asyncio.gather(_hammer(b), _hammer(b), _hammer(b))
        await b.close()
        seqs = [json.loads(line)["sequence"] for line in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

    asyncio.run(main())
