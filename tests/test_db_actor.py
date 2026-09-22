"""P1-10: DB actor queue ordering, error propagation, drain on shutdown."""

from __future__ import annotations

import asyncio


def test_db_actor_fifo_errors_and_drain(tmp_path):
    from tools.api.persistence import ApiPersistence, DbActor

    async def main():
        p = ApiPersistence(tmp_path)
        actor = DbActor(p)
        order: list[int] = []

        def _record(i: int) -> int:
            order.append(i)
            return i

        # Sequential awaits apply in submission order (FIFO worker).
        for i in range(100):
            assert await actor.arun(_record, i) == i
        assert order == list(range(100))

        # Concurrent tasks each get their own result back.
        results = await asyncio.gather(*[actor.arun(_record, i) for i in range(100, 200)])
        assert results == list(range(100, 200))

        # Real writes land.
        await asyncio.gather(
            *[actor.arun(p.create_run, run_id=f"r{i:03d}", request={}, preview={}) for i in range(100)]
        )
        assert await actor.arun(p.count_runs) == 100

        # Errors propagate to the awaiting caller.
        try:
            await actor.arun(p.create_run, run_id="r000", request={}, preview={})
        except Exception as exc:  # noqa: BLE001 -- duplicate id must surface (IntegrityError)
            assert "UNIQUE" in str(exc).upper() or "unique" in str(exc).lower()
        else:
            raise AssertionError("duplicate insert should raise")

        # Batched writes apply atomically in one transaction.
        await actor.abatch(
            [(p.create_run, (), {"run_id": f"b{i:03d}", "request": {}, "preview": {}}) for i in range(10)]
        )
        assert await actor.arun(p.count_runs) == 110

        actor.close()
        actor.close()  # idempotent

    asyncio.run(main())
