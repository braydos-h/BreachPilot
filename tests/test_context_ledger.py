"""P1-07: incremental context ledger matches full recompute."""

from __future__ import annotations

from copy import deepcopy


def test_ledger_matches_recompute():
    from tools.exploit_agent.context import ContextLedger, _estimate_context_tokens

    ledger = ContextLedger()
    msgs = [{"role": "user", "content": "hi " * 500}, {"role": "assistant", "content": "ok " * 700}]
    for m in msgs:
        ledger.add(m)
    assert ledger.total == _estimate_context_tokens(msgs)
    new = {"role": "user", "content": "replacement " * 100}
    ledger.replace(msgs[0], new)
    msgs[0] = new
    assert ledger.total == _estimate_context_tokens(msgs)


def test_ledger_sync_appends_without_recount():
    from tools.exploit_agent.context import ContextLedger, _estimate_context_tokens

    ledger = ContextLedger()
    msgs = [{"role": "user", "content": "start " * 100}]
    assert ledger.recompute(msgs) == _estimate_context_tokens(msgs)
    msgs.append({"role": "assistant", "content": "more " * 200})
    msgs.append({"role": "user", "content": "again " * 50})
    assert ledger.sync(msgs) == _estimate_context_tokens(msgs)
    assert ledger.total == _estimate_context_tokens(msgs)


def test_ledger_remove_and_resync_new_list():
    from tools.exploit_agent.context import ContextLedger, _estimate_context_tokens

    ledger = ContextLedger()
    msgs = [
        {"role": "system", "content": "sys " * 50},
        {"role": "user", "content": "memory " * 200},
        {"role": "user", "content": "task " * 300},
    ]
    ledger.recompute(msgs)
    # Simulate a refresh rebuild: drop index 1, insert a new message.
    new_mem = {"role": "user", "content": "memory2 " * 210}
    ledger.remove(msgs[1])
    ledger.add(new_mem)
    rebuilt = [msgs[0], new_mem, msgs[2]]
    ledger.resync(rebuilt)
    assert ledger.total == _estimate_context_tokens(rebuilt)
    # Pure appends after resync stay on the fast path.
    rebuilt.append({"role": "assistant", "content": "done " * 10})
    assert ledger.sync(rebuilt) == _estimate_context_tokens(rebuilt)


def test_ledger_tool_calls_and_overhead_match():
    from tools.exploit_agent.context import ContextLedger, _estimate_context_tokens

    ledger = ContextLedger()
    msgs = deepcopy(
        [
            {"role": "assistant", "content": "", "tool_calls": [{"name": "run_exploit_terminal", "args": {"cmd": "id"}}]},
            {"role": "user", "content": "out", "tool_name": "run_exploit_terminal"},
        ]
    )
    assert ledger.recompute(msgs) == _estimate_context_tokens(msgs)
