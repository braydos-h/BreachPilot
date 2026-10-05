---
title: Event & Decision Brokers — JSONL, Ring, Pub/Sub, Decisions
sources:
  - tools/api/event_broker.py
  - tools/api/event_log.py
  - tools/api/plugin_event_dispatcher.py
  - tools/api/decision_broker.py
  - tools/api/errors.py
  - tools/plugins.py
tests:
  - tests/test_api_events.py
  - tests/test_api_campaign_checkpoint.py
subsystem: api
status: maintained
---

# Event & Decision Brokers

`tools/api/event_broker.py`, `tools/api/event_log.py`,
`tools/api/plugin_event_dispatcher.py`, and `tools/api/decision_broker.py` —
the per-run event and decision brokers `RunManager` owns. Events are the live
progress channel (`events.jsonl` is authoritative); decisions are the
pause-for-operator gate.

## Event Broker — `RunEventBroker`

`tools/api/event_broker.py` — one instance per active run (`run_id`,
`reports_dir`, `buffer_size=1000` default; `app.py` passes
`api.event_buffer_size`).

### Fields

| Field | Type | Purpose |
|-------|------|---------|
| `_run_id` | `str` | scope |
| `_reports_dir` | `Path` | `reports/<run_id>/` (parent created on emit) |
| `_events_path` | `Path` | `reports_dir / "events.jsonl"` authoritative |
| `_ring` | `deque[dict]` | `maxlen=buffer_size` in-memory ring for WS live delivery |
| `_seq` | `int` | monotonic per run |
| `_lock` | `asyncio.Lock` | serialize broker state and subscriber changes |
| `_write_q` | `queue.Queue` | ordered handoff to the single JSONL writer thread |
| `_closed` | `bool` | after `close()` emits raise `RuntimeError` |
| `_subscribers` | `list[asyncio.Queue]` | live subscriber queues |

### `emit(event_type, payload) -> event`

`RunEventBroker.emit` sanitizes the payload, checks the closed state, and
queues an unsequenced item. The dedicated writer thread is the only sequence
allocator: it assigns the next number in queue order, appends JSONL and index
data in that same order, applies the selected durability policy, then
publishes the event to the ring and resolves the caller's acknowledgement.
After that acknowledgement, the event loop fans out to WebSocket queues and
the bounded plugin dispatcher. Queue overflow removes the slow WebSocket
subscriber; plugin queue overflow drops only that plugin delivery and logs a
warning. Plugin callbacks run in bounded workers outside the event loop.

The event-log constants and replay/index helpers live in
`tools/api/event_log.py`. Plugin queue, worker, and shutdown behavior live in
`tools/api/plugin_event_dispatcher.py`; historical imports remain re-exported
from `event_broker.py` for compatibility.

### `replay(after=0) -> list[dict]`

Drain queued writes with a writer barrier, then read from the ring when it
covers the requested range; otherwise replay from JSONL. Indexed pages seek
to the nearest checkpoint. Invalid or stale indexes fall back to a correct
full scan and index rebuild; legacy rows with invalid JSON are skipped.

### `replay_page(after, tail, before, limit)`

Paged cursor for the WebUI timeline.

- Read from the ring when it contains the full history; otherwise use the
  indexed replay helpers in `event_log.py`.
- `oldest/latest = full[0/-1]["sequence"]|None` — bounds of the **entire** history. Cases:
  - `tail=N` → `full[-tail:]` (ascending), `omitted_before = len(full)-len(page)`, `has_more_before = omitted_before>0`, `first/last = page[0/-1].sequence|None`, `next_before = first if has_more else None`
  - `before=X + limit=N` → `older_full=[e for e in full if sequence<X]` (all older), `older=older_full[-limit:]`, `events=reversed(older)` (newest-first), `omitted_before = len(older_full)-len(older)` (events still before page), `has_more_before = omitted_before>0`, `first/last = older[0/-1].sequence` (oldest/newest in page), `next_before = first if has_more else None`
  - else `after=X` → `sequence>after` ascending, `has_more_before=False`, `omitted_before=0`, `first/last = page[0/-1].sequence|None`, `next_before=None`
- Returns `{events, oldest_sequence, latest_sequence, has_more_before, first_returned_sequence, last_returned_sequence, omitted_before, next_before}` (`tools/api/event_broker.py`). `oldest/latest` describe the full history; `first/last/omitted/next` describe the returned page. `has_more_before` is derived from `omitted_before>0`, not from `oldest>1`.

### `subscribe(after=0) -> EventSubscription`

Drain queued writes, capture the initial replay under the state lock, and add
the live queue with a replay watermark so events seen during subscription are
not delivered twice.

### `close()` / `_stop_queue`

Mark the broker closed, enqueue the writer sentinel, wait for its bounded
flush/join, and then stop WebSocket queues. `EventBrokerRegistry.close_all()`
also clears ownership state. Plugin dispatcher shutdown is explicit and uses
its own bounded drain.

## `EventSubscription`

Each subscription has a bounded queue and an initial replay cursor.

- `__anext__`: return initial replay first; otherwise wait up to 30 seconds
  for a live event and return a heartbeat on timeout. The close sentinel ends
  iteration. `close()` removes the queue and its replay watermark.

## `EventBrokerRegistry`

The registry stores brokers in an LRU `OrderedDict`. `max_brokers` bounds
unowned archived-history brokers; `acquire()`/`release()` pin active-run
brokers so an archive lookup cannot evict a broker still owned by a run.

| Method | Notes |
|--------|-------|
| `get_or_create(run_id, reports_dir=None)` | move-to-end on hit; else `RunEventBroker(run_id, reports_dir or global/run_id, buffer_size)` |
| `get(run_id)` | no create |
| `acquire(run_id, reports_dir=None)` / `release(run_id)` | pin active owners against LRU eviction |
| `close_all()` | `close()` each + `clear()` |

Registry is created in `app.py`.

## Decision Broker — `DecisionBroker`

`tools/api/decision_broker.py` — per-run future table bridging `ApiPersistence` rows to `DecisionProvider` waits.

```python
self._pending: dict[str, asyncio.Future[str]] = {}
```

### `create(decision)` (`tools/api/decision_broker.py`)

`did = persistence.create_decision({id, run_id, kind.value, prompt_text, required_text, options})`; `decision.id = did; decision.run_id = run_id`; `future = loop.create_future()`; `self._pending[did]=future`; unless `kind==START_CONFIRM`, `update_run_state(run_id, "awaiting_input")` (`tools/api/persistence.py` has state `awaiting_input`). Return `did`.

### `await_answer(decision_id)` (`tools/api/decision_broker.py`)

`fut = _pending.get`; if None → `""`; else `await fut` (removed in `finally` pop).

### `resolve(decision_id, answer) -> bool` (`tools/api/decision_broker.py`)

`fut` must exist and not `done()`; `row = persistence.answer_decision(id, answer)` must be `answered`; `fut.set_result(answer)` → `True`.

### `cancel_all()` (`tools/api/decision_broker.py`)

`persistence.expire_pending_decisions(run_id)` (`tools/api/persistence.py`), then `set_result("")` per non-done future and clear.

Decision kinds drive different callers: `start_confirm` is validated in `RunManager.confirm_and_start`; `goal_select`/`tool_approval`/`campaign_next_step` flow through `RunManager.answer_decision` (`tools/api/run_manager.py`).

## Tests

`tests/test_api_events.py` covers sequence monotonicity, JSONL persistence, replay cursor, ring boundedness, `sanitize` secret redaction, `get_or_create` identity, concurrent ordering via JSONL, subscription iteration+close, `replay_page` `tail`/`before+limit`/`after+metadata`/empty, and registry LRU eviction/touch. Campaign checkpoint decision lifecycle: `tests/test_api_campaign_checkpoint.py`.
