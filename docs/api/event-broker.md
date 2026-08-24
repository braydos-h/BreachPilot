---
title: Event & Decision Brokers — JSONL, Ring, Pub/Sub, Decisions
sources:
  - tools/api/event_broker.py
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

`tools/api/event_broker.py:1` and `tools/api/decision_broker.py:1` — the two per-run brokers `RunManager` owns. Events are the live progress channel (JSONL authoritative); decisions are the pause-for-operator gate.

## Event Broker — `RunEventBroker`

`tools/api/event_broker.py:21` — one instance per active run (`run_id`, `reports_dir`, `buffer_size=1000` default; `app.py:85` passes `api.event_buffer_size`).

### Fields (`tools/api/event_broker.py:29`)

| Field | Type | Purpose |
|-------|------|---------|
| `_run_id` | `str` | scope |
| `_reports_dir` | `Path` | `reports/<run_id>/` (parent created on emit) |
| `_events_path` | `Path` | `reports_dir / "events.jsonl"` authoritative |
| `_ring` | `deque[dict]` | `maxlen=buffer_size` in-memory ring for WS live delivery |
| `_seq` | `int` | monotonic per run |
| `_lock` | `asyncio.Lock` | serialize `emit`/`replay` |
| `_closed` | `bool` | after `close()` emits raise `RuntimeError` |
| `_subscribers` | `list[asyncio.Queue]` | live subscriber queues |

### `emit(event_type, payload) -> event` (`tools/api/event_broker.py:39`)

Hold `_lock`; if `_closed` raise; `_seq+=1`; build `{"sequence":_seq, "timestamp": now ISO, "run_id", "type":event_type, "payload": sanitize(payload)}` (`sanitize` in `tools/api/errors.py:62` — redacts secret-pattern keys); `parent.mkdir(parents=True)`; append `json.dumps(event)+"\n"`; `ring.append(event)`; `queue.put_nowait(event)` per subscriber (drop+`_stop_queue` on `QueueFull`). After releasing lock, call `_fire_plugin_event_subscribers(event)` (`tools/api/event_broker.py:66`) best-effort (lazy import `tools.plugins.PLUGIN_REGISTRY.event_subscribers`, per-subscriber try/except with warning log `tools/api/event_broker.py:272`).

### `replay(after=0) -> list[dict]` (`tools/api/event_broker.py:69`)

Hold lock → `_replay_locked(after)`:

- If ring holds the range (`ring and after >= ring[0]["sequence"]-1`) → ring filter.
- Else scan JSONL line-by-line, skip blank/broken-JSON, `evt["sequence"]` int+not-bool and `>after`.

### `replay_page(after, tail, before, limit)` (`tools/api/event_broker.py:112`)

Paged cursor for the WebUI timeline (`tools/api/routes/events.py:86`).

- `full = list(ring)` when `ring[0].sequence==1` else `await to_thread(_read_jsonl_events)` (`tools/api/event_broker.py:94`).
- `oldest/latest = full[0/-1]["sequence"]|None`. Cases:
  - `tail=N` → `full[-tail:]`, `has_more_before = oldest>1`
  - `before=X + limit=N` → older=`[e for e in full if sequence<X]`, take `[-limit:]`, reverse (newest-first), `has_more_before = older[0].sequence>1`
  - else `after=X` → `sequence>after`, `has_more_before=False` (`uses oldest/latest already computed`)
- Returns `{events, oldest_sequence, latest_sequence, has_more_before}` (`tools/api/event_broker.py:152`).

### `subscribe(after=0) -> EventSubscription` (`tools/api/event_broker.py:159`)

Hold lock; build `EventSubscription(broker, initial=_replay_locked(after))`; if not closed append its queue to `_subscribers`; return.

### `close()` / `_stop_queue` (`tools/api/event_broker.py:170`)

`_closed=True`; for each queue drain then `put(None)` sentinel; clear list. `EventSubscription.__anext__` treats `None` as `StopAsyncIteration`.

## `EventSubscription` (`tools/api/event_broker.py:183`)

`asyncio.Queue(maxsize=ring.maxlen or 256)` (`tools/api/event_broker.py:188`) + `deque(initial)` replay cursor.

- `__anext__`: if `_initial` pop left; else if `broker._closed and empty` → stop; else `wait_for(queue.get(), 30s)` — `TimeoutError` → `{"type":"heartbeat", "run_id": ...}` keepalive (`tools/api/event_broker.py:206`); `None` → stop. `close()` removes queue from broker and marks `_closed`.

## `EventBrokerRegistry` (`tools/api/event_broker.py:220`)

`OrderedDict[str, RunEventBroker]` of at most `max_brokers=10` (`tools/api/event_broker.py:223`), LRU eviction (`popitem(last=False)` + `close`) (`tools/api/event_broker.py:237`).

| Method | Notes |
|--------|-------|
| `get_or_create(run_id, reports_dir=None)` | move-to-end on hit; else `RunEventBroker(run_id, reports_dir or global/run_id, buffer_size)` |
| `get(run_id)` | no create |
| `close_all()` | `close()` each + `clear()` |

Registry is created in `app.py:88`.

## Decision Broker — `DecisionBroker`

`tools/api/decision_broker.py:19` — per-run future table bridging `ApiPersistence` rows to `DecisionProvider` waits.

```python
self._pending: dict[str, asyncio.Future[str]] = {}
```

### `create(decision)` (`tools/api/decision_broker.py:27`)

`did = persistence.create_decision({id, run_id, kind.value, prompt_text, required_text, options})`; `decision.id = did; decision.run_id = run_id`; `future = loop.create_future()`; `self._pending[did]=future`; unless `kind==START_CONFIRM`, `update_run_state(run_id, "awaiting_input")` (`tools/api/persistence.py:207` has state `awaiting_input`). Return `did`.

### `await_answer(decision_id)` (`tools/api/decision_broker.py:50`)

`fut = _pending.get`; if None → `""`; else `await fut` (removed in `finally` pop).

### `resolve(decision_id, answer) -> bool` (`tools/api/decision_broker.py:60`)

`fut` must exist and not `done()`; `row = persistence.answer_decision(id, answer)` must be `answered`; `fut.set_result(answer)` → `True`.

### `cancel_all()` (`tools/api/decision_broker.py:71`)

`persistence.expire_pending_decisions(run_id)` (`tools/api/persistence.py:451`), then `set_result("")` per non-done future and clear.

Decision kinds drive different callers: `start_confirm` is validated in `RunManager.confirm_and_start`; `goal_select`/`tool_approval`/`campaign_next_step` flow through `RunManager.answer_decision` (`tools/api/run_manager.py:454`).

## Tests

`tests/test_api_events.py` covers sequence monotonicity, JSONL persistence, replay cursor, ring boundedness, `sanitize` secret redaction, `get_or_create` identity, concurrent ordering via JSONL, subscription iteration+close, `replay_page` `tail`/`before+limit`/`after+metadata`/empty, and registry LRU eviction/touch. Campaign checkpoint decision lifecycle: `tests/test_api_campaign_checkpoint.py`.
