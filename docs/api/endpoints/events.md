---
title: Events Endpoints — Replay, Pagination, SSE Stream
sources:
  - tools/api/routes/events.py
  - tools/api/event_broker.py
  - tools/api/persistence.py
  - tools/api/auth.py
tests:
  - tests/test_api_events.py
  - tests/test_api_frontend.py
subsystem: api
---

# Events Endpoints

`tools/api/routes/events.py:1` — `APIRouter(prefix="/api/v1", tags=["events"])`. Wired by `events_routes.configure(auth, events, persistence, token, allowed_origins)` (`app.py:137`). All routes require bearer (`_require_auth` `tools/api/routes/events.py:50`) except the WebSocket which uses `authenticate_websocket` (see `docs/api/websocket.md`). 404 when `persistence.get_run(run_id)` missing, `503` when broker registry missing.

Model `EventOut` (`tools/api/routes/events.py:56`): `{sequence:int, timestamp:str, run_id:str, type:str, payload:dict}`.

## `GET /api/v1/runs/{run_id}/events` — `get_events`

`tools/api/routes/events.py:66`:

Query:

| Param | Type | Default | Constraint |
|-------|------|---------|------------|
| `after` | int | `0` | `≥0` |
| `tail` | int | `null` | `1..1000` |
| `before` | int | `null` | `≥0` |
| `limit` | int | `null` | `1..1000` |

- When any of `tail|before|limit` present → `broker.replay_page(after, tail, before, limit)` (`tools/api/event_broker.py:112`) and return `{run_id, ...page}` where page is `{events, oldest_sequence, latest_sequence, has_more_before, first_returned_sequence, last_returned_sequence, omitted_before, next_before}`.
- Else → `broker.replay(after)` (`tools/api/event_broker.py:69`) and return `{run_id, events, oldest_sequence:None, latest_sequence:None, has_more_before:false, first_returned_sequence, last_returned_sequence, omitted_before:0, next_before:None}` (`tools/api/routes/events.py:88`).

Broker is `events.get_or_create(run_id)` which for completed runs reads from JSONL (`tools/api/event_broker.py:229`). Pagination detail: `tail=N` newest N ascending with `omitted_before=len(full)-len(page)` and `next_before=first_returned`; `before=X + limit=N` up to N with `sequence<X` descending so client pages older (`tools/api/event_broker.py:142`) with `omitted_before=len(older_full)-len(page)` and `next_before=oldest_in_page`. `oldest/latest` are whole-history bounds; `first/last/omitted/next` describe the returned page (`has_more_before=omitted_before>0`).

Error: `404 Run not found`, `503 Event service unavailable`.

## `GET /api/v1/runs/{run_id}/events/stream` — `stream_events` — SSE

`tools/api/routes/events.py:99` — `StreamingResponse` with `text/event-stream`.

- Requires bearer via `Authorization: Bearer <token>` header (same as every other route); token is **never** accepted in query string.
- Query: `after ≥0` default `0`.
- Creates `subscription = await broker.subscribe(after)` (`tools/api/event_broker.py:159`).
- Inner `event_generator()` loops `async for event in subscription: yield f"data: {json.dumps(event)}\n\n"`; `CancelledError` swallowed; `finally: subscription.close()` (`tools/api/routes/events.py:126`).
- Response headers `Cache-Control:no-cache`, `Connection:keep-alive`, `X-Accel-Buffering:no` (`tools/api/routes/events.py:135`).
- Return annotation is concrete `StreamingResponse` (not bare `Response`) so OpenAPI generation does not 500 (`tools/api/routes/events.py:108`).

Returns `404`/`503` same as above. Retry: WebUI falls back to this SSE after 3 WS failures (`webui/src/api/ws.ts:168`).

## Tests

`tests/test_api_events.py` covers broker primitives (`sequence`, JSONL, `replay`, ring, `replay_page`, `EventBrokerRegistry` LRU); HTTP-level stream/replay exercised via `tests/test_api_frontend.py` artifact and WebUI regression tests.
