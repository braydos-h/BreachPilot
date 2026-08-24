---
title: WebSocket & SSE — Live Event Transport (auth, heartbeat, reconnect, close codes)
sources:
  - tools/api/routes/events.py
  - tools/api/event_broker.py
  - tools/api/auth.py
  - tools/api/errors.py
  - app.py
tests:
  - tests/test_api_events.py
subsystem: api
status: maintained
---

# WebSocket & SSE

Live event delivery for a run is WebSocket-primary with an SSE fallback. Both share the same per-run broker; browser disconnect never cancels the run.

## Primitives

`RunEventBroker` emits `{"sequence": monotonic int, "timestamp": ISO, "run_id", "type", "payload": sanitize(payload)}` (`tools/api/event_broker.py:43`). Persisted to `reports/<run_id>/events.jsonl` + `deque(maxlen=buffer_size)` ring. Subscribers are `asyncio.Queue` via `EventSubscription` (`tools/api/event_broker.py:183`) which yields `payload` + 30 s heartbeat `{"type":"heartbeat", "run_id":...}` (`tools/api/event_broker.py:204`).

## `WS /ws/v1/runs/{run_id}` — `ws_run_events`

`tools/api/routes/events.py:146` — `APIRouter(prefix="/api/v1", tags=["events"])` websocket route (`@router.websocket`). Note the path is `/ws/v1/runs/{run_id}` (not `/api/v1/ws`). Mounted via `app.include_router(events_routes.router)` (`app.py:151`).

### Handshake (`tools/api/auth.py:128` / `tools/api/routes/events.py:153`)

1. Early guards before origin check: `if not _EVENTS` → `close(1011, "Server not configured")` (`tools/api/routes/events.py:153`).
2. `auth_message = await authenticate_websocket(ws, _TOKEN, _ALLOWED_ORIGINS)`:
   - `origin = ws.headers.get("origin","")`; if `not is_loopback_origin(origin, _ALLOWED_ORIGINS)` → `close(4403)` + return (`tools/api/auth.py:139`).
   - `accept()` (`tools/api/auth.py:142`).
   - `first = await wait_for(receive_json(), 5.0)`; `WebSocketDisconnect` → `None`; other → `close(4401)` (`tools/api/auth.py:143`).
   - `first` must be `dict` and `hmac.compare_digest(str(first.get("auth","")), token)` else `close(4401)` (`tools/api/auth.py:150`).
   - `after = first.get("after",0)` must be `int` (not `bool`) and `≥0` else `close(4400)` (`tools/api/auth.py:153`).
   - Return mutated `first` with normalized `after`.
3. If `authenticate_websocket` returned `None` handler returns.
4. If `persistence.get_run(run_id) is None` → `close(4404, "Run not found")` (`tools/api/routes/events.py:158`).
5. `broker = _EVENTS.get_or_create(run_id)` — creates by scanning JSONL for completed runs too.
6. `subscription = await broker.subscribe(after=auth_message["after"])` (`tools/api/event_broker.py:159`) — first yields `replay(after)` then live.

### Streaming (`tools/api/routes/events.py:166`)

```python
async for event in subscription:
    await ws.send_json(event)
```

`WebSocketDisconnect` swallowed; other exception → attempt `close(1011, "Event stream failed")` if socket still open; `finally: subscription.close()` which removes the queue from `broker._subscribers` (`tools/api/event_broker.py:214`).

### Heartbeats

`EventSubscription.__anext__` does `wait_for(queue.get(), 30.0)`; on `TimeoutError` returns `{"type":"heartbeat", "run_id": broker._run_id}` (`tools/api/event_broker.py:204`). Client sends no keepalive.

### Reconnect

Cursor is `after` = last seen `sequence`. `subscribe(after)` fast-paths the ring (`tools/api/event_broker.py:75`) else scans JSONL (`tools/api/event_broker.py:87`). Ring + JSONL cover the gap. There is no WS subprotocol.

### Close Codes

| Code | Meaning | Raised in |
|------|---------|-----------|
| 1011 | Server not configured / stream failed | `tools/api/routes/events.py:153`, `:173` |
| 4400 | Invalid `after` cursor | `tools/api/auth.py:155` |
| 4401 | Missing/invalid auth message | `tools/api/auth.py:143`, `:151` |
| 4403 | Origin not allowed | `tools/api/auth.py:140` |
| 4404 | Run not found | `tools/api/routes/events.py:159` |

## `GET /api/v1/runs/{run_id}/events/stream` — SSE `stream_events`

`tools/api/routes/events.py:99` — same subscription over `text/event-stream`.

- Auth: bearer header (never query string). WS and SSE both reject tokens in URLs (`tools/api/routes/events.py:108`).
- Inner `event_generator` loops `async for event in subscription: yield f"data: {json.dumps(event)}\n\n"`; `CancelledError` swallowed; `finally: close`.
- Response `StreamingResponse(generator, media_type="text/event-stream", headers={Cache-Control:no-cache, Connection:keep-alive, X-Accel-Buffering:no})` (`tools/api/routes/events.py:135`). Return annotation is concrete `StreamingResponse` so `openapi.json` does not 500.

## Event Types (streamed values)

Typed in `tools/run_service/models.py:248` and `tools/api/event_broker.py` payloads (examples):

| `type` | Payload excerpt |
|--------|----------------|
| `state` | `{"state": RunState, "result"?:RunResult}` |
| `approval` | `{"decision_id", "kind", "prompt_text", "required_text", "options?"}` / answered form |
| `title` | `{"title": str}` |
| `heartbeat` | `{"run_id": str}` (WS only) |
| plus service events | `boot`, `progress`, `assistant`, `tool_request`, `tool_start`, `tool_result`, `phase`, `goal_suggestions`, `recon_assessment`, `swarm`, `artifact`, `completion`, `error`, `fast_recon_*` (`tools/run_service/models.py:212`) |

All payloads sanitized before persistence/delivery.

## Frontend Contract

`webui/src/api/ws.ts` `useRunEvents(runId, {after})` opens `WS /api/v1/ws/v1/runs/{id}` and sends `{auth, after:lastSeq}` (`ws.ts:101`); dedupes by `sequence` (`ws.ts:40`). Reconnects with exponential backoff; after 3 WS failures switches to `GET /api/v1/runs/{id}/events/stream` (`ws.ts:168`). Resets cursor on `4400`, stops on `4404` (`ws.ts:160`). Poll fallback also via `GET /api/v1/runs/{id}/events?after=N`.
