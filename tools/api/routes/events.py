"""Event routes: replay via GET + live WebSocket delivery + SSE stream."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from tools.api.auth import BearerAuth, authenticate_websocket
from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence

router = APIRouter(prefix="/api/v1", tags=["events"])

# Set by create_app.
_AUTH: BearerAuth | None = None
_EVENTS: EventBrokerRegistry | None = None
_PERSISTENCE: ApiPersistence | None = None
_TOKEN: str = ""
_ALLOWED_ORIGINS: list[str] = []


def configure(
    auth: BearerAuth,
    events: EventBrokerRegistry,
    persistence: ApiPersistence,
    token: str,
    allowed_origins: list[str],
) -> None:
    global _AUTH, _EVENTS, _PERSISTENCE, _TOKEN, _ALLOWED_ORIGINS
    _AUTH = auth
    _EVENTS = events
    _PERSISTENCE = persistence
    _TOKEN = token
    _ALLOWED_ORIGINS = allowed_origins


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API not configured.")
    return await _AUTH(request)


class EventOut(BaseModel):
    """Typed event shape for OpenAPI codegen."""

    sequence: int
    timestamp: str
    run_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)


@router.get("/runs/{run_id}/events", response_model=None)
async def get_events(
    run_id: str,
    after: int = Query(0, ge=0),
    tail: int = Query(None, ge=1, le=1000),
    before: int = Query(None, ge=0),
    limit: int = Query(None, ge=1, le=1000),
    auth: str = Depends(_require_auth),
) -> dict:
    """Replay events for a run.

    ``after`` replays events with sequence > ``after`` (ascending). ``tail``
    returns the newest N events; ``before`` + ``limit`` pages older events
    (newest-first). Paged responses include cursor metadata.
    """
    if _PERSISTENCE is None or _PERSISTENCE.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if _EVENTS is None:
        raise HTTPException(status_code=503, detail="Event service unavailable")
    broker = _EVENTS.get_or_create(run_id)
    if tail is not None or before is not None or limit is not None:
        page = await broker.replay_page(after=after, tail=tail, before=before, limit=limit)
        return {"run_id": run_id, **page}
    events = await broker.replay(after)
    return {
        "run_id": run_id,
        "events": events,
        "oldest_sequence": None,
        "latest_sequence": None,
        "has_more_before": False,
    }


@router.get("/runs/{run_id}/events/stream", response_model=None)
async def stream_events(
    run_id: str,
    after: int = Query(0, ge=0),
    auth: str = Depends(_require_auth),
) -> StreamingResponse:
    """Server-Sent Events stream: replays from ``after`` then streams live.

    Auth via the standard ``Authorization: Bearer <token>`` header (same as
    every other API route). The bearer token is never accepted in the query
    string — tokens must not be placed in URLs/history. Each event is sent as
    ``data: {json}\\n\\n``; a ``: heartbeat`` comment keeps the connection
    alive every 30s.

    Returns a concrete ``StreamingResponse`` (not the bare ``Response`` base
    class) so FastAPI's OpenAPI schema generator can resolve the return
    annotation without raising ``PydanticUserError`` (ForwardRef 'Response'
    not fully defined), which previously made ``/openapi.json`` return 500.
    """
    if _PERSISTENCE is None or _PERSISTENCE.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if _EVENTS is None:
        raise HTTPException(status_code=503, detail="Event service unavailable")

    broker = _EVENTS.get_or_create(run_id)
    subscription = await broker.subscribe(after=after)

    async def event_generator():
        try:
            async for event in subscription:
                yield f"data: {json.dumps(event, default=str)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            subscription.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws/v1/runs/{run_id}")
async def ws_run_events(ws: WebSocket, run_id: str) -> None:
    """WebSocket: live event delivery for a run.

    First message must be ``{"auth": "<token>"}``. Origin must be loopback.
    Reconnect is safe: a browser disconnect does NOT cancel the run.
    """
    if not _EVENTS:
        await ws.close(code=1011, reason="Server not configured")
        return
    auth_message = await authenticate_websocket(ws, _TOKEN, _ALLOWED_ORIGINS)
    if auth_message is None:
        return
    if _PERSISTENCE is None or _PERSISTENCE.get_run(run_id) is None:
        await ws.close(code=4404, reason="Run not found")
        return
    # Get the broker (creates one if the run is active; for completed runs,
    # reads from JSONL).
    broker = _EVENTS.get_or_create(run_id)
    subscription = await broker.subscribe(after=auth_message["after"])
    try:
        async for event in subscription:
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.close(code=1011, reason="Event stream failed")
        except (RuntimeError, WebSocketDisconnect):
            pass  # socket already closed by the client
    finally:
        subscription.close()
