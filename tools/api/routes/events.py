"""Event routes: replay via GET + live WebSocket delivery."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)

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


@router.get("/runs/{run_id}/events", response_model=None)
async def get_events(run_id: str, after: int = Query(0, ge=0), auth: str = Depends(_require_auth)) -> dict:
    """Replay events for a run with sequence > ``after``."""
    if _PERSISTENCE is None or _PERSISTENCE.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if _EVENTS is None:
        raise HTTPException(status_code=503, detail="Event service unavailable")
    events = await _EVENTS.get_or_create(run_id).replay(after)
    return {"run_id": run_id, "events": events}


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
        await ws.close(code=1011, reason="Event stream failed")
    finally:
        subscription.close()
