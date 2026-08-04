"""Bearer token auth, loopback enforcement, and WebSocket origin validation.

v1 security posture:
- Bearer token required on every route except ``/health``.
- Token is 256-bit, generated into ``api.token_file`` (gitignored) on first
  boot, or overridden via ``NETATTACKAI_API_TOKEN`` env. Never logged/returned.
- Bind is loopback-only (127.0.0.1/localhost/::1); no public override in v1.
- WebSocket: first message must be ``{"auth": "<token>"}``; close 4401 on
  failure. Origin must be loopback or in ``api.allowed_origins``.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.websockets import WebSocketDisconnect

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_api_loopback(host: str) -> None:
    """Refuse any non-loopback bind. v1 has no public-bind override."""
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"API host must be loopback (127.0.0.1/localhost/::1); got {host!r}. "
            f"Public binds are not supported in v1."
        )


def load_or_create_token(token_file: Path | str, *, env_override: str = "") -> str:
    """Load the bearer token from env or file, generating one if neither exists.

    ``env_override`` (``NETATTACKAI_API_TOKEN``) takes precedence. The file is
    created with ``0o600`` perms where the OS supports it (best-effort on
    Windows). The token is never logged or returned through the API.
    """
    env_token = (env_override or os.environ.get("NETATTACKAI_API_TOKEN", "")).strip()
    if env_token:
        return env_token
    path = Path(token_file)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    # Generate a 256-bit URL-safe token.
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass  # Windows: chmod is best-effort
    return token


class BearerAuth:
    """FastAPI dependency + constant-time bearer token comparison."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("Bearer token must not be empty.")
        self._token = token
        self._scheme = HTTPBearer(auto_error=False)

    async def __call__(self, request: Request) -> str:
        creds: HTTPAuthorizationCredentials | None = await self._scheme(request)
        if creds is None or creds.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header. Expected: Bearer <token>",
            )
        if not hmac.compare_digest(creds.credentials, self._token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token.",
            )
        return creds.credentials


def is_loopback_origin(origin: str, allowed_origins: list[str]) -> bool:
    """Check if an HTTP Origin is loopback or explicitly allowed.

    ``null`` and non-loopback origins are always rejected. ``allowed_origins``
    is an additional allowlist (e.g. ``["http://localhost:3000"]``) that only
    permits loopback hosts.
    """
    if not origin or origin == "null":
        return False
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (port is not None and not 1 <= port <= 65535)
        ):
            return False
        loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
    if not loopback:
        return False
    return not allowed_origins or origin in allowed_origins or host.lower() in _LOOPBACK_HOSTS


async def authenticate_websocket(
    ws: WebSocket, token: str, allowed_origins: list[str],
) -> dict[str, Any] | None:
    """Validate WebSocket origin + auth message. Returns the message on success.

    Closes the connection with code 4401 on auth failure. The first message
    after connect must be ``{"auth": "<token>"}``.
    """
    origin = ws.headers.get("origin", "")
    if not is_loopback_origin(origin, allowed_origins):
        await ws.close(code=4403, reason="Origin not allowed")
        return None
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5.0)
    except WebSocketDisconnect:
        return None  # client already gone; socket is closed, no close() allowed
    except Exception:
        await ws.close(code=4401, reason="Auth message required")
        return None
    if not isinstance(first, dict) or not hmac.compare_digest(
        str(first.get("auth", "")), token
    ):
        await ws.close(code=4401, reason="Invalid auth token")
        return None
    after = first.get("after", 0)
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        await ws.close(code=4400, reason="Invalid event cursor")
        return None
    first["after"] = after
    return first
