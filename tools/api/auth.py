"""Bearer token auth, loopback enforcement, and WebSocket origin validation.

v1 security posture:
- Bearer token required on every route except ``/health``.
- Token is 256-bit, generated into ``api.token_file`` (gitignored) on first
  boot, or overridden via ``BREACHPILOT_API_TOKEN`` env. Never logged/returned.
- Bind is loopback-only (127.0.0.1/localhost/::1); no public override in v1.
- WebSocket: first message must be ``{"auth": "<token>"}``; close 4401 on
  failure. Origin must be loopback or in ``api.allowed_origins``.
"""

from __future__ import annotations

import asyncio
import hashlib
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

# ── Phase 6.3 (D4): multi-operator password hashing (stdlib only) ──────────
# pbkdf2_hmac with SHA-256 + 200k iterations + 16-byte salt. No new dep —
# hashlib + secrets are stdlib. The loopback bind is the trust boundary; user
# accounts add attribution + pair-testing annotations, not a permissions system.
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16


def assert_api_loopback(host: str) -> None:
    """Refuse any non-loopback bind. v1 has no public-bind override."""
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"API host must be loopback (127.0.0.1/localhost/::1); got {host!r}. Public binds are not supported in v1."
        )


def load_or_create_token(token_file: Path | str, *, env_override: str = "") -> str:
    """Load the bearer token from env or file, generating one if neither exists.

    ``env_override`` (``BREACHPILOT_API_TOKEN``) takes precedence. The file is
    created with ``0o600`` perms where the OS supports it (best-effort on
    Windows). The token is never logged or returned through the API.
    """
    env_token = (env_override or os.environ.get("BREACHPILOT_API_TOKEN", "")).strip()
    if env_token:
        if len(env_token) < 32:
            raise ValueError("BREACHPILOT_API_TOKEN must be at least 32 characters.")
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
    ws: WebSocket,
    token: str,
    allowed_origins: list[str],
) -> dict[str, Any] | None:
    """Validate WebSocket origin + auth message. Returns the message on success.

    Closes the connection with code 4401 on auth failure. The first message
    after connect must be ``{"auth": "<token>"}``.
    """
    origin = ws.headers.get("origin", "")
    if not is_loopback_origin(origin, allowed_origins):
        await ws.close(code=4403, reason="Origin not allowed")
        return None
    # Header fast-path: token checked BEFORE accept (non-browser clients).
    header = ws.headers.get("authorization", "")
    if header[:7].lower() == "bearer " and header[7:].strip():
        if hmac.compare_digest(header[7:].strip(), token):
            await ws.accept()
            return {"auth": "***", "after": 0}
        await ws.close(code=4401, reason="Invalid auth token")
        return None
    # Legacy first-message auth: ASGI requires accept before receive, so this
    # accept is the latest possible point; no state changes precede auth.
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5.0)
    except WebSocketDisconnect:
        return None  # client already gone; socket is closed, no close() allowed
    except Exception:
        await ws.close(code=4401, reason="Auth message required")
        return None
    if not isinstance(first, dict) or not hmac.compare_digest(str(first.get("auth", "")), token):
        await ws.close(code=4401, reason="Invalid auth token")
        return None
    after = first.get("after", 0)
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        await ws.close(code=4400, reason="Invalid event cursor")
        return None
    first["after"] = after
    return first


# ── Phase 6.3 (D4): multi-operator password hashing ─────────────────────────


def hash_password(password: str, *, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with PBKDF2-HMAC-SHA256. Returns (hash_hex, salt_hex).

    ``salt`` (hex) may be supplied to verify an existing hash. When omitted, a
    fresh 16-byte salt is generated. 200k iterations — slow enough to resist
    brute force, fast enough not to block the loopback API.
    """
    if not password:
        raise ValueError("password must not be empty")
    if salt is None:
        salt_bytes = secrets.token_bytes(_SALT_BYTES)
    else:
        salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, _PBKDF2_ITERATIONS)
    return dk.hex(), salt_bytes.hex()


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    """Constant-time verify a password against a stored (hash_hex, salt_hex)."""
    if not password or not password_hash or not password_salt:
        return False
    try:
        candidate, _ = hash_password(password, salt=password_salt)
    except (ValueError, ValueError):
        return False
    return hmac.compare_digest(candidate, password_hash)
