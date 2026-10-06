"""Stable error shape, request-id middleware, and redaction.

All errors use ``{error: {code, message, details, request_id}}``. A
``request_id`` (UUID) is injected per request by middleware so logs and
client-side debugging share a correlation key.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections import deque
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Keys whose values are redacted in API responses (config, secrets, events).
_SECRET_KEY_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key)"
)


class APIError(Exception):
    """Base API error with a stable code, message, details, and status."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


def _error_response(
    code: str,
    message: str,
    status_code: int,
    request_id: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers={"X-Request-ID": request_id},
        content={
            "error": {
                "code": code,
                "message": message,
                "details": sanitize(details or {}),
                "request_id": request_id,
            }
        },
    )


def sanitize(obj: Any) -> Any:
    """Recursively redact values whose keys match secret patterns."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _SECRET_KEY_PATTERNS.search(k) and v else sanitize(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(i) for i in obj]
    return obj


def _internal_error_response(request: Request, exc: Exception) -> JSONResponse:
    """Log only execution metadata, never exception text, source or locals."""
    rid = getattr(request.state, "request_id", "")
    sites: deque[str] = deque(maxlen=12)
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        sites.append(f"{frame.f_globals.get('__name__', '<unknown>')}.{frame.f_code.co_name}:{tb.tb_lineno}")
        tb = tb.tb_next
    logger.error(
        "Unhandled API error request_id=%s exception_type=%s.%s sites=%s",
        rid,
        type(exc).__module__,
        type(exc).__qualname__,
        " -> ".join(sites),
    )
    return _error_response("internal_error", "An internal error occurred", 500, rid)


def _log_caught_server_error(request: Request, code: str, exc: Exception) -> None:
    """Log the cause type for handled 5xx errors without echoing exception text."""
    rid = getattr(request.state, "request_id", "")
    cause = exc.__cause__
    error_type = f"{type(cause).__module__}.{type(cause).__qualname__}" if cause is not None else type(exc).__qualname__
    logger.error("Handled API server error request_id=%s code=%s cause_type=%s", rid, code, error_type)


def install_error_handlers(app: FastAPI) -> None:
    """Register error handlers that produce the stable error shape."""

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        if exc.status_code >= 500:
            _log_caught_server_error(request, "http_error", exc)
            return _error_response("http_error", "An internal error occurred", exc.status_code, rid)
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return _error_response("http_error", message, exc.status_code, rid)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        return _error_response(
            "validation_error",
            "Request validation failed",
            422,
            rid,
            # Pydantic's input/context and custom-validator messages may
            # contain passwords, tokens or non-JSON-serializable exceptions.
            # Return location + error kind, with a fixed safe explanation.
            details={
                "errors": [
                    {"loc": error.get("loc", ()), "type": error.get("type", "validation_error"), "msg": "Invalid value"}
                    for error in exc.errors()
                ]
            },
        )

    @app.exception_handler(APIError)
    async def _api_exc_handler(request: Request, exc: APIError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        if exc.status_code >= 500:
            _log_caught_server_error(request, exc.code, exc)
            return _error_response(exc.code, "An internal error occurred", exc.status_code, rid)
        return _error_response(exc.code, exc.message, exc.status_code, rid, exc.details)

    @app.exception_handler(ValueError)
    async def _value_exc_handler(request: Request, exc: ValueError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        # ponytail: never echo str(exc) — paths/ internals leak to the UI.
        return _error_response("value_error", "Invalid request", 400, rid)

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, exc: Exception) -> JSONResponse:
        return _internal_error_response(request, exc)


def install_middleware(app: FastAPI) -> None:
    """Install request-id injection middleware."""

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        try:
            response = await call_next(request)
        except Exception as exc:  # noqa: BLE001 -- sanitized response prevents raw ASGI traceback logging
            response = _internal_error_response(request, exc)
        response.headers["X-Request-ID"] = request.state.request_id
        return response
