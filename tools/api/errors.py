"""Stable error shape, request-id middleware, and redaction.

All errors use ``{error: {code, message, details, request_id}}``. A
``request_id`` (UUID) is injected per request by middleware so logs and
client-side debugging share a correlation key.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tools.kernel.redaction import sanitize, sanitize_message


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
        content={
            "error": {
                "code": code,
                "message": sanitize_message(message),
                "details": sanitize(details or {}),
                "request_id": request_id,
            }
        },
    )


def install_error_handlers(app: FastAPI) -> None:
    """Register error handlers that produce the stable error shape."""

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        return _error_response("http_error", str(exc.detail), exc.status_code, rid)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        # Pydantic's error dictionaries include the submitted `input`, which
        # may contain credentials even when the location is an ordinary field.
        # Return only schema location and error category to avoid reflecting it.
        safe_errors = [
            {
                "loc": list(error.get("loc", ())) if isinstance(error.get("loc", ()), tuple | list) else [],
                "type": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
            if isinstance(error, dict)
        ]
        return _error_response(
            "validation_error",
            "Request validation failed",
            422,
            rid,
            details={"errors": safe_errors},
        )

    @app.exception_handler(APIError)
    async def _api_exc_handler(request: Request, exc: APIError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        return _error_response(exc.code, exc.message, exc.status_code, rid, exc.details)

    @app.exception_handler(ValueError)
    async def _value_exc_handler(request: Request, exc: ValueError) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        # ponytail: never echo str(exc) — paths/ internals leak to the UI.
        return _error_response("value_error", "Invalid request", 400, rid)

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", "")
        return _error_response("internal_error", "An internal error occurred", 500, rid)


def install_middleware(app: FastAPI) -> None:
    """Install request-id injection middleware."""

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response
