"""API diagnostics correlate failures without exposing submitted secrets."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, field_validator

from tools.api.errors import APIError, install_error_handlers, install_middleware


class SecretPayload(BaseModel):
    password: int


class CustomPayload(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def reject(cls, value: str) -> str:
        raise ValueError(f"invalid credential {value}")


def _app() -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)
    install_middleware(app)
    return app


def test_validation_response_omits_submitted_credentials():
    app = _app()

    @app.post("/secret")
    def secret(payload: SecretPayload):
        return {}

    response = TestClient(app).post("/secret", json={"password": "submitted-secret-123"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert error["details"]["errors"] == [{"loc": ["body", "password"], "type": "int_parsing", "msg": "Invalid value"}]
    assert "submitted-secret-123" not in response.text


def test_custom_validator_secret_and_exception_context_are_not_serialized():
    app = _app()

    @app.post("/secret")
    def secret(payload: CustomPayload):
        return {}

    response = TestClient(app).post("/secret", json={"password": "validator-secret-123"})

    assert response.status_code == 422
    assert "validator-secret-123" not in response.text
    detail = response.json()["error"]["details"]["errors"][0]
    assert detail["type"] == "value_error"
    assert detail["msg"] == "Invalid value"
    assert "input" not in detail and "ctx" not in detail


def test_internal_failure_logs_safe_site_and_request_id_without_reraising(caplog):
    app = _app()

    @app.get("/crash")
    def crash():
        raise RuntimeError("Bearer unexpected-secret-123")

    # Default raise_server_exceptions=True: a rethrow to the ASGI server
    # would expose the raw traceback and fail this request in TestClient.
    with caplog.at_level(logging.ERROR, logger="tools.api.errors"):
        response = TestClient(app).get("/crash?token=query-secret-456")

    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    assert error["message"] == "An internal error occurred"
    assert error["request_id"] == response.headers["X-Request-ID"]
    records = [record for record in caplog.records if record.name == "tools.api.errors"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert error["request_id"] in message
    assert "builtins.RuntimeError" in message
    assert "test_api_errors.crash:" in message
    assert records[0].exc_info is None
    assert "unexpected-secret-123" not in caplog.text + response.text
    assert "query-secret-456" not in caplog.text + response.text


def test_explicit_api_error_redacts_nested_secret_details():
    app = _app()

    @app.get("/explicit")
    def explicit():
        raise APIError("bad_config", "Invalid configuration", details={"nested": {"api_key": "api-secret-123"}})

    response = TestClient(app).get("/explicit")

    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"nested": {"api_key": "[REDACTED]"}}
    assert "api-secret-123" not in response.text


def test_handled_server_errors_hide_exception_text(caplog):
    app = _app()

    @app.get("/api-error")
    def api_error():
        try:
            raise OSError("/private/config with token server-secret-123")
        except OSError as exc:
            raise APIError("install_failed", f"Could not install: {exc}", status_code=500) from exc

    @app.get("/http-error")
    def http_error():
        raise HTTPException(status_code=500, detail="database password raw-secret-456")

    with caplog.at_level(logging.ERROR, logger="tools.api.errors"):
        api_response = TestClient(app).get("/api-error")
        http_response = TestClient(app).get("/http-error")

    for response in (api_response, http_response):
        assert response.status_code == 500
        assert response.json()["error"]["message"] == "An internal error occurred"
    assert "server-secret-123" not in caplog.text + api_response.text
    assert "raw-secret-456" not in caplog.text + http_response.text
    assert "builtins.OSError" in caplog.text
