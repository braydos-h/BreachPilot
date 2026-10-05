"""API errors must preserve useful diagnostics without reflecting credentials."""

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from tools.api.errors import APIError, install_error_handlers, install_middleware


def _app() -> FastAPI:
    app = FastAPI()
    install_middleware(app)
    install_error_handlers(app)

    class RequestBody(BaseModel):
        api_key: int

    @app.post("/validation")
    def validation(_body: RequestBody) -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api-error")
    def api_error() -> None:
        raise APIError(
            "invalid_config",
            "Invalid configuration",
            details={
                "api_token": "token-value",
                "nested": {
                    "password": "password-value",
                    "reason": "access_token=access-secret client_secret=client-secret",
                },
            },
        )

    @app.get("/message-secret")
    def message_secret() -> None:
        raise HTTPException(
            status_code=502,
            detail="Upstream failed: api_key=api-secret; access_token=access-secret; client_secret=client-secret; Authorization: Bearer bearer-secret; retry https://user:pass-secret@example.test",
        )

    return app


def test_validation_errors_do_not_echo_submitted_input() -> None:
    secret = "submitted-secret-value"
    with TestClient(_app()) as client:
        response = client.post("/validation", json={"api_key": secret})

    assert response.status_code == 422
    assert secret not in response.text
    error = response.json()["error"]
    validation_errors = error["details"]["errors"]
    assert validation_errors[0]["loc"] == ["body", "api_key"]
    assert validation_errors[0]["type"]
    assert "input" not in validation_errors[0]
    assert response.headers["X-Request-ID"] == error["request_id"]


def test_api_error_details_are_recursively_redacted() -> None:
    with TestClient(_app()) as client:
        response = client.get("/api-error")

    assert response.status_code == 400
    assert response.json()["error"]["details"] == {
        "api_token": "[REDACTED]",
        "nested": {
            "password": "[REDACTED]",
            "reason": "access_token=[REDACTED] client_secret=[REDACTED]",
        },
    }


def test_exception_messages_redact_inline_credentials() -> None:
    with TestClient(_app()) as client:
        response = client.get("/message-secret")

    assert response.status_code == 502
    message = response.json()["error"]["message"]
    for secret in ("api-secret", "access-secret", "client-secret", "bearer-secret", "pass-secret"):
        assert secret not in message
    assert "api_key=[REDACTED]" in message
    assert "access_token=[REDACTED]" in message
    assert "client_secret=[REDACTED]" in message
    assert "Authorization: [REDACTED]" in message
    assert "example.test" in message
