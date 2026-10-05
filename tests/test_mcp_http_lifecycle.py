"""Focused regression tests for the local HTTP MCP process lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import tools.mcp_session as ms


class _RunningProcess:
    def poll(self):
        return None


class _ExitedProcess:
    def poll(self):
        return 7


def test_log_tail_is_bounded_and_redacts_secrets(tmp_path: Path) -> None:
    log_path = tmp_path / "mcp_exploit_server.log"
    log_path.write_text(
        "ordinary startup line\n"
        "MCP_HTTP_TOKEN=super-secret-token\n"
        "Authorization: Bearer bearer-secret\n"
        'api_key: "provider-secret"\n'
        "trace payload contained unlabeled-secret-value\n",
        encoding="utf-8",
    )

    tail = ms._server_log_tail(
        log_path,
        max_lines=4,
        max_chars=250,
        secret_values=("unlabeled-secret-value",),
    )

    assert "super-secret-token" not in tail
    assert "bearer-secret" not in tail
    assert "provider-secret" not in tail
    assert "unlabeled-secret-value" not in tail
    assert "[REDACTED]" in tail
    assert len(tail) < 500


def test_mcp_readiness_retries_until_listener_opens(monkeypatch, tmp_path: Path) -> None:
    attempts = iter((False, False, True))
    monkeypatch.setattr(ms, "port_is_open", lambda *_args: next(attempts))

    asyncio.run(
        ms.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=1,
            process=_RunningProcess(),
            log_path=tmp_path / "server.log",
            retry_initial_seconds=0,
        )
    )


def test_mcp_readiness_requires_matching_child_identity(monkeypatch) -> None:
    import tools.mcp_process as process_helpers

    proofs = iter((False, True))
    attempts: list[tuple[str, str]] = []
    monkeypatch.setattr(ms, "port_is_open", lambda *_args: True)

    async def _verify(url: str, identity_secret: str, **_kwargs: object) -> bool:
        attempts.append((url, identity_secret))
        return next(proofs)

    monkeypatch.setattr(process_helpers, "_verify_mcp_http_identity", _verify)

    asyncio.run(
        process_helpers.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=1,
            process=_RunningProcess(),
            identity_secret="private-session-identity",
            retry_initial_seconds=0,
        )
    )

    assert attempts == [
        ("http://127.0.0.1:8001/mcp", "private-session-identity"),
        ("http://127.0.0.1:8001/mcp", "private-session-identity"),
    ]


def test_open_rogue_listener_never_passes_identity_gate(monkeypatch) -> None:
    import tools.mcp_process as process_helpers

    monkeypatch.setattr(ms, "port_is_open", lambda *_args: True)

    async def _reject(_url: str, _identity_secret: str, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(process_helpers, "_verify_mcp_http_identity", _reject)

    with pytest.raises(RuntimeError, match="listener identity") as exc_info:
        asyncio.run(
            process_helpers.wait_for_mcp_http_ready(
                "http://127.0.0.1:8001/mcp",
                timeout_seconds=0,
                process=_RunningProcess(),
                identity_secret="must-not-appear",
            )
        )

    assert "must-not-appear" not in str(exc_info.value)


def test_http_identity_challenge_is_proven_without_weakening_mcp_auth() -> None:
    import asyncio
    import hashlib
    import hmac

    from tools.mcp_shared import _wrap_http_auth

    called: list[bool] = []

    async def _app(_scope, _receive, _send):
        called.append(True)

    wrapped = _wrap_http_auth(_app, "mcp-bearer", "private-identity")

    async def _call(headers: list[tuple[bytes, bytes]], path: str):
        events: list[dict[str, object]] = []

        async def _receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def _send(event):
            events.append(dict(event))

        await wrapped(
            {"type": "http", "method": "GET", "path": path, "headers": headers},
            _receive,
            _send,
        )
        return events

    challenge = b"fresh-random-challenge"
    events = asyncio.run(_call([(b"x-breachpilot-challenge", challenge)], "/.well-known/breachpilot-mcp-identity"))
    start = events[0]
    response_headers = dict(start["headers"])
    expected = hmac.new(b"private-identity", challenge, hashlib.sha256).hexdigest().encode("ascii")
    assert start["status"] == 200
    assert response_headers[b"x-breachpilot-proof"] == expected
    assert called == []

    unauthorized = asyncio.run(_call([], "/mcp"))
    assert unauthorized[0]["status"] == 401
    assert called == []

    authorized = asyncio.run(_call([(b"authorization", b"Bearer mcp-bearer")], "/mcp"))
    assert authorized == []
    assert called == [True]


def test_open_listener_does_not_wait_for_disposable_mcp_probe(monkeypatch) -> None:
    monkeypatch.setattr(ms, "port_is_open", lambda *_args: True)

    asyncio.run(
        ms.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=0.01,
            process=_RunningProcess(),
        )
    )


def test_mcp_readiness_reports_early_child_exit_with_redacted_log(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "server.log"
    log_path.write_text(
        "MCP_HTTP_TOKEN=must-not-leak\nRuntimeError: import failed\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(
            ms.wait_for_mcp_http_ready(
                "http://127.0.0.1:8001/mcp",
                timeout_seconds=2,
                process=_ExitedProcess(),
                log_path=log_path,
            )
        )

    message = str(exc_info.value)
    assert "exited with code 7" in message
    assert "import failed" in message
    assert "must-not-leak" not in message


@pytest.mark.parametrize(
    ("token", "authorization"),
    [
        ("", None),
        ("local-token", "Bearer local-token"),
    ],
)
def test_streamable_client_bypasses_proxy(monkeypatch, token, authorization) -> None:
    seen = {}

    @contextlib.asynccontextmanager
    async def _transport(_url, *, http_client=None, **_kwargs):
        seen["authorization"] = http_client.headers.get("authorization")
        seen["trust_env"] = http_client.trust_env
        yield ("read", "write", None)

    import mcp.client.streamable_http as streamable_module

    monkeypatch.setattr(streamable_module, "streamable_http_client", _transport)

    async def _run():
        async with ms._streamable_http_transport(
            "http://127.0.0.1:8001/mcp",
            token=token,
        ) as streams:
            assert streams == ("read", "write", None)

    asyncio.run(_run())
    assert seen == {"authorization": authorization, "trust_env": False}


def test_http_sessions_use_distinct_child_and_client_tokens(monkeypatch, tmp_path: Path) -> None:
    import mcp

    server_tokens: list[str] = []
    client_tokens: list[str] = []
    identity_secrets: list[str] = []

    class _Session:
        async def initialize(self) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc_info):
            return False

    @contextlib.asynccontextmanager
    async def _transport(_url, *, token=""):
        client_tokens.append(token)
        yield ("read", "write", None)

    def _start(**kwargs):
        server_tokens.append(kwargs["env"]["MCP_HTTP_TOKEN"])
        identity_secrets.append(kwargs["env"]["MCP_HTTP_IDENTITY_SECRET"])
        log_handle = SimpleNamespace(name=str(tmp_path / "server.log"), close=lambda: None)
        return _RunningProcess(), log_handle

    async def _ready(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setenv("MCP_HTTP_TOKEN", "operator-configured-token")
    monkeypatch.setattr(mcp, "ClientSession", lambda *_args: _Session())
    monkeypatch.setattr(ms, "start_exploit_http_server", _start)
    monkeypatch.setattr(ms, "wait_for_mcp_http_ready", _ready)
    monkeypatch.setattr(ms, "_streamable_http_transport", _transport)
    monkeypatch.setattr(ms, "stop_process", lambda *_args, **_kwargs: None)

    async def _open(workspace: Path) -> None:
        async with ms._open_exploit_mcp_session_once(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="192.0.2.10",
            exploit_port=8001,
            workspace=workspace,
        ) as session:
            assert session is not None

    async def _run() -> None:
        await _open(tmp_path / "run-1")
        await _open(tmp_path / "run-2")

    asyncio.run(_run())

    assert len(server_tokens) == len(client_tokens) == 2
    assert server_tokens == client_tokens
    assert len(set(server_tokens)) == 2
    assert len(set(identity_secrets)) == 2
    assert "operator-configured-token" not in server_tokens


def test_occupied_port_is_rejected_without_spawning(tmp_path: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with pytest.raises(RuntimeError, match="already in use"):
            ms.start_exploit_http_server(
                server_path=tmp_path / "mcp_exploit_server.py",
                config_path=tmp_path / "config.yaml",
                port=port,
                workspace=tmp_path / "workspace",
                env={},
            )


def test_process_helper_uses_legacy_session_port_probe(monkeypatch, tmp_path: Path) -> None:
    probes: list[tuple[str, int]] = []

    def _occupied(host: str, port: int) -> bool:
        probes.append((host, port))
        return True

    monkeypatch.setattr(ms, "port_is_open", _occupied)
    with pytest.raises(RuntimeError, match="already in use"):
        ms.start_exploit_http_server(
            server_path=tmp_path / "mcp_exploit_server.py",
            config_path=tmp_path / "config.yaml",
            port=8001,
            workspace=tmp_path / "workspace",
            env={},
        )

    assert probes == [("127.0.0.1", 8001)]


def test_snapshot_backed_session_uses_stdio_transport(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, bool]] = []
    config_paths: list[Path] = []
    fallback_session = object()
    accepted_config = {"exploit": {"allowed_targets": ["192.0.2.10"]}}
    from tools.kernel.config_fingerprint import config_fingerprint

    accepted_fingerprint = config_fingerprint(accepted_config)

    @contextlib.asynccontextmanager
    async def _open_once(**kwargs):
        calls.append((kwargs["transport"], kwargs["startup_soft_fail"]))
        config_path = kwargs["config_path"]
        config_paths.append(config_path)
        assert config_path.exists()
        assert kwargs["config_fingerprint"] == accepted_fingerprint
        assert kwargs["private_config_snapshot"] is True
        assert kwargs["transport"] == "stdio"
        yield fallback_session

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path / "reports" / "run" / "workspace",
            soft_fail=False,
            config_snapshot=accepted_config,
            config_fingerprint=accepted_fingerprint,
            snapshot_excluded_paths=(tmp_path / "reports",),
        ) as session:
            return session

    assert asyncio.run(_run()) is fallback_session
    assert calls == [("stdio", False)]
    assert len(config_paths) == 1
    assert not config_paths[0].exists()
    assert not config_paths[0].parent.exists()


def test_recon_soft_fail_yields_none_when_http_and_stdio_both_fail(monkeypatch, tmp_path: Path) -> None:
    @contextlib.asynccontextmanager
    async def _open_once(**_kwargs):
        yield None

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=True,
        ) as session:
            return session

    assert asyncio.run(_run()) is None


def test_attack_hard_fail_reports_http_and_stdio_startup_errors(monkeypatch, tmp_path: Path) -> None:
    @contextlib.asynccontextmanager
    async def _open_once(**kwargs):
        if kwargs["transport"] == "http":
            kwargs["startup_errors"].append(RuntimeError("HTTP child crashed"))
            yield None
            return
        raise RuntimeError("stdio init failed")
        yield  # pragma: no cover

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=False,
        ):
            pass

    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(_run())
    message = str(exc_info.value)
    assert "HTTP child crashed" in message
    assert "stdio init failed" in message


def test_snapshot_stdio_session_failure_after_yield_is_not_retried(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    config_paths: list[Path] = []
    accepted_config = {"exploit": {"allowed_targets": ["192.0.2.10"]}}
    from tools.kernel.config_fingerprint import config_fingerprint

    accepted_fingerprint = config_fingerprint(accepted_config)

    @contextlib.asynccontextmanager
    async def _open_once(**kwargs):
        calls.append(kwargs["transport"])
        config_paths.append(kwargs["config_path"])
        yield object()

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path / "workspace",
            config_snapshot=accepted_config,
            config_fingerprint=accepted_fingerprint,
        ):
            assert config_paths[-1].exists()
            raise RuntimeError("tool call failed after startup")

    with pytest.raises(RuntimeError, match="tool call failed after startup"):
        asyncio.run(_run())
    assert calls == ["stdio"]
    assert not config_paths[0].exists()
    assert not config_paths[0].parent.exists()


@pytest.mark.skipif(not hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"), reason="Windows only")
def test_http_server_starts_in_a_new_windows_process_group(monkeypatch, tmp_path: Path) -> None:
    popen_kwargs = {}
    log_handle = MagicMock()

    monkeypatch.setattr(ms, "port_is_open", lambda *_args: False)
    monkeypatch.setattr(Path, "mkdir", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: log_handle)

    def _popen(_args, **kwargs):
        popen_kwargs.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(ms.subprocess, "Popen", _popen)
    ms.start_exploit_http_server(
        server_path=tmp_path / "mcp_exploit_server.py",
        config_path=tmp_path / "config.yaml",
        port=8001,
        workspace=tmp_path,
        env={},
    )

    assert popen_kwargs["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP


@pytest.mark.skipif(not hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"), reason="Windows only")
def test_windows_shutdown_escalates_to_process_tree_kill(monkeypatch) -> None:
    calls = []

    class _Process:
        pid = 4242

        def __init__(self):
            self.waits = 0

        def poll(self):
            return None

        def send_signal(self, sent_signal):
            calls.append(("signal", sent_signal))

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("server", timeout)
            return 0

        def kill(self):
            calls.append(("kill",))

    def _run(args, **kwargs):
        calls.append(("taskkill", args, kwargs))
        return MagicMock(returncode=0)

    monkeypatch.setattr(ms.subprocess, "run", _run)
    ms.stop_process(_Process())

    taskkill = next(call for call in calls if call[0] == "taskkill")
    assert taskkill[1] == ["taskkill", "/PID", "4242", "/T", "/F"]
