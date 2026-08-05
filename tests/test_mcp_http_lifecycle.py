"""Focused regression tests for the local HTTP MCP process lifecycle."""
from __future__ import annotations

import asyncio
import contextlib
import socket
import subprocess
from pathlib import Path
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
    # Once the port opens, the /mcp probe must agree -- stub it to "serving".
    async def _probe(*_a, **_k):
        return True
    monkeypatch.setattr(ms, "_mcp_http_ready_probe", _probe)

    asyncio.run(
        ms.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=1,
            process=_RunningProcess(),
            log_path=tmp_path / "server.log",
            retry_initial_seconds=0,
        )
    )


def test_open_listener_returns_once_mcp_endpoint_serves(monkeypatch) -> None:
    """An open TCP port alone is not readiness -- ``/mcp`` must actually serve.
    Here the port is open from the first attempt and the probe says "serving",
    so readiness returns without waiting."""
    monkeypatch.setattr(ms, "port_is_open", lambda *_args: True)
    async def _probe(*_a, **_k):
        return True
    monkeypatch.setattr(ms, "_mcp_http_ready_probe", _probe)

    asyncio.run(
        ms.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=0.5,
            process=_RunningProcess(),
        )
    )


def test_open_port_with_503_mcp_retries_until_serving(monkeypatch) -> None:
    """Port open but ``/mcp`` 503ing during app startup must retry the probe
    until it serves (the structural defect from the --web log: a bare TCP
    probe declared readiness, then the live client 503'd and fell back to
    stdio)."""
    monkeypatch.setattr(ms, "port_is_open", lambda *_args: True)
    probe_results = iter((False, False, True))
    calls = {"n": 0}

    async def _probe(*_a, **_k):
        calls["n"] += 1
        return next(probe_results)

    monkeypatch.setattr(ms, "_mcp_http_ready_probe", _probe)

    asyncio.run(
        ms.wait_for_mcp_http_ready(
            "http://127.0.0.1:8001/mcp",
            timeout_seconds=1,
            process=_RunningProcess(),
            retry_initial_seconds=0,
        )
    )
    assert calls["n"] == 3, "probe must be retried through 503s until serving"


def _install_fake_httpx(monkeypatch, *, status=None, exc=None):
    """Inject a minimal fake ``httpx`` module so ``_mcp_http_ready_probe`` (which
    imports httpx at call time) can be exercised without a real server."""
    import sys
    import types

    class _Resp:
        def __init__(self, status_code):
            self.status_code = status_code

    class _StreamCtx:
        def __init__(self, status_code):
            self._resp = _Resp(status_code)

        async def __aenter__(self):
            return self._resp

        async def __aexit__(self, *exc):
            return False

    class _StreamMethod:
        def __init__(self, status_code, exc):
            self._status = status_code
            self._exc = exc

        def __call__(self, *a, **k):
            return _StreamCtx(self._status)

    class _ClientCtx:
        def __init__(self, status_code, exc):
            self._status = status_code
            self._exc = exc

        async def __aenter__(self):
            client = types.SimpleNamespace()
            client.stream = _StreamMethod(self._status, self._exc)
            return client

        async def __aexit__(self, *exc):
            return False

    class _AsyncClient:
        def __init__(self, *a, **k):
            self._status = status
            self._exc = exc

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def stream(self, *a, **k):
            return _StreamCtx(self._status)

    class _ConnectError(Exception):
        pass

    class _TimeoutException(Exception):
        pass

    class _TransportError(Exception):
        pass

    fake = types.ModuleType("httpx")
    fake.AsyncClient = _AsyncClient
    fake.ConnectError = _ConnectError
    fake.TimeoutException = _TimeoutException
    fake.TransportError = _TransportError
    monkeypatch.setitem(sys.modules, "httpx", fake)


def test_mcp_ready_probe_treats_non_503_as_ready(monkeypatch) -> None:
    for status in (200, 400, 404, 406):
        _install_fake_httpx(monkeypatch, status=status)
        assert asyncio.run(ms._mcp_http_ready_probe("http://127.0.0.1:8001/mcp")) is True


def test_mcp_ready_probe_treats_503_as_not_ready(monkeypatch) -> None:
    _install_fake_httpx(monkeypatch, status=503)
    assert asyncio.run(ms._mcp_http_ready_probe("http://127.0.0.1:8001/mcp")) is False


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


def test_http_token_is_used_by_streamable_client(monkeypatch) -> None:
    seen = {}

    @contextlib.asynccontextmanager
    async def _transport(_url, *, http_client=None, **_kwargs):
        seen["authorization"] = http_client.headers.get("authorization")
        yield ("read", "write", None)

    import mcp.client.streamable_http as streamable_module

    monkeypatch.setattr(streamable_module, "streamable_http_client", _transport)

    async def _run():
        async with ms._streamable_http_transport(
            "http://127.0.0.1:8001/mcp",
            token="local-token",
        ) as streams:
            assert streams == ("read", "write", None)

    asyncio.run(_run())
    assert seen["authorization"] == "Bearer local-token"


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


def test_http_startup_failure_falls_back_to_stdio(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, bool]] = []
    fallback_session = object()

    @contextlib.asynccontextmanager
    async def _open_once(**kwargs):
        calls.append((kwargs["transport"], kwargs["startup_soft_fail"]))
        if kwargs["transport"] == "http":
            yield None
        else:
            yield fallback_session

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=False,
        ) as session:
            return session

    assert asyncio.run(_run()) is fallback_session
    assert calls == [("http", True), ("stdio", False)]


def test_recon_soft_fail_yields_none_when_http_and_stdio_both_fail(
    monkeypatch, tmp_path: Path
) -> None:
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


def test_attack_hard_fail_reports_http_and_stdio_startup_errors(
    monkeypatch, tmp_path: Path
) -> None:
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


def test_http_session_failure_after_yield_does_not_retry_over_stdio(
    monkeypatch, tmp_path: Path
) -> None:
    calls: list[str] = []

    @contextlib.asynccontextmanager
    async def _open_once(**kwargs):
        calls.append(kwargs["transport"])
        yield object()

    monkeypatch.setattr(ms, "_open_exploit_mcp_session_once", _open_once)

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="http",
            config_path=Path("config.yaml"),
            target_ip="10.0.0.50",
            exploit_port=8001,
            workspace=tmp_path,
        ):
            raise RuntimeError("tool call failed after startup")

    with pytest.raises(RuntimeError, match="tool call failed after startup"):
        asyncio.run(_run())
    assert calls == ["http"]


@pytest.mark.skipif(not hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"), reason="Windows only")
def test_http_server_starts_in_a_new_windows_process_group(
    monkeypatch, tmp_path: Path
) -> None:
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
