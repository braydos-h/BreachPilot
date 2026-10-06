"""Tests for the proof-of-execution compromise verifier (Phase 1.3)."""

from __future__ import annotations

import pytest

from tools.verification import (
    classify_privilege,
    extract_output,
    verify_compromise,
    verify_compromise_sync,
)

# ── Fakes ─────────────────────────────────────────────────────────────────


class FakeTargetShell:
    """Records calls through a dedicated target-bound shell session.

    Default behavior: echo the canary token back with a POSIX id probe, so the
    verifier succeeds. Per-test fixtures mutate ``self.responses`` to simulate
    blocked results, missing tokens, etc.
    """

    def __init__(self, target_ip: str = "10.0.0.5") -> None:
        self.target_ip = target_ip
        self.calls: list[tuple[str, str]] = []
        # command-substring -> result string. Checked in insertion order.
        self.responses: list[tuple[str, str]] = []
        self.raise_on_call = False

    def __call__(self, target_ip: str, command: str) -> str:
        self.calls.append((target_ip, command))
        if self.raise_on_call:
            raise RuntimeError("executor exploded")
        for marker, result in self.responses:
            if marker in command:
                return result
        # Default: synthesize a successful POSIX probe that echoes the token.
        # Extract the token from the echo '<token>' portion of the command.
        token = ""
        if "echo '" in command:
            after = command.split("echo '", 1)[1]
            token = after.split("'", 1)[0]
        return (
            "TERMINAL_RESULT: success (exit_code=0, duration=0.2s)\n"
            "OUTPUT:\n"
            f"{token}\n"
            "---ID---\n"
            "uid=0(root) gid=0(root) groups=0(root)\n"
            "root\n"
            "target-host\n"
        )


def _blocked_executor() -> FakeTargetShell:
    fx = FakeTargetShell()
    fx.responses = [("echo ", "BLOCKED: target out of scope")]
    return fx


# ── extract_output ─────────────────────────────────────────────────────────


def test_extract_output_strips_output_marker():
    result = "TERMINAL_RESULT: ok\nOUTPUT:\nhello world"
    assert extract_output(result) == "\nhello world"


def test_extract_output_without_marker_returns_whole_string():
    assert extract_output("plain text") == "plain text"


def test_extract_output_non_string():
    assert extract_output(None) == ""
    assert extract_output({"x": 1}) == "{'x': 1}"


# ── classify_privilege ────────────────────────────────────────────────────


def test_classify_privilege_root():
    assert classify_privilege("uid=0(root) gid=0(root) groups=0(root)") == "root"


def test_classify_privilege_euid_root():
    assert classify_privilege("euid=0(root)") == "root"


def test_classify_privilege_system_windows():
    assert classify_privilege("", "NT AUTHORITY\\SYSTEM") == "system"


def test_classify_privilege_user():
    assert classify_privilege("uid=1000(bob) gid=1000(bob)") == "user"


def test_classify_privilege_unknown_empty():
    assert classify_privilege("", "") == "unknown"


# ── verify_compromise_sync ────────────────────────────────────────────────


def test_sync_verify_success_root():
    fx = FakeTargetShell()
    out = verify_compromise_sync(None, "10.0.0.5", target_shell_executor=fx)
    assert out["verified"] is True
    assert out["privilege"] == "root"
    assert out["shell_type"] == "shell"
    assert out["target_ip"] == "10.0.0.5"
    assert out["token"].startswith("PoE-10.0.0.5-")
    assert fx.calls[0][0] == "10.0.0.5"
    assert "echo 'PoE-" in fx.calls[0][1]
    assert any("canary" in e.lower() or "privilege=root" in e for e in out["evidence"])


def test_sync_verify_blocked_result():
    fx = _blocked_executor()
    out = verify_compromise_sync(None, "10.0.0.5", target_shell_executor=fx)
    assert out["verified"] is False
    assert out["privilege"] == "unknown"
    assert any("blocked" in e.lower() for e in out["evidence"])


def test_sync_verify_missing_token_echo():
    fx = FakeTargetShell()
    # Token never echoed back -- write/read did not land on the target.
    fx.responses = [
        (
            "echo ",
            "OUTPUT:\nnot-the-token\n---ID---\nuid=1000(bob)\nbob\nhost\n",
        )
    ]
    out = verify_compromise_sync(None, "10.0.0.5", target_shell_executor=fx)
    assert out["verified"] is False
    assert any("not echoed back" in e for e in out["evidence"])


def test_sync_verify_executor_raises():
    fx = FakeTargetShell()
    fx.raise_on_call = True
    out = verify_compromise_sync(None, "10.0.0.5", target_shell_executor=fx)
    assert out["verified"] is False
    assert any("verifier error" in e or "tool_execution_error" in e.lower() for e in out["evidence"])


def test_sync_verify_missing_target():
    out = verify_compromise_sync(None, "", target_shell_executor=FakeTargetShell())
    assert out["verified"] is False
    assert out["target_ip"] == ""


def test_sync_verify_non_callable_executor():
    out = verify_compromise_sync(None, "10.0.0.5")
    assert out["verified"] is False


def test_sync_verify_user_privilege():
    fx = FakeTargetShell()
    fx.responses = [
        (
            "echo ",
            ("OUTPUT:\n{token}\n---ID---\nuid=1000(bob) gid=1000(bob) groups=1000(bob)\nbob\nhost\n"),
        )
    ]

    # The default fake substitutes {token} literally; patch it to echo the
    # real token by overriding __call__ behavior through a subclass.
    class UserFake(FakeTargetShell):
        def __call__(self, target_ip, command):
            self.calls.append((target_ip, command))
            token = command.split("echo '", 1)[1].split("'", 1)[0] if "echo '" in command else ""
            return f"OUTPUT:\n{token}\n---ID---\nuid=1000(bob) gid=1000(bob) groups=1000(bob)\nbob\nhost\n"

    out = verify_compromise_sync(None, "10.0.0.5", target_shell_executor=UserFake())
    assert out["verified"] is True
    assert out["privilege"] == "user"


def test_sync_verify_never_uses_generic_mcp_worker_executor():
    calls = []

    def generic_executor(name, args):
        calls.append((name, args))
        return "OUTPUT: PoE-"

    out = verify_compromise_sync(generic_executor, "10.0.0.5")
    assert out["verified"] is False
    assert "sandbox worker" in out["evidence"][0]
    assert calls == []


# ── verify_compromise (async) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_verify_success():
    fx = FakeTargetShell()
    out = await verify_compromise(None, "10.0.0.5", target_shell_executor=fx, timeout=10)
    assert out["verified"] is True
    assert out["privilege"] == "root"


@pytest.mark.asyncio
async def test_async_verify_blocked():
    fx = _blocked_executor()
    out = await verify_compromise(None, "10.0.0.5", target_shell_executor=fx)
    assert out["verified"] is False


@pytest.mark.asyncio
async def test_async_verify_missing_inputs():
    out = await verify_compromise(None, "", target_shell_executor=FakeTargetShell())
    assert out["verified"] is False


@pytest.mark.asyncio
async def test_async_verify_timeout():
    class SlowExecutor:
        def __call__(self, target_ip, command):
            # Block long enough to trip the asyncio.wait_for guard.
            import time as _t

            _t.sleep(5)
            return "OUTPUT:\n"

    out = await verify_compromise(None, "10.0.0.5", target_shell_executor=SlowExecutor(), timeout=0.1)
    assert out["verified"] is False
    assert any("timed out" in e.lower() for e in out["evidence"])


@pytest.mark.asyncio
async def test_async_verify_executor_raises():
    fx = FakeTargetShell()
    fx.raise_on_call = True
    out = await verify_compromise(None, "10.0.0.5", target_shell_executor=fx, timeout=10)
    assert out["verified"] is False
