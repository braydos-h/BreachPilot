"""Tests for the --demon / --daemon CLI flag and parse_args wiring."""

from __future__ import annotations

import pytest


def test_demon_flag_alias(monkeypatch):
    """Both --demon and --daemon should set args.daemon = True."""
    from main import parse_args

    args = parse_args(["--demon"])
    assert args.daemon is True
    args2 = parse_args(["--daemon"])
    assert args2.daemon is True


def test_demon_default_host_port():
    """--api-host / --api-port default to None (filled from config at runtime)."""
    from main import parse_args

    args = parse_args(["--demon"])
    assert args.api_host is None
    assert args.api_port is None


def test_demon_reuses_running_api_daemon(monkeypatch):
    """A second daemon invocation must not attempt another bind."""
    import main

    class _Ui:
        def __init__(self):
            self.messages = []

        def status(self, message):
            self.messages.append(message)

    monkeypatch.setattr(main, "ui", _Ui())
    monkeypatch.setattr(main, "load_config", lambda _: {"api": {"host": "127.0.0.1", "port": 8765}})
    monkeypatch.setattr(main, "_api_daemon_ready", lambda host, port: True)
    monkeypatch.setattr(
        main, "create_app", lambda *args, **kwargs: pytest.fail("must not create a second daemon"), raising=False
    )

    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
    assert main.ui.messages == ["WebUI API daemon is already running on http://127.0.0.1:8765"]


# ── already-running daemon: press K to kill ────────────────────────────────


class _FakeTtyStdin:
    def isatty(self) -> bool:
        return True


def test_find_port_listener_pid_parses_netstat(monkeypatch):
    """Windows path: parse the LISTENING row for the requested port."""
    import main

    class _Proc:
        returncode = 0
        stdout = (
            "\n"
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    127.0.0.1:8765         0.0.0.0:0              LISTENING       4242\n"
            "  TCP    127.0.0.1:8766         0.0.0.0:0              LISTENING       1111\n"
        )

    monkeypatch.setattr(main.sys, "platform", "win32")
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: _Proc())
    assert main._find_port_listener_pid(8765) == 4242
    assert main._find_port_listener_pid(9999) is None


def test_find_port_listener_pid_missing_tool(monkeypatch):
    """When netstat/lsof/ss all fail, return None instead of raising."""
    import subprocess

    import main

    monkeypatch.setattr(main.sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no such tool")))
    assert main._find_port_listener_pid(8765) is None


def test_demon_kill_prompt_enter_keeps_daemon(monkeypatch):
    """Pressing Enter at the kill prompt keeps the running daemon (exit 0, no kill)."""
    import builtins
    import sys

    import main

    class _Ui:
        def __init__(self):
            self.messages = []

        def status(self, message):
            self.messages.append(message)

    monkeypatch.setattr(main, "ui", _Ui())
    monkeypatch.setattr(main, "load_config", lambda _: {"api": {"host": "127.0.0.1", "port": 8765}})
    monkeypatch.setattr(main, "_api_daemon_ready", lambda *_: True)
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr(builtins, "input", lambda *_args: "")
    monkeypatch.setattr(
        main, "_stop_running_daemon", lambda *_: (_ for _ in ()).throw(AssertionError("must not kill on Enter"))
    )

    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
    assert main.ui.messages == ["WebUI API daemon is already running on http://127.0.0.1:8765"]


def test_demon_kill_prompt_kills_and_restarts(monkeypatch):
    """Pressing K stops the old daemon, then a fresh daemon binds the same port."""
    import builtins
    import sys
    from unittest.mock import MagicMock

    import uvicorn

    import app
    import main
    import tools.api.auth as auth

    fake_ui = MagicMock()
    fake_ui._c.return_value = ""
    monkeypatch.setattr(main, "ui", fake_ui)
    monkeypatch.setattr(main, "load_config", lambda _: {"api": {"host": "127.0.0.1", "port": 8765}})
    monkeypatch.setattr(main, "_api_daemon_ready", lambda *_: True)
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr(builtins, "input", lambda *_args: "k")
    monkeypatch.setattr(main, "_stop_running_daemon", lambda *_: True)
    monkeypatch.setattr(main, "_auto_update_models", lambda *_args: None)
    monkeypatch.setattr(auth, "load_or_create_token", lambda *_args, **_kwargs: "token")
    monkeypatch.setattr(app, "create_app", lambda **_: object())
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda _app, **kwargs: seen.update(kwargs))

    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
    assert seen["port"] == 8765
    fake_ui.status.assert_any_call("Stopped the previous WebUI API daemon; starting a fresh one.")


def test_demon_kill_failure_keeps_daemon(monkeypatch):
    """If the kill fails, report the error and keep the existing daemon (exit 0)."""
    import builtins
    import sys

    import main

    class _Ui:
        def __init__(self):
            self.statuses = []
            self.errors = []

        def status(self, message):
            self.statuses.append(message)

        def error(self, message):
            self.errors.append(message)

    monkeypatch.setattr(main, "ui", _Ui())
    monkeypatch.setattr(main, "load_config", lambda _: {"api": {"host": "127.0.0.1", "port": 8765}})
    monkeypatch.setattr(main, "_api_daemon_ready", lambda *_: True)
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr(builtins, "input", lambda *_args: "k")
    monkeypatch.setattr(main, "_stop_running_daemon", lambda *_: False)

    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
    assert main.ui.errors == ["Could not stop the running daemon; keeping it."]


def test_daemon_bounds_graceful_shutdown(monkeypatch):
    """A streaming client cannot leave Uvicorn stuck after its listener closes."""
    import builtins
    from unittest.mock import MagicMock

    import uvicorn

    import app
    import main
    import tools.api.auth as auth

    seen = {}
    fake_ui = MagicMock()
    fake_ui._c.return_value = ""
    monkeypatch.setattr(main, "ui", fake_ui)
    monkeypatch.setattr(
        main,
        "load_config",
        lambda _: {"api": {"host": "127.0.0.1", "port": 8765, "shutdown_timeout_seconds": 7}},
    )
    monkeypatch.setattr(main, "_api_daemon_ready", lambda *_: False)
    monkeypatch.setattr(app, "create_app", lambda **_: object())
    monkeypatch.setattr(auth, "load_or_create_token", lambda *_args, **_kwargs: "token")
    monkeypatch.setattr(builtins, "input", lambda *_args: "")
    monkeypatch.setattr(uvicorn, "run", lambda _app, **kwargs: seen.update(kwargs))

    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
    assert seen["timeout_graceful_shutdown"] == 7


def test_demon_mutually_exclusive_with_target():
    """--demon + --target should return exit code 2 (conflict)."""
    from main import main

    code = main(["--demon", "--target", "10.0.0.50"])
    assert code == 2


def test_demon_mutually_exclusive_with_doctor():
    """--demon + --doctor should return exit code 2."""
    from main import main

    code = main(["--demon", "--doctor"])
    assert code == 2


def test_demon_mutually_exclusive_with_menu():
    """--demon + --menu should return exit code 2."""
    from main import main

    code = main(["--demon", "--menu"])
    assert code == 2


def test_no_daemon_flag_preserves_existing_behavior():
    """Without --demon, args.daemon is False."""
    from main import parse_args

    args = parse_args(["--target", "10.0.0.50", "--mode", "recon"])
    assert args.daemon is False


# ── --web flag ─────────────────────────────────────────────────────────────


def test_web_flag_sets_args_web():
    """--web sets args.web = True."""
    from main import parse_args

    args = parse_args(["--web"])
    assert args.web is True


def test_web_default_is_false():
    from main import parse_args

    args = parse_args(["--demon"])
    assert args.web is False


def test_web_mutually_exclusive_with_target():
    """--web + --target returns exit code 2."""
    from main import main

    code = main(["--web", "--target", "10.0.0.50"])
    assert code == 2


def test_web_mutually_exclusive_with_doctor():
    from main import main

    code = main(["--web", "--doctor"])
    assert code == 2


def test_web_mutually_exclusive_with_menu():
    from main import main

    code = main(["--web", "--menu"])
    assert code == 2


def test_web_setup_api_keys_does_not_bypass_gate(monkeypatch):
    """--web --setup-api-keys hits the conflict gate (returns 2), not _run_daemon.

    This confirms the daemon/web conflict gate fires even when setup_api_keys
    is set, closing the previous hole where --daemon --setup-api-keys slipped
    through the setup_only early return.
    """
    import tools.config_cli as _config_cli

    class _Result:
        loaded = []
        saved = []
        missing = []
        store_path = "x"

    monkeypatch.setattr(_config_cli, "bootstrap_api_keys", lambda *a, **kw: _Result())
    from main import main

    code = main(["--web", "--setup-api-keys", "--no-api-key-prompt"])
    assert code == 2


def test_ensure_webui_build_returns_zero_when_dist_exists(monkeypatch, tmp_path):
    """_ensure_webui_build returns 0 immediately when dist/index.html exists."""
    from pathlib import Path

    import main

    webui_dir = Path(main.__file__).resolve().parent / "webui"
    dist_index = webui_dir / "dist" / "index.html"
    if not dist_index.exists():
        pytest.skip("webui/dist not built — cannot test the exists-fast-path here.")

    # A dummy UI object that records calls.
    class _Ui:
        def __init__(self):
            self.calls = []

        def status(self, msg):
            self.calls.append(("status", msg))

        def error(self, msg):
            self.calls.append(("error", msg))

    ui = _Ui()
    rc = main._ensure_webui_build(ui)
    assert rc == 0


def test_ensure_webui_build_errors_when_npm_missing(monkeypatch, tmp_path):
    """_ensure_webui_build returns 1 when npm/node are not on PATH and dist is absent."""
    from pathlib import Path

    import main

    monkeypatch.setattr(main.shutil, "which", lambda name: None)
    # Force the dist-absent branch by patching Path.exists for index.html only.
    webui_dir = Path(main.__file__).resolve().parent / "webui"
    real_exists = Path.exists

    def _fake_exists(self):
        if self == webui_dir / "dist" / "index.html":
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", _fake_exists)

    class _Ui:
        def __init__(self):
            self.errors = []

        def status(self, msg):
            pass

        def error(self, msg):
            self.errors.append(msg)

    ui = _Ui()
    rc = main._ensure_webui_build(ui)
    assert rc == 1
    assert any("Node/npm" in e for e in ui.errors)
