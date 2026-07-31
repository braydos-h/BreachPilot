"""Tests for the --demon / --daemon CLI flag and parse_args wiring."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


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
    import main
    from pathlib import Path

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