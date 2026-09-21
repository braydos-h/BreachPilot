"""p2-03: main entry split — parse_args identity + boot-symbol patch seams."""

from __future__ import annotations


def test_parse_args_is_cli_args_parse_args():
    import main
    import tools.cli_args

    assert main.parse_args is tools.cli_args.parse_args
    assert main.__version__ == tools.cli_args.__version__


def test_boot_symbols_sync_into_impl_modules(monkeypatch):
    import main
    from tools import daemon_lifecycle as daemon_mod
    from tools import webui_boot as webui_mod

    fake_ui = object()
    monkeypatch.setattr(main, "ui", fake_ui)
    monkeypatch.setattr(main, "_api_daemon_ready", lambda host, port: True)
    with main._synced_boot_symbols():
        assert daemon_mod.ui is fake_ui
        assert webui_mod.ui is fake_ui
        assert daemon_mod._api_daemon_ready("127.0.0.1", 8765) is True
    # Hermetic: impl modules are restored on context exit.
    assert daemon_mod.ui is not fake_ui


def test_wrappers_are_not_synced_back(monkeypatch):
    """Syncing must not copy a wrapper into the impl module (that would recurse)."""
    import main
    from tools import daemon_lifecycle as daemon_mod

    real_impl = daemon_mod._run_daemon
    with main._synced_boot_symbols():
        assert daemon_mod._run_daemon is real_impl


def test_rebuild_wrapper_honors_main_patch(monkeypatch):
    import main

    seen = {}

    def _fake_ensure(ui, *, force=False):
        seen["force"] = force
        return 0

    monkeypatch.setattr(main, "_ensure_webui_build", _fake_ensure)
    assert main._rebuild_webui(object()) == 0
    assert seen == {"force": True}


def test_daemon_wrapper_honors_main_patches(monkeypatch):
    import main

    monkeypatch.setattr(main, "ui", type("U", (), {"status": lambda self, m: None})())
    monkeypatch.setattr(main, "load_config", lambda _: {"api": {"host": "127.0.0.1", "port": 8765}})
    monkeypatch.setattr(main, "_api_daemon_ready", lambda host, port: True)
    assert main._run_daemon(main.parse_args(["--daemon"])) == 0
