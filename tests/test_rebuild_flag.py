"""--rebuild flag: force-rebuild webui/dist/ for updates (all I/O mocked)."""

from pathlib import Path

import main


class _Ui:
    def __init__(self):
        self.statuses = []
        self.errors = []

    def status(self, msg):
        self.statuses.append(msg)

    def error(self, msg):
        self.errors.append(msg)


def _patch_build_env(monkeypatch, *, dist_exists):
    """Fake npm/node + control the dist fast-path. Returns the subprocess argv calls."""
    calls = []
    monkeypatch.setattr(main.shutil, "which", lambda name: f"/fake/{name}")
    webui_dir = Path(main.__file__).resolve().parent / "webui"
    dist_index = webui_dir / "dist" / "index.html"
    real_exists = Path.exists

    def _fake_exists(self):
        if self == dist_index:
            return dist_exists
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", _fake_exists)

    class _Completed:
        returncode = 0
        stderr = ""

    def _fake_run(argv, **kwargs):
        calls.append(argv)
        return _Completed()

    monkeypatch.setattr(main.subprocess, "run", _fake_run)
    return calls


def _no_bootstrap(monkeypatch):
    monkeypatch.setattr(main, "bootstrap_startup_api_keys", lambda *a, **k: None)


def test_parse_args_rebuild_long_and_single_dash():
    assert main.parse_args(["--rebuild"]).rebuild is True
    assert main.parse_args(["-rebuild"]).rebuild is True
    assert main.parse_args(["--doctor"]).rebuild is False


def test_main_rebuild_standalone_delegates(monkeypatch):
    _no_bootstrap(monkeypatch)
    seen = {}

    def _fake_rebuild(ui):
        seen["called"] = True
        return 0

    monkeypatch.setattr(main, "_rebuild_webui", _fake_rebuild)
    assert main.main(["--rebuild", "--no-api-key-prompt"]) == 0
    assert seen == {"called": True}


def test_main_rebuild_conflicts_with_doctor(monkeypatch):
    _no_bootstrap(monkeypatch)
    assert main.main(["--rebuild", "--doctor", "--no-api-key-prompt"]) == 2


def test_main_rebuild_conflicts_with_target(monkeypatch):
    _no_bootstrap(monkeypatch)
    assert main.main(["--rebuild", "--target", "10.0.0.50", "--no-api-key-prompt"]) == 2


def test_ensure_webui_build_force_rebuilds_when_dist_exists(monkeypatch):
    calls = _patch_build_env(monkeypatch, dist_exists=True)
    assert main._ensure_webui_build(_Ui(), force=True) == 0
    assert len(calls) == 2  # install + build ran despite dist existing


def test_ensure_webui_build_skips_when_dist_exists_without_force(monkeypatch):
    calls = _patch_build_env(monkeypatch, dist_exists=True)
    assert main._ensure_webui_build(_Ui()) == 0
    assert calls == []


def test_rebuild_webui_forces(monkeypatch):
    seen = {}

    def _fake_ensure(ui, *, force=False):
        seen["force"] = force
        return 0

    monkeypatch.setattr(main, "_ensure_webui_build", _fake_ensure)
    assert main._rebuild_webui(_Ui()) == 0
    assert seen == {"force": True}


def test_web_rebuild_falls_through_to_daemon(monkeypatch):
    _no_bootstrap(monkeypatch)
    seen = {}

    def _fake_daemon(args):
        seen["daemon"] = True
        return 7

    monkeypatch.setattr(main, "_run_daemon", _fake_daemon)
    assert main.main(["--web", "--rebuild", "--no-api-key-prompt"]) == 7
    assert seen == {"daemon": True}
