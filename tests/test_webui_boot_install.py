"""WebUI boot must prefer reproducible installs.

When ``webui/package-lock.json`` exists the install step must run
``npm ci`` (reproducible, faster); checkouts without a lockfile keep
``npm install``. Both carry ``--no-audit --no-fund``.
"""

from __future__ import annotations

from pathlib import Path

from tools import webui_boot


class _Ui:
    def __init__(self):
        self.statuses: list[str] = []
        self.errors: list[str] = []

    def status(self, msg):
        self.statuses.append(str(msg))

    def error(self, msg):
        self.errors.append(str(msg))


class _Result:
    returncode = 0
    stdout = ""
    stderr = ""


def _run_boot(monkeypatch, tmp_path: Path, *, lockfile: bool) -> list[list[str]]:
    webui = tmp_path / "webui"
    webui.mkdir(parents=True, exist_ok=True)
    if lockfile:
        (webui / "package-lock.json").write_text("{}", encoding="utf-8")
    # dist/index.html absent -> forces the install+build path
    monkeypatch.setattr(webui_boot, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(webui_boot.shutil, "which", lambda name: f"/fake/{name}")
    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):
        calls.append(list(argv))
        if "build" in argv:
            dist = webui / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "index.html").write_text("<html></html>", encoding="utf-8")
        return _Result()

    monkeypatch.setattr(webui_boot.subprocess, "run", _fake_run)
    rc = webui_boot._ensure_webui_build(_Ui())
    assert rc == 0
    return calls


def test_install_uses_npm_ci_when_lockfile_exists(monkeypatch, tmp_path):
    calls = _run_boot(monkeypatch, tmp_path, lockfile=True)
    install = calls[0]
    assert install[1] == "ci", f"expected `npm ci`, got {install}"
    assert "--no-audit" in install and "--no-fund" in install


def test_install_falls_back_to_npm_install_without_lockfile(monkeypatch, tmp_path):
    calls = _run_boot(monkeypatch, tmp_path, lockfile=False)
    install = calls[0]
    assert install[1] == "install", f"expected `npm install`, got {install}"
