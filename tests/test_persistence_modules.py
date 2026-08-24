"""Tests for the persistence attack modules."""

from __future__ import annotations

import subprocess

from tools.attack_modules import ModuleContext
from tools.attack_modules.modules.persistence import (
    LinuxPersistence,
    WebShellPersistence,
    WindowsPersistence,
)
from tools.attack_modules.registry import list_modules


def _ctx() -> ModuleContext:
    return ModuleContext(target_ip="10.0.0.5", target_os="linux", services=[], cves=[])


class _FakeProc:
    """Minimal subprocess.run stand-in for the persistence-script exec tests."""
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


def test_linux_persistence_script_has_marker() -> None:
    mod = LinuxPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "LinuxPersistence"
    assert "PERSISTENCE_INSTALLED: cron" in result["script"]


def test_windows_persistence_script_has_marker() -> None:
    mod = WindowsPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "WindowsPersistence"
    assert "PERSISTENCE_INSTALLED: schtask" in result["script"]


def test_webshell_persistence_script_has_marker() -> None:
    mod = WebShellPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "WebShellPersistence"
    assert "PERSISTENCE_INSTALLED: webshell" in result["script"]


def test_persistence_modules_registered() -> None:
    names = [m.name for m in list_modules()]
    assert "LinuxPersistence" in names
    assert "WindowsPersistence" in names
    assert "WebShellPersistence" in names


def test_persistence_modules_have_target_metadata() -> None:
    for mod in (LinuxPersistence(), WindowsPersistence(), WebShellPersistence()):
        assert mod.target_services, f"{mod.name} has no target_services"
        assert mod.target_ports, f"{mod.name} has no target_ports"


def test_linux_persistence_plants_real_ssh_key(tmp_path, monkeypatch) -> None:
    """0.5 — the SSH persistence block must generate a REAL ed25519 keypair via
    ssh-keygen and plant the real pubkey into authorized_keys (not the old
    placeholder string that could never authenticate). Execs the generated
    script in-process with a patched subprocess.run + HOME=tmp_path so no real
    box is touched and the test is cross-platform (no ssh-keygen on PATH)."""
    import contextlib
    import io

    home = tmp_path / "home"
    home.mkdir()
    # expanduser("~") reads HOME (posix) / USERPROFILE (windows).
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    real_run = subprocess.run

    def fake_run(argv, *a, **k):
        # Intercept ssh-keygen: write a real-shaped ed25519 pubkey to <f>.pub.
        if argv and argv[0] == "ssh-keygen":
            f = None
            for i, arg in enumerate(argv):
                if arg == "-f" and i + 1 < len(argv):
                    f = argv[i + 1]
            if f:
                open(f, "w").write("PRIVKEY\n")
                open(f + ".pub", "w").write(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIREALKEY persist@host\n"
                )
            return _FakeProc(0)
        # All other shell calls (crontab/systemctl/sc) succeed silently.
        return _FakeProc(0)

    monkeypatch.setattr("subprocess.run", fake_run)

    script = LinuxPersistence().run(_ctx())["script"]
    # The generated script targets Linux (`import pwd`); inject a stub so it
    # execs on the Windows test host. Only the SSH block is asserted here.
    import types as _types
    _pwd = _types.ModuleType("pwd")

    class _pw:
        pw_name = "root"
    _pwd.getpwuid = lambda uid: _pw()
    monkeypatch.setitem(__import__("sys").modules, "pwd", _pwd)
    ns: dict = {"__name__": "__persistence_test__"}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(script, "<persistence>", "exec"), ns)
    out = buf.getvalue()

    ak = home / ".ssh" / "authorized_keys"
    assert ak.exists(), "authorized_keys not created"
    ak_text = ak.read_text()
    assert "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIREALKEY persist@host" in ak_text
    assert "PLACEHOLDER" not in ak_text
    assert "PLACEHOLDER" not in out
    assert '"authorized_keys": true' in out
    assert "PERSISTENCE_INSTALLED: cron" in out

    # Idempotent: re-running must not duplicate the pubkey.
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        exec(compile(script, "<persistence>", "exec"), ns)
    assert ak.read_text().count("IREALKEY") == 1
