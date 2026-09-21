"""Daemon lifecycle for the BreachPilot entry point.

Moved verbatim out of ``main.py`` (p2-03 split) — no behavior change.
``ui``/``load_config`` are module globals so ``main._sync_boot_symbols``
can propagate test monkeypatches; cross-module calls into
``tools.webui_boot`` go through the module object (``_webui_boot.*``) so a
synced fake is honored instead of a stale direct reference.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time

from tools import webui_boot as _webui_boot
from tools.attack_ui import get_ui
from tools.config_cli import load_config

ui = get_ui()

__all__ = [
    "_api_daemon_ready",
    "_copy_to_clipboard",
    "_find_port_listener_pid",
    "_offer_daemon_kill",
    "_run_daemon",
    "_stop_running_daemon",
]


def _api_daemon_ready(host: str, port: int) -> bool:
    """Return whether a BreachPilot API daemon already owns this endpoint."""
    import urllib.request

    base = f"http://{host}:{port}/" if host != "::1" else f"http://[{host}]:{port}/"
    try:
        with urllib.request.urlopen(f"{base}api/v1/health", timeout=1) as response:  # noqa: S310 -- loopback only
            return response.status == 200
    except OSError:
        return False


def _find_port_listener_pid(port: int) -> int | None:
    """Best-effort PID of the process listening on TCP ``port`` (None if unknown)."""
    if sys.platform == "win32":
        try:
            proc = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        for line in proc.stdout.splitlines():
            # TCP    127.0.0.1:8765    0.0.0.0:0    LISTENING    <pid>
            fields = line.split()
            if len(fields) >= 5 and fields[3].upper() == "LISTENING" and fields[1].endswith(f":{port}"):
                try:
                    return int(fields[4])
                except ValueError:
                    return None
        return None
    for cmd in (["lsof", "-nP", f"-tiTCP:{port}", "-sTCP:LISTEN"], ["ss", "-ltnp"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            if cmd[0] == "lsof":
                try:
                    return int(line.strip().split()[0])
                except (IndexError, ValueError):
                    continue
            fields = line.split()
            if len(fields) >= 4 and fields[0] == "LISTEN" and fields[3].endswith(f":{port}"):
                match = re.search(r"pid=(\d+)", line)
                if match:
                    return int(match.group(1))
    return None


def _stop_running_daemon(host: str, port: int) -> bool:
    """Terminate the process owning ``port``; True once the endpoint stops answering."""
    pid = _find_port_listener_pid(port)
    if pid is None:
        return False
    cmd = ["taskkill", "/F", "/PID", str(pid)] if sys.platform == "win32" else ["kill", str(pid)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if not _api_daemon_ready(host, port):
            return True
        time.sleep(0.3)
    return False


def _offer_daemon_kill() -> bool:
    """TTY-only prompt for the already-running-daemon case. Returns True on K."""
    try:
        if not sys.stdin.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    try:
        return input("  Press K to kill it and start fresh, or Enter to keep it: ").strip().lower() == "k"
    except (EOFError, KeyboardInterrupt):
        return False


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort copy ``text`` to the system clipboard. Returns True on success.

    Tries, in order: 1) ``pyperclip`` if installed, 2) OS-native commands
    (``clip``/PowerShell on Windows, ``pbcopy`` on macOS, ``wl-copy``/``xclip``/``xsel``
    on Linux), 3) ``tkinter`` as a stdlib fallback. Never raises — a failure is
    just ``False`` so the daemon can still print the token for manual copy.
    """
    clipped = text.strip()
    if not clipped:
        return False
    # 1) Optional pyperclip dep (no hard requirement).
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(clipped)
        return True
    except Exception:
        pass
    # 2) Native OS commands (lightweight, no window).
    try:
        if sys.platform == "win32":
            # clip.exe is built into Windows; PowerShell Set-Clipboard is the fallback
            # that also works when clip is absent or stdin handling differs.
            if shutil.which("clip"):
                try:
                    proc = subprocess.run(
                        ["clip"], input=clipped, text=True, timeout=5, capture_output=True, check=False
                    )
                    if proc.returncode == 0:
                        return True
                except Exception:
                    pass
            if shutil.which("powershell") or shutil.which("pwsh"):
                pwsh = shutil.which("pwsh") or shutil.which("powershell")
                try:
                    # Feed via stdin to avoid quoting issues: $input | Set-Clipboard
                    proc = subprocess.run(
                        [pwsh, "-NoProfile", "-Command", "$input | Set-Clipboard"],
                        input=clipped,
                        text=True,
                        timeout=5,
                        capture_output=True,
                        check=False,
                    )
                    if proc.returncode == 0:
                        return True
                except Exception:
                    pass
        elif sys.platform == "darwin":
            if shutil.which("pbcopy"):
                try:
                    proc = subprocess.run(
                        ["pbcopy"], input=clipped, text=True, timeout=5, capture_output=True, check=False
                    )
                    return proc.returncode == 0
                except Exception:
                    pass
        else:
            for cmd in (
                ["wl-copy"],
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
            ):
                if shutil.which(cmd[0]):
                    try:
                        proc = subprocess.run(
                            cmd, input=clipped, text=True, timeout=5, capture_output=True, check=False
                        )
                        if proc.returncode == 0:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    # 3) tkinter fallback (stdlib, but may need a display).
    try:
        import tkinter  # type: ignore

        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(clipped)
        root.update()
        root.destroy()
        return True
    except Exception:
        pass
    return False


def _run_daemon(args: argparse.Namespace) -> int:
    """Start the local WebUI API server (``--demon`` / ``--daemon`` / ``--web``)."""
    config = load_config(args.config)
    api_cfg = config.setdefault("api", {})
    host = args.api_host or api_cfg.get("host", "127.0.0.1")
    port = int(args.api_port or api_cfg.get("port", 8765))
    shutdown_timeout = int(api_cfg.get("shutdown_timeout_seconds", 15))
    # v1: loopback-only. Refuse any non-loopback bind (no public override).
    if host not in ("127.0.0.1", "localhost", "::1"):
        ui.error(
            f"--api-host must be loopback (127.0.0.1/localhost/::1); got {host!r}. Public binds are not supported in v1."
        )
        return 2
    status_host = f"[{host}]" if host == "::1" else host
    web_mode = getattr(args, "web", False)
    if _api_daemon_ready(host, port):
        ui.status(f"WebUI API daemon is already running on http://{status_host}:{port}")
        restarted = False
        if _offer_daemon_kill():
            if _stop_running_daemon(host, port):
                ui.status("Stopped the previous WebUI API daemon; starting a fresh one.")
                restarted = True
            else:
                ui.error("Could not stop the running daemon; keeping it.")
        if not restarted:
            if web_mode:
                threading.Thread(
                    target=_webui_boot._open_browser_when_ready, args=(host, port, ui), daemon=True
                ).start()
            return 0
    try:
        import uvicorn  # noqa: F401 -- import gate
    except ImportError:
        ui.error("uvicorn is not installed. Run: python -m pip install -r requirements.txt")
        return 1
    try:
        from app import create_app
    except ImportError as exc:
        ui.error(f"Could not import the ASGI app factory (app.py): {exc}")
        return 1

    if web_mode:
        build_rc = _webui_boot._ensure_webui_build(ui, force=bool(getattr(args, "rebuild", False)))
        if build_rc != 0:
            return build_rc
        # In-memory override only; never persisted to config.yaml.
        api_cfg["serve_webui"] = True
    elif getattr(args, "rebuild", False):
        # --daemon --rebuild: the API daemon doesn't serve the SPA, but honor
        # the explicit rebuild request before starting.
        rebuild_rc = _webui_boot._rebuild_webui(ui)
        if rebuild_rc != 0:
            return rebuild_rc

    # Auto-update the model registry against the live Ollama API before the
    # app factory snapshots the config (models.auto_update, default true).
    _webui_boot._auto_update_models(config, args.config)

    ui.banner()
    base = f"http://{status_host}:{port}"
    print(f"  {ui._c('green')}*{ui._c('reset')} API ready  {ui._c('blue')}{base}{ui._c('reset')}")
    print(f"    {ui._c('gray')}{'docs':<7}{ui._c('reset')} {ui._c('blue')}{base}/docs{ui._c('reset')}")
    print(f"    {ui._c('gray')}{'openapi':<7}{ui._c('reset')} {ui._c('blue')}{base}/openapi.json{ui._c('reset')}")
    if web_mode:
        print(f"    {ui._c('gray')}{'webui':<7}{ui._c('reset')} {ui._c('blue')}{base}/{ui._c('reset')}")
    print(f"  {ui._c('gray')}{'-' * 46}{ui._c('reset')}")
    # ponytail: print the bearer token here (create_app re-reads the same file;
    # one extra read beats threading the token back through the factory).
    from tools.api.auth import load_or_create_token

    token = load_or_create_token(
        api_cfg.get("token_file", ".webui_secret_key"),
        env_override=os.environ.get("BREACHPILOT_API_TOKEN", ""),
    )
    # Single prompt — reveal token (and open browser in --web mode) so the
    # user isn't hit with two sequential "press Enter" pauses.
    if web_mode:
        print(f"  {ui._c('gray')}Press Enter to reveal API token and open browser...{ui._c('reset')}")
    else:
        print(f"  {ui._c('gray')}Press Enter to reveal API token...{ui._c('reset')}")
    try:
        input(f"  {ui._c('gray')}>{ui._c('reset')} ")
    except KeyboardInterrupt:
        return 130
    except EOFError:
        pass
    print(f"  {ui._c('gray')}token{ui._c('reset')}   {token}")
    if _copy_to_clipboard(token):
        print(f"  {ui._c('green')}copied to clipboard{ui._c('reset')} {ui._c('gray')}(Ctrl+V to paste){ui._c('reset')}")
    app = create_app(config_path=args.config, config=config)

    if web_mode:
        browser_thread = threading.Thread(
            target=_webui_boot._open_browser_when_ready,
            args=(host, port, ui),
            daemon=True,
        )
        browser_thread.start()

    print(f"  {ui._c('gray')}{'-' * 46}{ui._c('reset')}")
    print(f"  {ui._c('gray')}Logs and agent output will stream here - leave this running.{ui._c('reset')}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning" if not getattr(args, "debug", False) else "info",
        access_log=bool(getattr(args, "debug", False)),
        timeout_graceful_shutdown=shutdown_timeout,
    )
    return 0
