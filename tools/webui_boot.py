"""WebUI/browser boot helpers for the BreachPilot entry point.

Moved verbatim out of ``main.py`` (p2-03 split) — no behavior change.
``ui``/``load_config`` are module globals so ``main._sync_boot_symbols``
can propagate test monkeypatches. ``REPO_ROOT`` anchors ``webui/`` exactly
where ``main.py``'s ``Path(__file__).resolve().parent`` did
(``tools/webui_boot.py`` sits one level deeper, hence ``parent.parent``).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import time
import webbrowser
from pathlib import Path
from typing import Any

from tools.attack_ui import get_ui
from tools.config_cli import load_config

ui = get_ui()

REPO_ROOT = Path(__file__).resolve().parent.parent

__all__ = [
    "_auto_update_models",
    "_ensure_chatgpt_runtime",
    "_ensure_webui_build",
    "_install_bun",
    "_open_browser_when_ready",
    "_rebuild_webui",
]


def _ensure_webui_build(ui: Any, *, force: bool = False) -> int:
    """Build webui/dist/ if missing (or always, when ``force`` is set). Returns 0 on success, non-zero on failure."""
    webui_dir = REPO_ROOT / "webui"
    dist_index = webui_dir / "dist" / "index.html"
    if dist_index.exists() and not force:
        return 0
    npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
    node_cmd = shutil.which("node") or shutil.which("nodejs")
    if not npm_cmd or not node_cmd:
        ui.error("Node/npm not found on PATH. Install Node.js, or build the WebUI manually:")
        ui.error(f"  cd {webui_dir} && npm ci && npm run build")
        return 1
    ui.status("Rebuilding the WebUI..." if force else "Building the WebUI (first run only)...")
    # Prefer `npm ci` for reproducible installs when package-lock.json exists;
    # fall back to `npm install` for source checkouts without a lockfile.
    lockfile = webui_dir / "package-lock.json"
    install_argv = (
        [npm_cmd, "ci", "--no-audit", "--no-fund"]
        if lockfile.is_file()
        else [npm_cmd, "install", "--no-audit", "--no-fund"]
    )
    for step in (("install", install_argv), ("build", [npm_cmd, "run", "build"])):
        label, argv = step
        ui.status(f"  npm {label}...")
        try:
            result = subprocess.run(argv, cwd=str(webui_dir), capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            ui.error(f"npm {label} timed out.")
            return 1
        except OSError as exc:
            ui.error(f"npm {label} failed: {exc}")
            return 1
        if result.returncode != 0:
            ui.error(f"npm {label} exited {result.returncode}.")
            stderr_tail = (result.stderr or "")[-1500:]
            if stderr_tail:
                ui.error(stderr_tail)
            return 1
    if not dist_index.exists():
        ui.error(f"Build finished but {dist_index} was not produced.")
        return 1
    ui.status("WebUI build complete.")
    return 0


def _rebuild_webui(ui: Any) -> int:
    """Force a clean rebuild of the WebUI (``npm install`` + ``npm run build``), even when dist/ exists.

    Used by ``--rebuild`` to pick up WebUI updates after a ``git pull``. Returns 0 on success.
    """
    return _ensure_webui_build(ui, force=True)


def _install_bun(ui: Any) -> bool:
    """Install the pinned bun release (ChatGPT provider). Returns True on success.

    Thin back-compat wrapper around :mod:`tools.chatgpt_bootstrap` — see
    that module for the pinned ``BUN_VERSION`` and the safety rationale (no
    remote-script piping, pinned npm package only, actionable manual
    message when automatic install is unavailable).
    """
    from tools.chatgpt_bootstrap import install_bun

    return install_bun(ui)


def _ensure_chatgpt_runtime(args: argparse.Namespace) -> int:
    """Ensure the ChatGPT (openai-oauth) provider is runnable.

    Thin back-compat wrapper around
    :func:`tools.chatgpt_bootstrap.ensure_chatgpt_runtime` — see that module
    for the pinned ``BUN_VERSION`` / ``OPENAI_OAUTH_*`` revisions and the
    safety rationale (no remote-script piping, HEAD verified before anything
    runs, ``--frozen-lockfile``, no ``shell=True``).

    Returns 0 on success or when the ChatGPT provider is not active; non-zero
    only when a required step fails AND the operator is about to use the
    ChatGPT provider.
    """
    from tools.chatgpt_bootstrap import ensure_chatgpt_runtime
    from tools.config_manager import get_ai_provider, get_chatgpt_config

    try:
        config = load_config(args.config)
    except Exception as exc:  # noqa: BLE001 -- corrupt config must not crash the provider probe; fall through as non-chatgpt
        ui.warning(f"Could not read config ({args.config}): {exc} — skipping ChatGPT runtime setup.")
        config = {}
    if get_ai_provider(config) != "chatgpt":
        return 0

    chatgpt_cfg = get_chatgpt_config(config)
    return ensure_chatgpt_runtime(
        provider="chatgpt",
        local_repo=str(chatgpt_cfg.get("local_repo") or "./oauth"),
        ui=ui,
    )


def _open_browser_when_ready(host: str, port: int, ui: Any) -> None:
    """Poll the health endpoint, then open the browser. Daemon thread."""
    import urllib.request

    base = f"http://{host}:{port}/" if host != "::1" else f"http://[::1]:{port}/"
    health_url = f"{base}api/v1/health"
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=2) as resp:  # noqa: S310 -- loopback only
                if resp.status == 200:
                    break
        except OSError:
            time.sleep(0.5)
    else:
        ui.warning("Could not confirm the API was ready; open the browser manually.")
        return
    try:
        webbrowser.open(base)
    except Exception as exc:  # noqa: BLE001 -- headless/text browsers
        ui.warning(f"Could not open the browser automatically: {exc}")
        ui.status(f"  Open {base} manually.")


def _auto_update_models(config: dict[str, Any], config_path: str) -> None:
    """Best-effort ``models.registry`` sync against the Ollama API (boot hook).

    Gated by ``models.auto_update`` (default true, ollama provider only); never
    raises. Bumps each registry alias to the newest same-family version the
    Ollama host lists (``glm-5.2:cloud`` -> ``glm-5.3:cloud``) — no pulls, the
    registry stores ids. See ``tools/ollama_models.py``.
    """
    try:
        from tools.ollama_models import auto_refresh_on_startup

        result = auto_refresh_on_startup(config, config_path=config_path)
    except Exception as exc:  # noqa: BLE001 -- advisory only, never blocks the daemon
        ui.warning(f"Model auto-update skipped: {type(exc).__name__}: {exc}")
        return
    if not result:
        return
    updates = result.get("updates") or {}
    if updates:
        ui.status("Model auto-update: " + ", ".join(f"{a}: {u['old']} -> {u['new']}" for a, u in updates.items()))
    else:
        ui.status(
            f"Model registry current ({result.get('available_count', 0)} models on {result.get('host', 'Ollama')})."
        )
