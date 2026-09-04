"""Sandbox-contained Playwright execution (strict fail-closed, no host fallback).

Contained runs never launch Chromium on the operator host. Instead each
browser op is executed inside the sandbox worker via ``SandboxManager`` +
``docker exec`` (``python3 -c <one-shot script>``), inside the worker netns
whose egress firewall authorizes only the effective target allowlist. The
one-shot worker script is stdlib-only + the Playwright sync API (installed in
the browser worker image); translation into ``models.*`` stays host-side in
:mod:`tools.browser.playwright_backend`, so there is exactly one translation
layer.

Session continuity across one-shot ops is explicit and bounded: the launcher
keeps ``{last_url, cookies, storage_seed, pending_net}`` per token host-side,
re-seeds cookies/``localStorage`` on every op, and accumulates network events
host-side. There is deliberately no persistent page/JS context in sandboxed
mode (documented limitation); in-process mode keeps live pages.

This module never imports ``playwright`` itself (worker-side only).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from tools.browser.errors import (
    BrowserBackendError,
    BrowserCrashed,
    BrowserNavigationFailed,
    BrowserScriptError,
    BrowserSessionNotFound,
    BrowserTimeout,
)

logger = logging.getLogger(__name__)

__all__ = [
    "BROWSER_WORKER_IMAGE",
    "SandboxPlaywrightLauncher",
    "browser_worker_image",
    "resolve_browser_launcher",
]

BROWSER_WORKER_IMAGE = "breachpilot-sandbox:browser"

_PROBE_CACHE: dict[str, bool] = {}


def browser_worker_image(config: dict[str, Any] | None = None) -> str:
    """Expected browser worker image (explicit override or the variant tag)."""
    cfg = (config or {}).get("browser", {}) or {}
    override = str(cfg.get("worker_image", "") or "").strip()
    return override or BROWSER_WORKER_IMAGE


def _bootstrap_script(dom_js: str, storage_js: str) -> str:
    """Assemble the one-shot worker script (JS extractors embedded as JSON)."""
    return (
        "import json, sys\n"
        "def _emit(payload):\n"
        "    print(json.dumps(payload, default=str))\n"
        f"DOM_JS = {json.dumps(dom_js)}\n"
        f"STORAGE_JS = {json.dumps(storage_js)}\n"
        "def main():\n"
        "    try:\n"
        "        req = json.loads(sys.argv[1])\n"
        "    except Exception as exc:\n"
        "        _emit({'ok': False, 'kind': 'error', 'error': f'bad payload: {exc}'}); return\n"
        "    op = req.get('op', '')\n"
        "    url = req.get('url', '') or ''\n"
        "    timeout_ms = int(req.get('timeout_ms') or 30000)\n"
        "    try:\n"
        "        from playwright.sync_api import sync_playwright\n"
        "    except ImportError:\n"
        "        _emit({'ok': False, 'kind': 'error', 'error': 'playwright SDK not installed in worker'}); return\n"
        "    net = []\n"
        "    def _on_request(r):\n"
        "        try:\n"
        "            net.append({'direction': 'request', 'method': r.method, 'url': r.url,\n"
        "                      'req_headers': dict(r.headers or {}), 'resource_type': r.resource_type})\n"
        "        except Exception:\n"
        "            pass\n"
        "    def _on_response(resp):\n"
        "        try:\n"
        "            headers = dict(resp.headers or {})\n"
        "            body, size = '', None\n"
        "            try:\n"
        "                ctype = str(headers.get('content-type', '')).lower()\n"
        "                declared = int(str(headers.get('content-length', '') or '-1').strip())\n"
        "                textish = ctype.startswith(('text/', 'application/json', 'application/javascript',\n"
        "                                          'application/xml', 'application/x-www-form-urlencoded'))\n"
        "                if textish and (declared < 0 or declared <= 1048576):\n"
        "                    raw = resp.body()\n"
        "                    size = len(raw)\n"
        "                    body = raw[:4096].decode('utf-8', errors='replace')\n"
        "                elif declared >= 0:\n"
        "                    size = declared\n"
        "            except Exception:\n"
        "                pass\n"
        "            net.append({'direction': 'response', 'method': resp.request.method, 'url': resp.url,\n"
        "                      'status': resp.status, 'content_type': headers.get('content-type', ''),\n"
        "                      'req_headers': dict(resp.request.headers or {}), 'resp_headers': headers,\n"
        "                      'resource_type': resp.request.resource_type, 'body': body, 'body_size': size})\n"
        "        except Exception:\n"
        "            pass\n"
        "    with sync_playwright() as pw:\n"
        "        try:\n"
        "            browser = pw.chromium.launch(headless=True,\n"
        "                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'])\n"
        "        except Exception as exc:\n"
        "            _emit({'ok': False, 'kind': 'crash', 'error': f'launch failed: {exc}'}); return\n"
        "        try:\n"
        "            context = browser.new_context(accept_downloads=False)\n"
        "            cookies = req.get('cookies') or []\n"
        "            if cookies:\n"
        "                try:\n"
        "                    context.add_cookies(cookies)\n"
        "                except Exception:\n"
        "                    pass\n"
        "            seed = req.get('storage_seed') or {}\n"
        "            if seed:\n"
        "                try:\n"
        "                    context.add_init_script(\n"
        "                        'Object.entries(' + json.dumps(seed) + ').forEach(([k,v]) => {'\n"
        "                        ' try { localStorage.setItem(k, v); } catch(e) {} })')\n"
        "                except Exception:\n"
        "                    pass\n"
        "            page = context.new_page()\n"
        "            page.on('request', _on_request)\n"
        "            page.on('response', _on_response)\n"
        "            data = _do_op(page, op, req, url, timeout_ms)\n"
        "            try:\n"
        "                new_cookies = context.cookies()\n"
        "            except Exception:\n"
        "                new_cookies = []\n"
        "            stores = {}\n"
        "            try:\n"
        "                stores = {'local': page.evaluate(STORAGE_JS, 'local') or {},\n"
        "                        'session': page.evaluate(STORAGE_JS, 'session') or {}}\n"
        "            except Exception:\n"
        "                pass\n"
        "            _emit({'ok': True, 'data': data, 'net': net, 'cookies': new_cookies,\n"
        "                 'stores': stores, 'final_url': page.url})\n"
        "        except Exception as exc:\n"
        "            name = type(exc).__name__\n"
        "            text = str(exc)\n"
        "            if 'Timeout' in name or 'timed out' in text.lower():\n"
        "                kind = 'timeout'\n"
        "            elif 'has been closed' in text or 'Closed' in name:\n"
        "                kind = 'crash'\n"
        "            elif op == 'navigate' or 'net::' in text or 'ERR_' in text:\n"
        "                kind = 'navigation'\n"
        "            elif op == 'evaluate':\n"
        "                kind = 'script'\n"
        "            else:\n"
        "                kind = 'error'\n"
        "            _emit({'ok': False, 'kind': kind, 'error': text, 'net': net})\n"
        "        finally:\n"
        "            try:\n"
        "                browser.close()\n"
        "            except Exception:\n"
        "                pass\n"
        "def _do_op(page, op, req, url, timeout_ms):\n"
        "    if op in ('navigate', 'snapshot'):\n"
        "        if not url:\n"
        "            raise ValueError('navigate first: no page loaded')\n"
        "        resp = page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)\n"
        "        try:\n"
        "            page.wait_for_load_state('networkidle', timeout=min(timeout_ms // 2, 10000))\n"
        "        except Exception:\n"
        "            pass\n"
        "        final = page.url or url\n"
        "        out = {'url': url, 'final_url': final,\n"
        "               'status': (resp.status if resp is not None else None),\n"
        "               'redirect_chain': ([url] if final == url else [url, final])}\n"
        "        if op == 'snapshot':\n"
        "            out.update(_collect(page))\n"
        "        for extra in list(page.context.pages)[1:]:\n"
        "            try:\n"
        "                extra.close()\n"
        "            except Exception:\n"
        "                pass\n"
        "        return out\n"
        "    if op == 'evaluate':\n"
        "        value = page.evaluate(req.get('expression', ''))\n"
        "        try:\n"
        "            rendered = json.dumps(value, default=str)\n"
        "        except Exception:\n"
        "            rendered = str(value)\n"
        "        return {'ok': True, 'value': rendered[:4000], 'truncated': len(rendered) > 4000}\n"
        "    if op == 'screenshot':\n"
        "        import base64 as _b64\n"
        "        raw = page.screenshot(full_page=bool(req.get('full_page', False)), timeout=timeout_ms)\n"
        "        return {'png_base64': _b64.b64encode(bytes(raw)).decode('ascii')}\n"
        "    raise ValueError(f'unknown op {op!r}')\n"
        "def _collect(page):\n"
        "    data = page.evaluate(DOM_JS) or {}\n"
        "    if not isinstance(data, dict):\n"
        "        data = {}\n"
        "    return {'title': str(data.get('title', '') or page.title or ''),\n"
        "            'text': str(data.get('text', '') or ''),\n"
        "            'forms': data.get('forms') if isinstance(data.get('forms'), list) else [],\n"
        "            'scripts': [str(s) for s in (data.get('scripts') or []) if s],\n"
        "            'head': str(data.get('head', '') or '')}\n"
        "main()\n"
    )


def _raise_for_worker_result(result: dict[str, Any], op: str) -> dict[str, Any]:
    """Map a worker ``{ok, kind, error}`` envelope onto typed errors (or data)."""
    if result.get("ok"):
        return result
    kind = str(result.get("kind", "error") or "error")
    message = str(result.get("error", "") or f"browser worker {op} failed")
    if kind == "timeout":
        raise BrowserTimeout(f"browser {op} timed out in worker: {message}")
    if kind == "crash":
        raise BrowserCrashed(f"browser {op}: worker chromium died: {message}")
    if kind == "navigation":
        raise BrowserNavigationFailed(f"browser navigate failed: {message}")
    if kind == "script":
        raise BrowserScriptError(f"browser javascript failed: {message}")
    raise BrowserBackendError(f"browser worker {op} failed: {message}")


class SandboxPlaywrightLauncher:
    """One Chromium op per ``docker exec`` inside the sandbox worker netns."""

    kind = "sandbox_worker"

    def __init__(self, manager: Any, config: dict[str, Any] | None = None) -> None:
        self._manager = manager
        self._config = dict(config or {})
        self._states: dict[str, dict[str, Any]] = {}
        from tools.browser.playwright_backend import DOM_EXTRACT_JS, STORAGE_DUMP_JS

        self._script = _bootstrap_script(DOM_EXTRACT_JS, STORAGE_DUMP_JS)

    def _state(self, token: str) -> dict[str, Any]:
        try:
            return self._states[token]
        except KeyError:
            raise BrowserSessionNotFound(f"unknown browser engine session for token {token!r}") from None

    async def launch(self, *, headless: bool = True, capture_console: bool = False) -> str:  # noqa: ARG002
        token = f"sbw-{uuid.uuid4().hex[:12]}"
        self._states[token] = {"last_url": "", "cookies": [], "storage_seed": {}, "pending_net": []}
        return token

    async def _exec(
        self, payload: dict[str, Any], *, timeout_s: float, target_ip: str, tool_name: str
    ) -> dict[str, Any]:
        import json as _json

        argv = ["python3", "-c", self._script, _json.dumps(payload, default=str)]
        # SandboxError subclasses propagate untouched: the MCP layer turns them
        # into SANDBOX_* blocks (fail closed, never host fallback).
        result = await asyncio.to_thread(
            self._manager.execute_argv,
            argv,
            timeout=int(timeout_s),
            target_ip=target_ip,
            tool_name=tool_name or "browser",
        )
        if getattr(result, "timed_out", False):
            raise BrowserTimeout(f"browser worker op timed out after {timeout_s:g}s")
        if (getattr(result, "exit_code", 1) or 1) != 0:
            stderr = str(getattr(result, "stderr", "") or "")[-2000:]
            raise BrowserCrashed(f"browser worker op failed (exit {result.exit_code}): {stderr}")
        stdout = str(getattr(result, "stdout", "") or "").strip()
        try:
            parsed = _json.loads(stdout)
        except Exception as exc:
            raise BrowserCrashed(f"browser worker returned unparsable output: {exc}: {stdout[-500:]}") from exc
        if not isinstance(parsed, dict):
            raise BrowserCrashed(f"browser worker returned unexpected output shape: {stdout[-500:]}")
        return parsed

    def _absorb(self, state: dict[str, Any], envelope: dict[str, Any]) -> None:
        for event in envelope.get("net") or []:
            if isinstance(event, dict):
                state["pending_net"].append(event)
        if envelope.get("cookies"):
            state["cookies"] = envelope["cookies"]
        stores = envelope.get("stores") or {}
        seed: dict[str, str] = {}
        for area in ("local", "session"):
            store = stores.get(area) or {}
            if isinstance(store, dict):
                for key, value in list(store.items())[:200]:
                    seed[str(key)] = str(value)[:2048]
        if seed:
            state["storage_seed"] = seed
        if envelope.get("final_url"):
            state["last_url"] = str(envelope["final_url"])

    async def navigate(self, token: str, url: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        state = self._state(token)
        envelope = await self._exec(
            {"op": "navigate", "url": url, "cookies": state["cookies"], "timeout_ms": timeout_ms},
            timeout_s=timeout_ms / 1000.0 + 60.0,
            target_ip=target_ip,
            tool_name="browser_navigate",
        )
        data = _raise_for_worker_result(envelope, "navigate")
        self._absorb(state, envelope)
        payload = dict(data.get("data") or {})
        state["last_url"] = str(payload.get("final_url", "") or url)
        payload.setdefault("blocked_popups", 0)
        return payload

    async def snapshot(self, token: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        state = self._state(token)
        if not state["last_url"]:
            raise BrowserNavigationFailed("navigate first: no page loaded in this session")
        envelope = await self._exec(
            {
                "op": "snapshot",
                "url": state["last_url"],
                "cookies": state["cookies"],
                "storage_seed": state["storage_seed"],
                "timeout_ms": timeout_ms,
            },
            timeout_s=timeout_ms / 1000.0 + 60.0,
            target_ip=target_ip,
            tool_name="browser_observe",
        )
        data = _raise_for_worker_result(envelope, "snapshot")
        self._absorb(state, envelope)
        payload = dict(data.get("data") or {})
        cookies = envelope.get("cookies") or []
        stores = envelope.get("stores") or {}
        return {
            "url": str(payload.get("final_url", "") or state["last_url"]),
            "title": str(payload.get("title", "") or ""),
            "text": str(payload.get("text", "") or ""),
            "forms": payload.get("forms") or [],
            "scripts": payload.get("scripts") or [],
            "head": payload.get("head", "") or "",
            "cookies": cookies if isinstance(cookies, list) else [],
            "local_storage": stores.get("local") if isinstance(stores.get("local"), dict) else {},
            "session_storage": stores.get("session") if isinstance(stores.get("session"), dict) else {},
        }

    async def evaluate(self, token: str, expression: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        state = self._state(token)
        if not state["last_url"]:
            raise BrowserNavigationFailed("navigate first: no page loaded in this session")
        envelope = await self._exec(
            {
                "op": "evaluate",
                "url": state["last_url"],
                "expression": expression,
                "cookies": state["cookies"],
                "storage_seed": state["storage_seed"],
                "timeout_ms": timeout_ms,
            },
            timeout_s=timeout_ms / 1000.0 + 60.0,
            target_ip=target_ip,
            tool_name="browser_execute_js",
        )
        data = _raise_for_worker_result(envelope, "evaluate")
        self._absorb(state, envelope)
        return dict(data.get("data") or {"ok": True, "value": ""})

    async def screenshot(
        self, token: str, *, full_page: bool = False, timeout_ms: int = 30000, target_ip: str = ""
    ) -> bytes:
        import base64 as _b64

        state = self._state(token)
        if not state["last_url"]:
            raise BrowserNavigationFailed("navigate first: no page loaded in this session")
        envelope = await self._exec(
            {
                "op": "screenshot",
                "url": state["last_url"],
                "full_page": bool(full_page),
                "cookies": state["cookies"],
                "storage_seed": state["storage_seed"],
                "timeout_ms": timeout_ms,
            },
            timeout_s=timeout_ms / 1000.0 + 60.0,
            target_ip=target_ip,
            tool_name="browser_screenshot",
        )
        data = _raise_for_worker_result(envelope, "screenshot")
        payload = dict(data.get("data") or {})
        self._absorb(state, envelope)
        raw = str(payload.get("png_base64", "") or "")
        try:
            return _b64.b64decode(raw) if raw else b""
        except Exception as exc:
            raise BrowserCrashed(f"browser worker returned corrupt screenshot bytes: {exc}") from exc

    async def take_network(
        self, token: str, *, body_sample_max_bytes: int = 4096, target_ip: str = ""
    ) -> list[dict[str, Any]]:  # noqa: ARG002
        state = self._state(token)
        pending = list(state["pending_net"])
        state["pending_net"].clear()
        for event in pending:
            body = str(event.get("body", "") or "")
            if len(body.encode("utf-8", errors="replace")) > body_sample_max_bytes:
                event["body"] = body.encode("utf-8", errors="replace")[:body_sample_max_bytes].decode(
                    "utf-8", errors="replace"
                )
            event.setdefault("observed_at", "")
        return pending

    def drain_console(self, token: str) -> list[dict[str, str]]:  # noqa: ARG002
        # Console capture is an in-process-mode facility; worker one-shot ops do
        # not stream console events (documented limitation).
        return []

    async def close(self, token: str) -> None:
        self._states.pop(token, None)


def _worker_has_playwright(manager: Any, image: str) -> bool:
    """Probe the live worker for the Playwright SDK (cached per image)."""
    cached = _PROBE_CACHE.get(image)
    if cached is not None:
        return cached
    try:
        result = manager.execute_argv(
            ["python3", "-c", "import playwright; print('pw-ok')"],
            timeout=60,
            target_ip="",
            tool_name="browser_preflight",
        )
        ok = bool(result is not None and "pw-ok" in str(getattr(result, "stdout", "") or ""))
    except Exception:  # noqa: BLE001 — probe failure means "not usable"
        ok = False
    _PROBE_CACHE[image] = ok
    return ok


def resolve_browser_launcher(ctx: Any, config: dict[str, Any] | None) -> tuple[Any | None, str]:
    """Pick the browser engine launcher for this MCP call.

    Returns ``(launcher, "")`` on success, or ``(None, block)`` where ``block``
    is a ``SANDBOX_*`` result string the tool must return verbatim. Browser
    execution is STRICT fail-closed: when the sandbox is enabled but unusable
    it blocks even if ``sandbox.fallback_native`` is true (the native fallback
    covers terminal/Python execution only — never Chromium).
    """
    from tools.browser.playwright_backend import InProcessPlaywrightLauncher
    from tools.sandbox.mcp_bridge import manager_from_ctx, sandbox_block
    from tools.sandbox.models import SandboxConfig

    sandbox_cfg = SandboxConfig.from_config(config)
    if not sandbox_cfg.enabled:
        # Explicit operator opt-out (documented legacy host-execution mode).
        return InProcessPlaywrightLauncher(), ""
    manager = manager_from_ctx(ctx)
    if manager is None:
        from tools.sandbox.exceptions import SandboxUnavailableError as _Unavailable

        return None, sandbox_block(
            _Unavailable(
                "browser execution requires the sandbox worker, but no session manager is attached "
                "(sandbox.enabled:true with an unusable Docker stack). Refusing host Chromium execution "
                "(fail closed — the browser never inherits the native fallback)."
            ),
            tool_name="browser",
        )
    image = str(getattr(getattr(manager, "cfg", None), "image", "") or browser_worker_image(config))
    if not _worker_has_playwright(manager, image):
        from tools.sandbox.exceptions import SandboxUnavailableError as _Unavailable

        expected = browser_worker_image(config)
        return None, sandbox_block(
            _Unavailable(
                f"browser worker image {image!r} has no Playwright/Chromium. Build the browser worker "
                f"(docker build -t {expected} -f docker/sandbox/Dockerfile.browser docker/sandbox) "
                f"and point sandbox.image at it (the browser variant is a superset of the base worker)."
            ),
            tool_name="browser",
        )
    return SandboxPlaywrightLauncher(manager, config), ""
