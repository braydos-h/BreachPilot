"""Playwright-backed browser engine (optional ``browser`` extra).

This is the ONLY module (besides :mod:`tools.browser.sandbox_launcher` and
:mod:`tools.browser._pw_probe`) allowed to import the ``playwright`` SDK
(enforced by ``tests/test_no_playwright_regression.py``). No Playwright object
(``Browser``/``BrowserContext``/``Page``/``Request``/``Response``/handles)
escapes this module — every method translates at the boundary into
:mod:`tools.browser.models` types.

Execution topology: the backend drives Chromium through a swappable
*launcher*. :class:`InProcessPlaywrightLauncher` runs Chromium in-process
(host dev / legacy ``sandbox.enabled: false`` opt-out). Contained runs use
``SandboxPlaywrightLauncher`` (``tools/browser/sandbox_launcher.py``), which
executes one Chromium op per ``docker exec`` inside the sandbox worker netns —
no host fallback, ever. The backend NEVER touches the target allowlist itself;
the MCP layer + netns firewall own policy (see ``BrowserBackend`` contract).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import urllib.parse
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.browser._pw_probe import MISSING_DEP_MSG, chromium_present, playwright_present, playwright_version
from tools.browser.errors import (
    BrowserBackendError,
    BrowserBackendUnavailable,
    BrowserCrashed,
    BrowserNavigationFailed,
    BrowserScriptError,
    BrowserSessionNotFound,
    BrowserTimeout,
    browser_error_from_exception,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import (
    BrowserAction,
    BrowserActionKind,
    BrowserArtifact,
    BrowserArtifactKind,
    BrowserError,
    BrowserEventDirection,
    BrowserFailureClass,
    BrowserNetworkEvent,
    BrowserObservation,
    BrowserObservationKind,
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionState,
    BrowserStorageKind,
    BrowserStorageSnapshot,
    _mask_body,
    new_session_id,
)

logger = logging.getLogger(__name__)

__all__ = [
    "PlaywrightBackend",
    "InProcessPlaywrightLauncher",
    "BROWSER_WORKER_IMAGE",
    "DOM_EXTRACT_JS",
    "STORAGE_DUMP_JS",
    "FORM_FILL_SUBMIT_JS",
]

#: Default sandbox browser-worker image (variant of the base worker + Playwright/Chromium).
BROWSER_WORKER_IMAGE = "breachpilot-sandbox:browser"

# ── Bounds (config-overridable via the ``browser:`` block) ────────────────
_DOM_SUMMARY_MAX_CHARS = 8000
_BODY_SAMPLE_MAX_BYTES = 4096
_NETWORK_MAX_EVENTS = 500
_CONSOLE_MAX_EVENTS = 200
_MAX_FORMS = 50
_MAX_FORM_FIELDS = 20
_MAX_SCRIPTS = 100
_MAX_INDICATORS = 20
_MAX_STORAGE_ENTRIES = 200
_STORAGE_VALUE_MAX_CHARS = 2048
_JS_MAX_CHARS = 8192
_JS_PREVIEW_MAX_CHARS = 500
_MAX_SUBMIT_FIELDS = 20
_SUBMIT_VALUE_MAX_CHARS = 2000
_REPLAY_BODY_MAX_BYTES = 4096
_REPLAY_PREVIEW_MAX_CHARS = 2000
_REPLAY_MAX_HEADERS = 20
_LAUNCH_TIMEOUT_SECONDS = 60.0
_MAX_WAIT_SECONDS = 30.0

_CRASH_NAMES = ("TargetClosed", "BrowserClosed", "ConnectionClosed")

#: One evaluate() harvesting title/text/forms/scripts + an HTML head sample for
#: framework indicators. Returns JSON-serializable data only; raw HTML never
#: leaves the page (indicators are computed host-side from the sample).
DOM_EXTRACT_JS = """() => {
  const doc = document;
  const bodyText = (doc.body && doc.body.innerText) || "";
  const forms = Array.prototype.slice.call(doc.forms || []).map((f) => ({
    action: f.getAttribute("action") || "",
    method: ((f.getAttribute("method") || "get") + "").toLowerCase(),
    inputs: Array.prototype.slice.call(f.elements || [])
      .filter((el) => el && el.name)
      .slice(0, 20)
      .map((el) => ({name: el.name + "", type: (el.type || "text") + ""})),
  }));
  const scripts = Array.prototype.slice.call(doc.scripts || [])
    .map((s) => s.src || "")
    .filter(Boolean);
  const head = doc.documentElement
    ? (doc.documentElement.outerHTML || "").slice(0, 20000)
    : "";
  return {title: doc.title || "", text: bodyText, forms: forms, scripts: scripts, head: head};
}"""

#: Dump one web-storage area as {key: value} (bounded host-side).
STORAGE_DUMP_JS = """(area) => {
  const store = area === "session" ? window.sessionStorage : window.localStorage;
  const out = {};
  try {
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i);
      if (k !== null && k !== undefined) out[k + ""] = (store.getItem(k) || "") + "";
    }
  } catch (e) { out.__error__ = (e && e.message) || "unavailable"; }
  return out;
}"""

#: Fill one form's fields by name, then submit it. Fills + submits in a single
#: evaluate() so the returned info resolves before navigation commits; the
#: caller settles + harvests (final URL, status) afterwards. Returns
#: JSON-serializable data only.
FORM_FILL_SUBMIT_JS = """([idx, fields]) => {
  const f = document.forms[idx];
  if (!f) return {ok: false, error: "no such form index " + idx + " (" + document.forms.length + " forms)"};
  let filled = 0;
  for (const entry of Object.entries(fields || {})) {
    const name = entry[0] + "", value = entry[1] + "";
    const el = f.elements.namedItem(name);
    if (!el) continue;
    try {
      const targets = (typeof RadioNodeList !== "undefined" && el instanceof RadioNodeList)
        ? Array.prototype.slice.call(el) : [el];
      for (const t of targets) {
        const type = ((t.type || "text") + "").toLowerCase();
        if (type === "checkbox") t.checked = !(value === "" || value === "0" || value.toLowerCase() === "false");
        else if (type === "radio") t.checked = ((t.value || "on") + "" === value);
        else t.value = value;
        t.dispatchEvent(new Event("input", {bubbles: true}));
        t.dispatchEvent(new Event("change", {bubbles: true}));
      }
      filled++;
    } catch (e) {}
  }
  const info = {ok: true, action: f.getAttribute("action") || "",
    method: ((f.getAttribute("method") || "get") + ""), filled: filled,
    form_count: document.forms.length};
  try { if (f.requestSubmit) f.requestSubmit(); else f.submit(); }
  catch (e) { return {ok: false, error: "submit failed: " + ((e && e.message) || e)}; }
  return info;
}"""

_INDICATOR_MARKERS: tuple[tuple[str, str], ...] = (
    ("__next_data__", "next.js"),
    ("_next/static", "next.js"),
    ("react", "react"),
    ("react-dom", "react"),
    ("vue", "vue"),
    ("nuxt", "nuxt"),
    ("ng-version", "angular"),
    ("angular", "angular"),
    ("svelte", "svelte"),
    ("wordpress", "wordpress"),
    ("wp-content", "wordpress"),
    ("wp-json", "wordpress"),
    ("wp-includes", "wordpress"),
    ("drupal", "drupal"),
    ("csrftoken", "django"),
    ("rails", "rails"),
    ("laravel", "laravel"),
    ("/graphql", "graphql"),
    ("graphql", "graphql"),
    ("jquery", "jquery"),
    ('<div id="root"', "spa-root"),
    ('<div id="app"', "spa-app"),
)

_STATIC_ASSET_EXTS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".css",
        ".map",
    }
)


def _utcnow() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _browser_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    """Accept a full config or a bare ``browser:`` block."""
    cfg = config or {}
    nested = cfg.get("browser")
    if isinstance(nested, dict):
        return nested
    return cfg if isinstance(cfg, dict) else {}


def _int_cfg(cfg: dict[str, Any], key: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(cfg.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _summarize_text(text: str, max_chars: int) -> str:
    collapsed = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[:max_chars] + f"…[truncated {len(collapsed) - max_chars} chars]"


def _detect_indicators(head: str, scripts: list[str]) -> list[str]:
    blob = f"{head or ''}\n" + "\n".join(scripts or [])
    low = blob.lower()
    found = sorted({label for marker, label in _INDICATOR_MARKERS if marker in low})
    return found[:_MAX_INDICATORS]


def _is_crash_name(exc: BaseException) -> bool:
    name = type(exc).__name__
    if any(token in name for token in _CRASH_NAMES):
        return True
    text = ""
    try:
        text = str(exc)
    except Exception:  # noqa: BLE001 — never mask the caller
        text = ""
    return "Browser has been closed" in text or "Target has been closed" in text


def _map_launch_error(exc: Exception) -> BrowserBackendError:
    if isinstance(exc, TimeoutError) or "Timeout" in type(exc).__name__:
        return BrowserTimeout(f"chromium launch timed out: {exc}")
    if _is_crash_name(exc):
        return BrowserCrashed(f"chromium crashed during launch: {exc}")
    return BrowserBackendUnavailable(f"could not launch chromium ({exc}); {MISSING_DEP_MSG}")


def _map_op_error(exc: Exception, op: str) -> BrowserBackendError:
    if isinstance(exc, BrowserBackendError):
        return exc
    if isinstance(exc, TimeoutError) or "Timeout" in type(exc).__name__:
        return BrowserTimeout(f"browser {op} timed out: {exc}")
    if _is_crash_name(exc):
        return BrowserCrashed(f"browser {op}: chromium session died: {exc}")
    if op == "navigate":
        return BrowserNavigationFailed(f"browser navigate failed: {exc}")
    if op == "evaluate":
        return BrowserScriptError(f"browser javascript failed: {exc}")
    code, message = browser_error_from_exception(exc)
    err = BrowserBackendError(f"browser {op} failed: {message}")
    err.code = code
    return err


# ── Launcher interface ────────────────────────────────────────────────────
# Duck-typed: launch/navigate/snapshot/evaluate/screenshot/take_network/close.
# Raw dicts cross this seam (never Playwright objects); the backend translates
# them into models.* — so the sandbox worker-script path shares one translation.


class InProcessPlaywrightLauncher:
    """Run Chromium in this process (host dev / legacy uncontained opt-out)."""

    kind = "in_process"

    def __init__(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}

    # -- lifecycle --
    async def launch(self, *, headless: bool = True, capture_console: bool = False) -> str:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise BrowserBackendUnavailable(MISSING_DEP_MSG) from None
        try:
            pw = await async_playwright().start()
        except Exception as exc:
            raise _map_launch_error(exc) from exc
        try:
            browser = await pw.chromium.launch(
                headless=headless,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = await browser.new_context(accept_downloads=False)
            page = await context.new_page()
        except Exception as exc:
            try:
                await pw.stop()
            except Exception:  # noqa: BLE001 — launch cleanup is best-effort
                pass
            raise _map_launch_error(exc) from exc
        token = f"pw-{uuid.uuid4().hex[:12]}"
        state: dict[str, Any] = {
            "pw": pw,
            "browser": browser,
            "context": context,
            "page": page,
            "net": deque(maxlen=1000),
            "console": deque(maxlen=400),
            "capture_console": bool(capture_console),
        }

        def _on_request(req: Any) -> None:
            try:
                state["net"].append(
                    {
                        "direction": "request",
                        "method": str(getattr(req, "method", "") or ""),
                        "url": str(getattr(req, "url", "") or ""),
                        "req_headers": dict(getattr(req, "headers", {}) or {}),
                        "resource_type": str(getattr(req, "resource_type", "") or ""),
                        "observed_at": _utcnow(),
                    }
                )
            except Exception:  # noqa: BLE001 — listeners never break the page
                pass

        def _on_response(resp: Any) -> None:
            try:
                req = getattr(resp, "request", None)
                headers = dict(getattr(resp, "headers", {}) or {})
                timing_ms: float | None = None
                try:
                    timing = (getattr(req, "timing", None) or {}) if req is not None else {}
                    if timing.get("responseStart", -1) >= 0 and timing.get("start", -1) >= 0:
                        timing_ms = float(timing["responseStart"] - timing["start"])
                except Exception:  # noqa: BLE001 — timing is best-effort
                    timing_ms = None
                state["net"].append(
                    {
                        "direction": "response",
                        "method": str(getattr(req, "method", "") or "") if req is not None else "",
                        "url": str(getattr(resp, "url", "") or ""),
                        "status": getattr(resp, "status", None),
                        "content_type": str(headers.get("content-type", "") or ""),
                        "req_headers": dict(getattr(req, "headers", {}) or {}) if req is not None else {},
                        "resp_headers": headers,
                        "resource_type": str(getattr(req, "resource_type", "") or "") if req is not None else "",
                        "timing_ms": timing_ms,
                        "observed_at": _utcnow(),
                        "_resp": resp,
                    }
                )
            except Exception:  # noqa: BLE001 — listeners never break the page
                pass

        def _on_console(msg: Any) -> None:
            if not state["capture_console"]:
                return
            try:
                state["console"].append(
                    {"type": str(getattr(msg, "type", "") or ""), "text": str(getattr(msg, "text", "") or "")[:2000]}
                )
            except Exception:  # noqa: BLE001 — listeners never break the page
                pass

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("console", _on_console)
        self._states[token] = state
        return token

    def _state(self, token: str) -> dict[str, Any]:
        try:
            return self._states[token]
        except KeyError:
            raise BrowserSessionNotFound(f"unknown browser engine session for token {token!r}") from None

    async def _close_extras(self, state: dict[str, Any]) -> int:
        """Close popup tabs (auto-deny new-tab navigation); return count."""
        closed = 0
        try:
            pages = list(state["context"].pages)
        except Exception:  # noqa: BLE001 — context may be dead
            return 0
        for extra in pages[1:]:
            try:
                await extra.close()
                closed += 1
            except Exception:  # noqa: BLE001 — best-effort
                pass
        return closed

    async def navigate(self, token: str, url: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        blocked_popups = await self._close_extras(state)
        page = state["page"]
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            raise _map_op_error(exc, "navigate") from exc
        try:  # best-effort SPA settle; never fails the navigation itself
            await page.wait_for_load_state("networkidle", timeout=min(timeout_ms // 2, 10000))
        except Exception:  # noqa: BLE001 — settle is advisory
            pass
        try:
            final_url = str(page.url or url)
        except Exception:  # noqa: BLE001 — page may be gone
            final_url = url
        status = getattr(resp, "status", None) if resp is not None else None
        chain = [url] if final_url == url else [url, final_url]
        return {
            "url": url,
            "final_url": final_url,
            "status": status,
            "redirect_chain": chain,
            "blocked_popups": blocked_popups,
        }

    async def snapshot(self, token: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        await self._close_extras(state)
        page, context = state["page"], state["context"]
        try:
            title = await page.title()
            cur_url = str(page.url or "")
            data = await page.evaluate(DOM_EXTRACT_JS)
            cookies = await context.cookies()
        except Exception as exc:
            raise _map_op_error(exc, "snapshot") from exc
        local: dict[str, str] = {}
        sess: dict[str, str] = {}
        try:
            local = dict(await page.evaluate(STORAGE_DUMP_JS, "local") or {})
            sess = dict(await page.evaluate(STORAGE_DUMP_JS, "session") or {})
        except Exception:  # noqa: BLE001 — storage dump is best-effort
            pass
        if not isinstance(data, dict):
            data = {"title": title, "text": "", "forms": [], "scripts": [], "head": ""}
        data["title"] = data.get("title") or title
        return {
            "url": cur_url,
            "title": str(data.get("title", "") or ""),
            "text": str(data.get("text", "") or ""),
            "forms": data.get("forms") if isinstance(data.get("forms"), list) else [],
            "scripts": [str(s) for s in (data.get("scripts") or []) if s],
            "head": str(data.get("head", "") or ""),
            "cookies": cookies if isinstance(cookies, list) else [],
            "local_storage": local,
            "session_storage": sess,
        }

    async def evaluate(self, token: str, expression: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        try:
            value = await asyncio.wait_for(state["page"].evaluate(expression), timeout=timeout_ms / 1000.0)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise BrowserTimeout(f"browser javascript timed out: {expression[:120]}") from exc
        except Exception as exc:
            raise _map_op_error(exc, "evaluate") from exc
        try:
            rendered = json.dumps(value, default=str)
        except Exception:  # noqa: BLE001 — coerce exotic returns
            rendered = str(value)
        truncated = len(rendered) > 4000
        return {"ok": True, "value": rendered[:4000], "truncated": truncated}

    async def screenshot(
        self, token: str, *, full_page: bool = False, timeout_ms: int = 30000, target_ip: str = ""
    ) -> bytes:
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        try:
            data = await asyncio.wait_for(
                state["page"].screenshot(full_page=full_page, timeout=timeout_ms),
                timeout=timeout_ms / 1000.0 + 5.0,
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise BrowserTimeout("browser screenshot timed out") from exc
        except Exception as exc:
            raise _map_op_error(exc, "screenshot") from exc
        return bytes(data)

    async def fill_submit(
        self, token: str, form_index: int, field_values: dict[str, str], timeout_ms: int, *, target_ip: str = ""
    ) -> dict[str, Any]:
        """Fill one live-page form by field name, submit it, settle, harvest."""
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        page = state["page"]
        try:
            before = str(page.url or "")
        except Exception:  # noqa: BLE001 — page may be gone
            before = ""
        try:
            info = await page.evaluate(FORM_FILL_SUBMIT_JS, [form_index, dict(field_values or {})])
        except Exception as exc:
            raise _map_op_error(exc, "fill_submit") from exc
        if not isinstance(info, dict) or not info.get("ok"):
            reason = info.get("error", "unexpected form result") if isinstance(info, dict) else "unexpected form result"
            raise BrowserBackendError(f"browser form submit failed: {reason}")
        try:
            # The submit navigation commits asynchronously after evaluate()
            # resolves; wait_for_load_state alone can observe the
            # pre-navigation document and return immediately, so wait for the
            # URL to move first (same-document submits simply time this out).
            await page.wait_for_url(lambda u: u != before, timeout=5000)
        except Exception as exc:  # noqa: BLE001 — timeout here means same-page submit
            if "Timeout" not in type(exc).__name__ and "timeout" not in str(exc).lower():
                raise _map_op_error(exc, "fill_submit") from exc
        try:  # best-effort post-submit settle; never fails the submit itself
            await page.wait_for_load_state("networkidle", timeout=min(timeout_ms // 2, 10000))
        except Exception:  # noqa: BLE001 — settle is advisory
            pass
        status: int | None = None
        for raw in reversed(state["net"]):
            if raw.get("direction") == "response" and raw.get("status") is not None:
                try:
                    status = int(raw["status"])
                except (TypeError, ValueError):
                    status = None
                break
        try:
            final_url = str(page.url or "")
        except Exception:  # noqa: BLE001 — page may be gone
            final_url = ""
        chain = [final_url or before] if not before or before == final_url else [before, final_url]
        return {
            "final_url": final_url or before,
            "status": status,
            "action": str(info.get("action", "") or ""),
            "method": str(info.get("method", "get") or "get"),
            "filled": int(info.get("filled", 0) or 0),
            "redirect_chain": chain,
        }

    async def replay(
        self,
        token: str,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
        timeout_ms: int,
        *,
        target_ip: str = "",
    ) -> dict[str, Any]:
        """Replay one HTTP request through the page's context (cookies shared)."""
        del target_ip  # context-bound replay; policy lives above
        state = self._state(token)
        try:
            kwargs: dict[str, Any] = {"method": method, "headers": dict(headers or {}), "timeout": timeout_ms}
            if body:
                kwargs["data"] = body
            resp = await state["page"].request.fetch(url, **kwargs)
            try:
                text = await resp.text()
            except Exception:  # noqa: BLE001 — body sampling is best-effort
                text = ""
            return {
                "url": url,
                "method": method,
                "status": resp.status,
                "headers": dict(resp.headers or {}),
                "body": text[:_REPLAY_BODY_MAX_BYTES],
            }
        except Exception as exc:
            raise _map_op_error(exc, "replay") from exc

    async def take_network(
        self, token: str, *, body_sample_max_bytes: int = _BODY_SAMPLE_MAX_BYTES, target_ip: str = ""
    ) -> list[dict[str, Any]]:
        """Drain captured raw events; response bodies sampled best-effort."""
        del target_ip  # in-process pages are already session-bound; policy lives above
        state = self._state(token)
        raw_events = list(state["net"])
        state["net"].clear()
        out: list[dict[str, Any]] = []
        for raw in raw_events:
            event = {k: v for k, v in raw.items() if not k.startswith("_")}
            resp = raw.get("_resp")
            body = ""
            body_size: int | None = None
            if resp is not None and raw.get("direction") == "response":
                try:
                    content_type = str(event.get("content_type", "") or "").lower()
                    length_hdr = (event.get("resp_headers", {}) or {}).get("content-length", "")
                    try:
                        declared = int(str(length_hdr).strip())
                    except (TypeError, ValueError):
                        declared = -1
                    textish = content_type.startswith(
                        (
                            "text/",
                            "application/json",
                            "application/javascript",
                            "application/xml",
                            "application/x-www-form-urlencoded",
                            "image/svg",
                        )
                    )
                    if textish and (declared < 0 or declared <= 1024 * 1024):
                        payload = await asyncio.wait_for(resp.body(), timeout=5.0)
                        body_size = len(payload)
                        body = payload[:body_sample_max_bytes].decode("utf-8", errors="replace")
                    elif declared >= 0:
                        body_size = declared
                except Exception:  # noqa: BLE001 — body sampling is best-effort
                    pass
            event["body"] = body
            event["body_size"] = body_size
            out.append(event)
        return out

    def drain_console(self, token: str) -> list[dict[str, str]]:
        try:
            state = self._states[token]
        except KeyError:
            return []
        events = list(state["console"])
        state["console"].clear()
        return events

    async def close(self, token: str) -> None:
        state = self._states.pop(token, None)
        if state is None:
            return
        for key in ("page", "context", "browser"):
            try:
                await state[key].close()
            except Exception:  # noqa: BLE001 — close is best-effort
                pass
        try:
            await state["pw"].stop()
        except Exception:  # noqa: BLE001 — close is best-effort
            pass


@dataclass
class _PlaywrightSession:
    """Backend-private live state (never crosses the seam)."""

    token: str
    target: str
    run_id: str = ""
    headless: bool = True
    last_url: str = ""
    last_status: int | None = None
    net_history: list[BrowserNetworkEvent] = field(default_factory=list)
    net_seq: int = 0
    created_at: float = 0.0
    last_active: float = 0.0


class PlaywrightBackend(BrowserBackend):
    """Chromium-via-Playwright engine behind the :class:`BrowserBackend` seam."""

    backend_id = "playwright"
    display_name = "Playwright (Chromium)"
    capabilities: tuple[str, ...] = (
        "browser.navigate",
        "browser.dom.inspect",
        "browser.javascript.execute",
        "browser.network.observe",
        "browser.network.replay",
        "browser.storage.read",
        "browser.form.inspect",
        "browser.form.submit",
        "browser.screenshot",
        "browser.endpoint.discover",
    )

    def __init__(self, config: dict[str, Any] | None = None, launcher: Any | None = None) -> None:
        self._config = dict(config or {})
        self._launcher = launcher if launcher is not None else InProcessPlaywrightLauncher()
        self._sessions: dict[str, _PlaywrightSession] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._seq = 0

    @property
    def launcher(self) -> Any:
        """The active engine launcher (swappable for sandbox containment)."""
        return self._launcher

    @launcher.setter
    def launcher(self, value: Any) -> None:
        self._launcher = value

    def _cfg(self) -> dict[str, Any]:
        return _browser_cfg(self._config)

    # -- metadata (never launches) --
    def is_configured(self, config: dict[str, Any] | None) -> bool:
        cfg = _browser_cfg(config if config is not None else self._config)
        backend = str(cfg.get("backend", "playwright") or "playwright")
        if backend != "playwright":
            return False
        return playwright_present()

    def health(self, config: dict[str, Any] | None) -> dict[str, Any]:
        cfg = _browser_cfg(config if config is not None else self._config)
        report = {
            "name": "browser_backend_playwright",
            "playwright_present": playwright_present(),
            "playwright_version": playwright_version(),
            "chromium_present": chromium_present(executable_path=str(cfg.get("executable_path") or "")),
        }
        ok = bool(report["playwright_present"] and report["chromium_present"])
        if ok:
            detail = f"playwright {report['playwright_version'] or 'unknown'} + chromium runtime present"
        elif not report["playwright_present"]:
            detail = MISSING_DEP_MSG
        else:
            detail = "playwright SDK present but no chromium runtime (run: python -m playwright install chromium)"
        report["ok"] = ok
        report["detail"] = detail
        return report

    # -- internals --
    def _live_session(self, session_id: str) -> _PlaywrightSession:
        try:
            return self._sessions[session_id]
        except KeyError:
            raise BrowserSessionNotFound(f"unknown browser session id: {session_id!r}") from None

    def _session_lock(self, session_id: str) -> asyncio.Lock:
        lock = self._locks.get(session_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[session_id] = lock
        return lock

    def _nav_timeout(self, override: float | None) -> float:
        if override is not None and override > 0:
            return float(override)
        return float(_int_cfg(self._cfg(), "navigation_timeout_seconds", 30))

    async def _guard(self, awaitable: Any, *, timeout_s: float, op: str, session: _PlaywrightSession | None) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout_s)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise BrowserTimeout(f"browser {op} timed out after {timeout_s:g}s") from exc
        except BrowserCrashed:
            if session is not None:
                await self._drop_token(session)
            raise
        except BrowserBackendError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed, never leak engine errors
            if _is_crash_name(exc):
                if session is not None:
                    await self._drop_token(session)
                raise BrowserCrashed(f"browser {op}: chromium session died: {exc}") from exc
            raise _map_op_error(exc, op) from exc

    async def _drop_token(self, session: _PlaywrightSession) -> None:
        try:
            await self._launcher.close(session.token)
        except Exception:  # noqa: BLE001 — crash cleanup is best-effort
            pass

    def _convert_network(self, session: _PlaywrightSession, raw: dict[str, Any]) -> BrowserNetworkEvent:
        session.net_seq += 1
        direction = (
            BrowserEventDirection.RESPONSE
            if str(raw.get("direction", "")) == "response"
            else BrowserEventDirection.REQUEST
        )
        url = str(raw.get("url", "") or "")
        try:
            scheme = urllib.parse.urlparse(url).scheme.lower()
        except Exception:  # noqa: BLE001 — unparsable URL is simply not replayable
            scheme = ""
        body = str(raw.get("body", "") or "")
        digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else ""
        size = raw.get("body_size")
        try:
            size_int = (
                int(size) if size is not None else (len(body.encode("utf-8", errors="replace")) if body else None)
            )
        except (TypeError, ValueError):
            size_int = None
        return BrowserNetworkEvent(
            event_id=f"evt-{session.net_seq:06d}",
            session_id="",
            direction=direction,
            method=str(raw.get("method", "") or ""),
            url=str(raw.get("url", "") or ""),
            status_code=raw.get("status"),
            content_type=str(raw.get("content_type", "") or ""),
            request_headers={str(k): str(v) for k, v in (raw.get("req_headers") or {}).items()},
            response_headers={str(k): str(v) for k, v in (raw.get("resp_headers") or {}).items()},
            body_size=size_int,
            body_sha256=digest,
            body_sample=body,
            replayable=scheme in ("http", "https"),
            timing_ms=raw.get("timing_ms"),
            observed_at=str(raw.get("observed_at", "") or _utcnow()),
        )

    async def _drain_network(self, session: _PlaywrightSession, session_id: str) -> list[BrowserNetworkEvent]:
        """Pull launcher raw events into the bounded converted history."""
        cfg = self._cfg()
        cap = _int_cfg(cfg, "network_max_events", _NETWORK_MAX_EVENTS)
        body_cap = _int_cfg(cfg, "body_sample_max_bytes", _BODY_SAMPLE_MAX_BYTES)
        try:
            raw_events = await self._launcher.take_network(
                session.token, body_sample_max_bytes=body_cap, target_ip=session.target
            )
        except AttributeError:
            raw_events = []
        fresh: list[BrowserNetworkEvent] = []
        for raw in raw_events or []:
            event = self._convert_network(session, raw if isinstance(raw, dict) else {})
            event.session_id = session_id
            fresh.append(event)
        session.net_history.extend(fresh)
        if len(session.net_history) > cap:
            del session.net_history[: len(session.net_history) - cap]
        session.last_active = time.monotonic()
        return fresh

    def _build_page_state(
        self,
        session_id: str,
        url: str,
        final_url: str,
        status: int | None,
        snap: dict[str, Any],
    ) -> BrowserPageState:
        cfg = self._cfg()
        dom_cap = _int_cfg(cfg, "dom_summary_max_chars", _DOM_SUMMARY_MAX_CHARS)
        scripts = [str(s) for s in (snap.get("scripts") or []) if s][:_MAX_SCRIPTS]
        forms: list[dict[str, Any]] = []
        for form in (snap.get("forms") or [])[:_MAX_FORMS]:
            if not isinstance(form, dict):
                continue
            inputs = [i for i in (form.get("inputs") or []) if isinstance(i, dict)][:_MAX_FORM_FIELDS]
            forms.append(
                {
                    "action": str(form.get("action", "") or ""),
                    "method": str(form.get("method", "") or ""),
                    "inputs": inputs,
                }
            )
        endpoints: list[dict[str, Any]] = []
        graphql: list[str] = []
        seen_urls: set[str] = set()
        for event in self._sessions[session_id].net_history if session_id in self._sessions else []:
            if event.direction is not BrowserEventDirection.RESPONSE:
                continue
            event_url = event.url
            if not event_url or event_url in seen_urls:
                continue
            seen_urls.add(event_url)
            path = urllib.parse.urlparse(event_url).path or ""
            if path.lower().split("?")[0].endswith(tuple(_STATIC_ASSET_EXTS)):
                continue
            endpoints.append({"method": event.method, "url": event_url, "status": event.status_code})
            if "graphql" in event_url.lower():
                graphql.append(event_url)
            if len(endpoints) >= 100:
                break
        return BrowserPageState(
            session_id=session_id,
            url=url,
            final_url=final_url,
            status_code=status,
            title=str(snap.get("title", "") or ""),
            dom_summary=_summarize_text(str(snap.get("text", "") or ""), dom_cap),
            forms=forms,
            endpoints=endpoints,
            scripts=scripts,
            indicators=_detect_indicators(str(snap.get("head", "") or ""), scripts),
            authenticated=None,
            graphql_endpoints=sorted(set(graphql))[:20],
            observed_at=_utcnow(),
            evidence_refs=[],
            metadata={},
        )

    # -- session lifecycle --
    async def start_session(
        self,
        *,
        target: str,
        run_id: str = "",
        session_id: str = "",
        headless: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> BrowserSession:
        if not (target or "").strip():
            raise BrowserBackendUnavailable("browser session requires a locked target")
        if not playwright_present() and isinstance(self._launcher, InProcessPlaywrightLauncher):
            raise BrowserBackendUnavailable(MISSING_DEP_MSG)
        cfg = self._cfg()
        capture_console = bool(cfg.get("capture_console", False))
        self._seq += 1
        sid = session_id or new_session_id(self._seq)
        try:
            token = await asyncio.wait_for(
                self._launcher.launch(headless=headless, capture_console=capture_console),
                timeout=_LAUNCH_TIMEOUT_SECONDS,
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise BrowserTimeout(f"chromium launch timed out after {_LAUNCH_TIMEOUT_SECONDS:g}s") from exc
        session = _PlaywrightSession(
            token=str(token),
            target=target.strip(),
            run_id=run_id,
            headless=headless,
            created_at=time.monotonic(),
            last_active=time.monotonic(),
        )
        self._sessions[sid] = session
        return BrowserSession(
            session_id=sid,
            state=BrowserSessionState.STARTING,
            run_id=run_id,
            target_ip=target.strip(),
            backend_id=self.backend_id,
            started_at=_utcnow(),
            metadata=dict(metadata or {}),
        )

    async def stop_session(self, session_id: str) -> BrowserResult:
        try:
            session = self._live_session(session_id)
        except BrowserSessionNotFound:
            return BrowserResult(success=True, session_id=session_id, follow_ups=[], metadata={"already_closed": True})
        try:
            await self._guard(self._launcher.close(session.token), timeout_s=30.0, op="stop", session=session)
        except BrowserBackendError:
            pass
        self._sessions.pop(session_id, None)
        self._locks.pop(session_id, None)
        return BrowserResult(success=True, session_id=session_id, follow_ups=[])

    # -- navigation / observation / interaction --
    async def navigate(self, session_id: str, url: str, *, timeout_seconds: float | None = None) -> BrowserResult:
        session = self._live_session(session_id)
        parsed = urllib.parse.urlparse((url or "").strip())
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise BrowserNavigationFailed(f"refusing non-http(s) navigation target: {url!r}")
        timeout_s = self._nav_timeout(timeout_seconds)
        async with self._session_lock(session_id):
            raw = await self._guard(
                self._launcher.navigate(session.token, url.strip(), int(timeout_s * 1000), target_ip=session.target),
                timeout_s=timeout_s + 15.0,
                op="navigate",
                session=session,
            )
            if not isinstance(raw, dict):
                raw = {"url": url, "final_url": url, "status": None, "redirect_chain": [url]}
            session.last_url = str(raw.get("final_url", "") or url)
            session.last_status = raw.get("status")
            await self._drain_network(session, session_id)
        metadata = {
            "url": str(raw.get("url", "") or url),
            "final_url": session.last_url,
            "status_code": session.last_status,
            "redirect_chain": list(raw.get("redirect_chain") or [url]),
            "blocked_popups": int(raw.get("blocked_popups") or 0),
        }
        return BrowserResult(
            success=True,
            session_id=session_id,
            follow_ups=["browser_observe", "browser_discover_endpoints"],
            metadata=metadata,
        )

    async def observe(
        self, session_id: str, *, include_forms: bool = True, include_endpoints: bool = True
    ) -> BrowserObservation:
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(None)
        async with self._session_lock(session_id):
            snap = await self._guard(
                self._launcher.snapshot(session.token, int(timeout_s * 1000), target_ip=session.target),
                timeout_s=timeout_s + 15.0,
                op="snapshot",
                session=session,
            )
            if not isinstance(snap, dict):
                snap = {}
            await self._drain_network(session, session_id)
            if snap.get("url"):
                session.last_url = str(snap["url"])
            page_state = self._build_page_state(
                session_id, session.last_url, session.last_url, session.last_status, snap
            )
        payload = page_state.to_dict()
        if not include_forms:
            payload["forms"] = []
        if not include_endpoints:
            payload["endpoints"] = []
            payload["graphql_endpoints"] = []
        return BrowserObservation(
            observation_id=f"obs-{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            kind=BrowserObservationKind.PAGE_STATE,
            url=session.last_url,
            payload=payload,
            sensitive=False,
            evidence_refs=[],
            metadata={},
            observed_at=_utcnow(),
        )

    async def execute_action(self, session_id: str, action: BrowserAction) -> BrowserResult:
        kind = action.kind
        params = dict(action.parameters or {})
        if kind is BrowserActionKind.SUBMIT_FORM:
            return await self._submit_form(session_id, action)
        if kind is BrowserActionKind.REPLAY_REQUEST:
            return await self._replay_request(session_id, action)
        if kind is BrowserActionKind.NAVIGATE:
            result = await self.navigate(
                session_id, str(params.get("url", "") or ""), timeout_seconds=action.timeout_seconds
            )
            result.action_id = action.action_id
            return result
        if (
            kind is BrowserActionKind.OBSERVE
            or kind is BrowserActionKind.DISCOVER_FORMS
            or kind is BrowserActionKind.DISCOVER_ENDPOINTS
        ):
            observation = await self.observe(session_id)
            payload = dict(observation.payload)
            metadata: dict[str, Any] = {
                "observation_id": observation.observation_id,
                "title": payload.get("title", ""),
                "url": payload.get("final_url", ""),
            }
            if kind is BrowserActionKind.DISCOVER_FORMS:
                metadata["forms"] = payload.get("forms", [])
            elif kind is BrowserActionKind.DISCOVER_ENDPOINTS:
                metadata["endpoints"] = payload.get("endpoints", [])
                metadata["graphql_endpoints"] = payload.get("graphql_endpoints", [])
            else:
                metadata["page_state_keys"] = sorted(payload.keys())
            result = BrowserResult(
                success=True,
                action_id=action.action_id,
                session_id=session_id,
                metadata=metadata,
                follow_ups=["browser_observe", "browser_discover_endpoints"],
            )
            return result
        if kind is BrowserActionKind.EXECUTE_JS:
            expression = str(params.get("expression", "") or params.get("js", "") or "")
            if len(expression) > _JS_MAX_CHARS:
                return BrowserResult(
                    success=False,
                    failure_class=BrowserFailureClass.SCRIPT_ERROR,
                    retryable=False,
                    action_id=action.action_id,
                    session_id=session_id,
                    error=BrowserError(
                        failure_class=BrowserFailureClass.SCRIPT_ERROR,
                        message=f"javascript expression exceeds {_JS_MAX_CHARS} chars",
                        source="backend",
                        retryable=False,
                    ),
                )
            session = self._live_session(session_id)
            timeout_s = self._nav_timeout(action.timeout_seconds)
            async with self._session_lock(session_id):
                raw = await self._guard(
                    self._launcher.evaluate(session.token, expression, int(timeout_s * 1000), target_ip=session.target),
                    timeout_s=timeout_s + 10.0,
                    op="evaluate",
                    session=session,
                )
            value = str((raw or {}).get("value", "") or "") if isinstance(raw, dict) else ""
            # Body-sample-grade masking: JS return values are the highest-risk
            # string surface (tokens/cookies dumped by page scripts).
            preview = _mask_body(value[:_JS_PREVIEW_MAX_CHARS])
            return BrowserResult(
                success=True,
                action_id=action.action_id,
                session_id=session_id,
                metadata={"return_preview": preview, "truncated": bool((raw or {}).get("truncated"))},
                follow_ups=["browser_observe"],
            )
        if kind is BrowserActionKind.SCREENSHOT:
            artifact = await self.capture_screenshot(
                session_id, artifact_path=str(params.get("artifact_path", "") or "")
            )
            return BrowserResult(
                success=True,
                action_id=action.action_id,
                session_id=session_id,
                produced_artifacts=[artifact.artifact_id],
                evidence_refs=[f"browser_artifact:{artifact.artifact_id}"],
                metadata={"artifact": artifact.to_dict()},
            )
        if kind is BrowserActionKind.GET_NETWORK_EVENTS:
            events = await self.get_network_events(
                session_id, limit=int(params.get("limit", 100) or 100), after_id=str(params.get("after_id", "") or "")
            )
            return BrowserResult(
                success=True,
                action_id=action.action_id,
                session_id=session_id,
                metadata={"events": [e.to_redacted_dict() for e in events], "count": len(events)},
            )
        if kind is BrowserActionKind.GET_STORAGE:
            snapshot = await self.get_storage(session_id, origin=str(params.get("origin", "") or ""))
            redacted = snapshot.to_dict()
            return BrowserResult(
                success=True,
                action_id=action.action_id,
                session_id=session_id,
                metadata={"storage": redacted, "entry_count": len(snapshot.entries)},
                follow_ups=[],
            )
        if kind is BrowserActionKind.WAIT:
            seconds = min(max(float(params.get("seconds", 2) or 2), 0.0), _MAX_WAIT_SECONDS)
            await asyncio.sleep(seconds)
            return BrowserResult(
                success=True, action_id=action.action_id, session_id=session_id, metadata={"waited_seconds": seconds}
            )
        if kind is BrowserActionKind.CLOSE:
            result = await self.close(session_id)
            result.action_id = action.action_id
            return result
        return BrowserResult(
            success=False,
            failure_class=BrowserFailureClass.UNSUPPORTED_ACTION,
            retryable=False,
            action_id=action.action_id,
            session_id=session_id,
            error=BrowserError(
                failure_class=BrowserFailureClass.UNSUPPORTED_ACTION,
                message=f"unsupported browser action: {kind.value}",
                source="backend",
                retryable=False,
            ),
        )

    @staticmethod
    def _invalid(
        action: BrowserAction,
        session_id: str,
        message: str,
        failure_class: BrowserFailureClass = BrowserFailureClass.UNEXPECTED_OUTPUT,
    ) -> BrowserResult:
        """Malformed mutating-action input (never dispatched, never retried)."""
        return BrowserResult(
            success=False,
            failure_class=failure_class,
            retryable=False,
            action_id=action.action_id,
            session_id=session_id,
            error=BrowserError(
                failure_class=failure_class,
                message=message,
                source="backend",
                retryable=False,
            ),
        )

    async def _submit_form(self, session_id: str, action: BrowserAction) -> BrowserResult:
        """Fill one live-page form by field name and submit it (mutating)."""
        params = dict(action.parameters or {})
        try:
            form_index = int(params.get("form_index", 0))
        except (TypeError, ValueError):
            form_index = -1
        fields = params.get("field_values") or {}
        if not isinstance(fields, dict):
            return self._invalid(action, session_id, "submit field_values must be a {name: value} mapping")
        bounded = {str(k): str(v)[:_SUBMIT_VALUE_MAX_CHARS] for k, v in list(fields.items())[:_MAX_SUBMIT_FIELDS]}
        if form_index < 0:
            return self._invalid(action, session_id, f"invalid form_index {params.get('form_index')!r}")
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(action.timeout_seconds)
        async with self._session_lock(session_id):
            raw = await self._guard(
                self._launcher.fill_submit(
                    session.token, form_index, bounded, int(timeout_s * 1000), target_ip=session.target
                ),
                timeout_s=timeout_s + 15.0,
                op="submit",
                session=session,
            )
            if not isinstance(raw, dict):
                raw = {}
            fresh = await self._drain_network(session, session_id)
            final_url = str(raw.get("final_url", "") or session.last_url)
            session.last_url = final_url or session.last_url
        return BrowserResult(
            success=True,
            action_id=action.action_id,
            session_id=session_id,
            metadata={
                "final_url": final_url,
                "status_code": raw.get("status"),
                "form_action": str(raw.get("action", "") or ""),
                "form_method": str(raw.get("method", "get") or "get"),
                "filled_fields": int(raw.get("filled", 0) or 0),
                "redirect_chain": list(raw.get("redirect_chain") or [final_url]),
                "captured_events": len(fresh),
            },
            follow_ups=["browser_observe", "browser_network_events"],
        )

    async def _replay_request(self, session_id: str, action: BrowserAction) -> BrowserResult:
        """Replay one HTTP request through the session context (mutating)."""
        params = dict(action.parameters or {})
        url = str(params.get("url", "") or "").strip()
        parsed = urllib.parse.urlparse(url)
        if not url or parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return self._invalid(
                action,
                session_id,
                f"refusing non-http(s) replay target: {url!r}",
                BrowserFailureClass.NAVIGATION_FAILED,
            )
        method = re.sub(r"[^A-Z]", "", str(params.get("method", "GET") or "GET").upper())[:16]
        if not method:
            return self._invalid(action, session_id, "replay method must be a valid HTTP token")
        headers = params.get("headers") or {}
        if not isinstance(headers, dict):
            return self._invalid(action, session_id, "replay headers must be a {name: value} mapping")
        bounded_headers = {str(k)[:256]: str(v)[:4096] for k, v in list(headers.items())[:_REPLAY_MAX_HEADERS]}
        body = str(params.get("body", "") or "")[:_REPLAY_BODY_MAX_BYTES]
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(action.timeout_seconds)
        async with self._session_lock(session_id):
            raw = await self._guard(
                self._launcher.replay(
                    session.token,
                    method,
                    url,
                    bounded_headers,
                    body,
                    int(timeout_s * 1000),
                    target_ip=session.target,
                ),
                timeout_s=timeout_s + 15.0,
                op="replay",
                session=session,
            )
            if not isinstance(raw, dict):
                raw = {}
        text = str(raw.get("body", "") or "")
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest() if text else ""
        return BrowserResult(
            success=True,
            action_id=action.action_id,
            session_id=session_id,
            metadata={
                "url": url,
                "method": method,
                "status_code": raw.get("status"),
                "body_preview": _mask_body(text[:_REPLAY_PREVIEW_MAX_CHARS]),
                "truncated": len(text) > _REPLAY_PREVIEW_MAX_CHARS,
                "body_sha256": digest,
            },
            follow_ups=["browser_network_events", "browser_observe"],
        )

    async def capture_screenshot(self, session_id: str, *, artifact_path: str = "") -> BrowserArtifact:
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(None)
        async with self._session_lock(session_id):
            png = await self._guard(
                self._launcher.screenshot(
                    session.token, full_page=False, timeout_ms=int(timeout_s * 1000), target_ip=session.target
                ),
                timeout_s=timeout_s + 15.0,
                op="screenshot",
                session=session,
            )
        data = bytes(png) if not isinstance(png, (bytes, bytearray)) else bytes(png)
        if artifact_path:
            path = artifact_path
        else:
            artifact_dir = str(self._cfg().get("artifact_dir", "") or "browser_artifacts").strip()
            import os

            path = os.path.join(artifact_dir, session_id, f"screenshot-{uuid.uuid4().hex[:8]}.png")
        parent = Path(path).parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(data)
        except OSError as exc:
            raise BrowserBackendError(f"could not persist browser screenshot to {path!r}: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        return BrowserArtifact(
            artifact_id=f"ba-{uuid.uuid4().hex[:8]}",
            session_id=session_id,
            kind=BrowserArtifactKind.SCREENSHOT,
            path=path,
            sha256=digest,
            size_bytes=len(data),
            content_type="image/png",
            evidence_type="screenshot",
            created_at=_utcnow(),
            metadata={"url": session.last_url},
        )

    async def get_network_events(
        self, session_id: str, *, limit: int = 100, after_id: str = ""
    ) -> list[BrowserNetworkEvent]:
        session = self._live_session(session_id)
        async with self._session_lock(session_id):
            await self._drain_network(session, session_id)
            history = list(session.net_history)
        if after_id:
            try:
                idx = next(i for i, event in enumerate(history) if event.event_id == after_id)
                history = history[idx + 1 :]
            except StopIteration:
                pass
        cap = max(1, min(int(limit or 100), _NETWORK_MAX_EVENTS))
        return history[-cap:]

    async def get_storage(self, session_id: str, *, origin: str = "") -> BrowserStorageSnapshot:
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(None)
        async with self._session_lock(session_id):
            snap = await self._guard(
                self._launcher.snapshot(session.token, int(timeout_s * 1000), target_ip=session.target),
                timeout_s=timeout_s + 15.0,
                op="snapshot",
                session=session,
            )
            if not isinstance(snap, dict):
                snap = {}
            if snap.get("url"):
                session.last_url = str(snap["url"])
        entries: list[dict[str, str]] = []
        for cookie in snap.get("cookies") or []:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get("name", "") or "")
            if not name:
                continue
            entries.append({"key": name, "value": str(cookie.get("value", "") or "")})
            if len(entries) >= _MAX_STORAGE_ENTRIES:
                break
        for prefix, area in (("local:", "local_storage"), ("session:", "session_storage")):
            store = snap.get(area) or {}
            if not isinstance(store, dict):
                continue
            for key, value in store.items():
                if len(entries) >= _MAX_STORAGE_ENTRIES:
                    break
                entries.append({"key": f"{prefix}{key}", "value": str(value)[:_STORAGE_VALUE_MAX_CHARS]})
        resolved_origin = origin or session.last_url
        if not resolved_origin and entries:
            resolved_origin = session.last_url
        return BrowserStorageSnapshot(
            origin=resolved_origin,
            storage_kind=BrowserStorageKind.COOKIES,
            session_id=session_id,
            entries=entries,
            collected_at=_utcnow(),
        )

    async def get_page_state(self, session_id: str) -> BrowserPageState:
        session = self._live_session(session_id)
        timeout_s = self._nav_timeout(None)
        async with self._session_lock(session_id):
            snap = await self._guard(
                self._launcher.snapshot(session.token, int(timeout_s * 1000), target_ip=session.target),
                timeout_s=timeout_s + 15.0,
                op="snapshot",
                session=session,
            )
            if not isinstance(snap, dict):
                snap = {}
            await self._drain_network(session, session_id)
            if snap.get("url"):
                session.last_url = str(snap["url"])
            return self._build_page_state(session_id, session.last_url, session.last_url, session.last_status, snap)

    async def close(self, session_id: str) -> BrowserResult:
        try:
            session = self._live_session(session_id)
        except BrowserSessionNotFound:
            return BrowserResult(success=True, session_id=session_id, metadata={"already_closed": True})
        try:
            await self._launcher.close(session.token)
        except Exception:  # noqa: BLE001 — hard close never raises
            pass
        self._sessions.pop(session_id, None)
        self._locks.pop(session_id, None)
        return BrowserResult(success=True, session_id=session_id)

    # -- console (opt-in capture) --
    def drain_console(self, session_id: str) -> list[dict[str, str]]:
        """Best-effort console events (empty unless ``capture_console: true``)."""
        try:
            session = self._live_session(session_id)
        except BrowserSessionNotFound:
            return []
        drain = getattr(self._launcher, "drain_console", None)
        if not callable(drain):
            return []
        try:
            events = drain(session.token)
        except Exception:  # noqa: BLE001 — console is advisory
            return []
        cap = _int_cfg(self._cfg(), "console_max_events", _CONSOLE_MAX_EVENTS)
        return list(events or [])[-cap:]

    # -- test seam --
    @property
    def _test_sessions(self) -> dict[str, _PlaywrightSession]:
        return self._sessions
