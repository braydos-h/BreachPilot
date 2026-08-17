"""webhook_notify plugin — outbound-only Slack/Discord run-status notifications.

Operator gets pinged when a long campaign hits a milestone/finding instead of
polling the WebUI. Registers an event subscriber (``PluginRegistry.register_
event_subscriber``) that fires AFTER the event is persisted to JSONL + pushed
to live WS subscribers, so a slow/endpoint-down webhook never blocks the run.

SAFETY (lab build): trusted Python with full operator-box privileges, same as
built-in ``tools/mcp_tools/*``. Outbound-only HTTP POST — no target touch, no
inbound surface. The webhook URL is a secret: it is read from config and never
logged in plaintext (the audit redactor masks ``url``/``webhook_url`` args;
this plugin additionally logs only the URL's host so failures are debuggable
without leaking the path/token segment).

Failure modes:
- webhook endpoint down → retry with exponential backoff, then drop (do not
  block the run). Logged at WARNING with the last HTTP status.
- URL missing/empty → no-op, log once.
- event filter empty → send nothing.
- payload too large → cap at ``max_payload_chars``.

The subscriber is synchronous and runs in the emit() call site's thread. The
HTTP POST uses a short timeout + ``urllib`` (stdlib) so the plugin adds no new
dependency. Retries are bounded (``max_retries``) so a permanently-down
endpoint does not stall emit() indefinitely.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Callable

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.webhook_notify")

_MANIFEST_DEFAULTS = {
    "enabled": False,
    "url": "",
    "events": ["finding", "state"],
    "timeout_seconds": 5,
    "max_retries": 3,
    "backoff_seconds": 2.0,
    "max_payload_chars": 8192,
}


def _load_webhook_config(config_loader: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Read the ``webhook_notify`` config section, overlaying defaults.

    ``config_loader`` is injected so tests can pass a fake; the production
    path uses ``tools.config_cli.load_config`` lazily on first event.
    """
    try:
        cfg = config_loader() or {}
    except Exception:  # noqa: BLE001 -- config read must never break emit
        return dict(_MANIFEST_DEFAULTS)
    section = cfg.get("webhook_notify", {}) or {}
    if not isinstance(section, dict):
        return dict(_MANIFEST_DEFAULTS)
    merged = dict(_MANIFEST_DEFAULTS)
    merged.update(section)
    return merged


def _url_host(url: str) -> str:
    """Return just the ``host`` of a URL for safe logging (no path/token)."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or "(invalid url)"
    except Exception:
        return "(invalid url)"


def _post_webhook(url: str, payload: bytes, timeout: int) -> tuple[bool, str]:
    """POST ``payload`` to ``url``. Returns (ok, status_or_error)."""
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "NetAttackAI-webhook-notify/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (200 <= resp.status < 300), f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _build_subscriber(config_loader: Callable[[], dict[str, Any]]) -> Callable[[dict[str, Any]], None]:
    """Build the event subscriber closure.

    Captures ``config_loader`` so config is read lazily on the first event
    (the plugin is loaded at boot before config is finalized for a run; the
    section is read each event so an operator editing ``config.yaml`` mid-run
    is picked up without a restart).
    """
    logged_missing_url = False

    def subscriber(event: dict[str, Any]) -> None:
        nonlocal logged_missing_url
        cfg = _load_webhook_config(config_loader)
        if not cfg.get("enabled"):
            return
        url = str(cfg.get("url") or "").strip()
        if not url:
            if not logged_missing_url:
                log.info("webhook_notify: url not configured; no-op")
                logged_missing_url = True
            return
        event_type = str(event.get("type") or "")
        allowed = cfg.get("events") or []
        if not isinstance(allowed, list) or not allowed:
            return
        if event_type not in {str(e) for e in allowed}:
            return
        # Cap payload size; treat audit fields as data (never execute).
        body = json.dumps(event, default=str)
        max_chars = int(cfg.get("max_payload_chars", 8192))
        if len(body) > max_chars:
            body = body[:max_chars]
        payload = body.encode("utf-8")
        timeout = int(cfg.get("timeout_seconds", 5))
        max_retries = int(cfg.get("max_retries", 3))
        backoff = float(cfg.get("backoff_seconds", 2.0))
        import time as _time
        last_status = ""
        for attempt in range(max_retries):
            ok, status = _post_webhook(url, payload, timeout)
            if ok:
                return
            last_status = status
            if attempt + 1 < max_retries:
                _time.sleep(backoff * (2 ** attempt))
        log.warning(
            "webhook_notify: dropped event %s for %s after %d attempts: %s",
            event_type, _url_host(url), max_retries, last_status,
        )

    return subscriber


class WebhookNotifyPlugin(Plugin):
    """Registers the outbound webhook event subscriber."""

    manifest: PluginManifest

    def __init__(self, config_loader: Callable[[], dict[str, Any]] | None = None) -> None:
        self.manifest = self._load_manifest()
        # Inject a config loader; default reads config.yaml lazily so the
        # plugin stays decoupled from the boot config lifecycle.
        self._config_loader = config_loader or _default_config_loader

    @staticmethod
    def _load_manifest() -> PluginManifest:
        from pathlib import Path
        manifest_path = Path(__file__).resolve().parent / "plugin.yaml"
        text = manifest_path.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore
        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_event_subscriber(_build_subscriber(self._config_loader))


def _default_config_loader() -> dict[str, Any]:
    """Production config loader: read config.yaml via the shared loader."""
    from pathlib import Path

    from tools.config_cli import load_config
    return load_config(Path("config.yaml"))


def create_plugin() -> Plugin:
    """Factory invoked by :class:`PluginManager` when loading this plugin."""
    return WebhookNotifyPlugin()


__all__ = ["WebhookNotifyPlugin", "create_plugin"]
