"""OWASP ZAP REST integration plugin for NetAttackAi.

Wraps the ZAP REST API to run spider + active scans against authenticated web
targets, correlated with the AI's hypothesis loop. Pairs with the existing
``tools/mcp_tools/web_scan.py`` (nikto/nuclei/sqlmap) — this plugin adds the
ZAP path.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Every target-touching MCP tool is wrapped with ``ctx.require_allowlist()`` so
  the target-IP allowlist lock + JSONL audit trail apply automatically.
* The ZAP daemon runs on the operator's box; the operator MUST start ZAP with
  its REST API enabled before invoking this plugin.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.zap_scan")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


# ---------------------------------------------------------------------------
# ZAP REST API client (stdlib only)
# ---------------------------------------------------------------------------


def _zap_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("zap_scan") or {}
    if not isinstance(cfg_block, dict):
        return {}
    return cfg_block


def _zap_base(config: dict[str, Any] | None) -> str:
    return str(_zap_cfg(config).get("api_url", "http://127.0.0.1:8080")).rstrip("/")


def _zap_api_key(config: dict[str, Any] | None) -> str:
    env_name = str(_zap_cfg(config).get("api_key_env", "ZAP_API_KEY"))
    return os.environ.get(env_name, "")


def _zap_get(
    config: dict[str, Any] | None, path: str, params: dict[str, Any] | None = None, timeout: int = 30
) -> tuple[int, str]:
    """GET against the ZAP REST API. Returns (status, body)."""
    base = _zap_base(config)
    qs = []
    api_key = _zap_api_key(config)
    if api_key:
        qs.append(f"apikey={api_key}")
    if params:
        for k, v in params.items():
            qs.append(f"{k}={urllib.parse.quote(str(v))}")
    url = base + path + ("?" + "&".join(qs) if qs else "")
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, f"ZAP request failed: {exc}"


def _zap_post(
    config: dict[str, Any] | None, path: str, params: dict[str, Any] | None = None, timeout: int = 30
) -> tuple[int, str]:
    """POST against the ZAP REST API. Returns (status, body)."""
    import urllib.parse

    base = _zap_base(config)
    api_key = _zap_api_key(config)
    data = dict(params or {})
    if api_key:
        data["apikey"] = api_key
    body = urllib.parse.urlencode(data).encode()
    url = base + path
    try:
        req = urllib.request.Request(
            url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, f"ZAP request failed: {exc}"


def _zap_status_ok(body: str) -> bool:
    """Return True if the ZAP response body's ``status`` == ``OK`` or has no
    ``status`` field (some endpoints return a plain value)."""
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            return str(obj.get("status", "OK")).upper() == "OK"
        return True
    except Exception:  # noqa: BLE001
        return True


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class ZapScanPlugin(Plugin):
    """Plugin wrapper that registers the ZAP scan MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_zap_tools)


def _register_zap_tools(mcp: Any, ctx: Any) -> None:
    """Register ZAP MCP tools. Every tool is allowlist-gated via ctx."""
    require_allowlist = ctx.require_allowlist
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def zap_spider(target_ip: str, url: str, max_depth: int = 5) -> str:
        """Run the ZAP spider against a target URL.

        The ZAP REST API must already be running on the operator's box
        (``zap_scan.api_url``). The target_ip is allowlist-gated; the URL's host
        must resolve to an allowlisted IP.
        """
        if not url or not url.strip():
            return "BLOCKED: url is required."
        cfg = _zap_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: zap_scan plugin not enabled in config (zap_scan.enabled)."

        status, body = _zap_post(config, "/JSON/spider/action/scan/", {"url": url, "maxDepth": str(max_depth)})
        if status == 0:
            return f"ZAP_SPIDER_ERROR: {body}"
        if status != 200:
            return f"ZAP_SPIDER_ERROR: http_{status}\n{body}"
        try:
            scan_id = json.loads(body).get("scan", "")
        except Exception:  # noqa: BLE001
            scan_id = ""
        return (
            f"ZAP_SPIDER_RESULT: started\nSCAN_ID: {scan_id}\nURL: {url}\nMAX_DEPTH: {max_depth}\nTARGET: {target_ip}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def zap_active_scan(target_ip: str, url: str, recurse: bool = True) -> str:
        """Run a ZAP active scan against a target URL.

        WARNING: active scans send attack payloads. Only run against targets
        you own or are explicitly authorized to test. The target_ip is
        allowlist-gated; the URL's host must resolve to an allowlisted IP.
        """
        if not url or not url.strip():
            return "BLOCKED: url is required."
        cfg = _zap_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: zap_scan plugin not enabled in config (zap_scan.enabled)."

        status, body = _zap_post(
            config,
            "/JSON/ascan/action/scan/",
            {"url": url, "recurse": str(recurse).lower()},
        )
        if status == 0:
            return f"ZAP_ACTIVE_SCAN_ERROR: {body}"
        if status != 200:
            return f"ZAP_ACTIVE_SCAN_ERROR: http_{status}\n{body}"
        try:
            scan_id = json.loads(body).get("scan", "")
        except Exception:  # noqa: BLE001
            scan_id = ""
        return f"ZAP_ACTIVE_SCAN_RESULT: started\nSCAN_ID: {scan_id}\nURL: {url}\nTARGET: {target_ip}"

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def zap_scan_status(target_ip: str, scan_id: str) -> str:
        """Return the status of a ZAP scan (spider or active) by scan_id."""
        if not scan_id or not scan_id.strip():
            return "BLOCKED: scan_id is required."
        status, body = _zap_get(config, "/JSON/ascan/view/status/", {"scanId": scan_id})
        if status == 0:
            return f"ZAP_STATUS_ERROR: {body}"
        return f"ZAP_SCAN_STATUS:\n{body}"

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def zap_alerts(target_ip: str, baseurl: str = "") -> str:
        """Return all alerts ZAP has recorded, optionally filtered by baseurl."""
        params = {}
        if baseurl:
            params["baseurl"] = baseurl
        status, body = _zap_get(config, "/JSON/core/view/alerts/", params or None)
        if status == 0:
            return f"ZAP_ALERTS_ERROR: {body}"
        try:
            obj = json.loads(body)
            alerts = obj.get("alerts", [])
        except Exception:  # noqa: BLE001
            alerts = []
        return f"ZAP_ALERTS_RESULT: count={len(alerts)}\nTARGET: {target_ip}\nALERTS:\n{body[:4000]}"


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return ZapScanPlugin()
