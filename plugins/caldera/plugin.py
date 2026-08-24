"""Caldera adversary emulation plugin (D6).

Runs Caldera abilities against an authorized Caldera server (target-side). The
Caldera server is target-side — the operator adds it to
``exploit.allowed_targets``. Every target-touching tool is
``@require_allowlist()``-gated so the target-IP allowlist lock applies.

The plugin exposes two MCP tools:
- ``caldera_list_abilities`` — list Caldera abilities (target-touching →
  ``@require_allowlist()`` on the Caldera server IP).
- ``caldera_run_ability`` — run an ability against a target agent
  (``@require_allowlist()`` on both the Caldera server and the target).

Safety (lab build): plugin is OFF by default. The Caldera server IP must be
in ``exploit.allowed_targets``. deps: Caldera server + REST client (the
operator configures the URL/API key in the plugin's config section).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _caldera_config(config: dict[str, Any] | None) -> tuple[str, str]:
    """Return (url, api_key) from the top-level ``caldera`` config block.

    ``url`` defaults to empty (tool surfaces a clear error). ``api_key`` is
    read from the env var named by ``api_key_env`` (default ``CALDERA_API_KEY``).
    """
    cfg = (config or {}).get("caldera", {}) or {}
    url = str(cfg.get("url", "") or "").strip()
    api_key_env = str(cfg.get("api_key_env", "CALDERA_API_KEY") or "CALDERA_API_KEY")
    api_key = os.environ.get(api_key_env, "").strip()
    return url, api_key


class CalderaPlugin(Plugin):
    """Plugin that registers Caldera adversary-emulation MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        def register_mcp_tools(mcp: Any, ctx: Any) -> None:
            require_allowlist = ctx.require_allowlist
            config = getattr(ctx, "config", None)

            @mcp.tool()
            @require_allowlist()
            def caldera_list_abilities(target_ip: str) -> str:
                """List Caldera abilities from an authorized Caldera server.

                ``target_ip`` is the Caldera server IP (must be in the allowlist).
                The Caldera URL + API key come from the ``caldera`` config block
                (``caldera.url`` + ``caldera.api_key_env``). Target-touching →
                @require_allowlist on the Caldera server IP.
                """
                url, api_key = _caldera_config(config)
                if not url:
                    return "ERROR: caldera.url not set in config.yaml (e.g. https://caldera.local:8888)"
                # ponytail: the real implementation would HTTP GET {url}/api/v2/abilities
                # with an Authorization: Bearer {api_key} header. Stubbed here so the
                # plugin is testable without a live Caldera server; the @require_allowlist
                # gate is the safety surface, and the REST call is a pure stdlib
                # urllib.request when wired.
                if not api_key:
                    return "ERROR: caldera API key not set (env var from caldera.api_key_env)."
                return (
                    f"CALDERA_ABILITIES: stub for {url} (target={target_ip})\n"
                    f"Wire urllib.request to GET {url}/api/v2/abilities "
                    f"with Authorization: Bearer <{api_key[:4]}...> to list abilities."
                )

            @mcp.tool()
            @require_allowlist()
            def caldera_run_ability(target_ip: str, ability_id: str) -> str:
                """Run a Caldera ability against a target agent.

                ``target_ip`` is the target the ability runs against (must be in
                the allowlist). ``ability_id`` is the Caldera ability identifier.
                The Caldera URL + API key come from the ``caldera`` config block.
                Target-touching → @require_allowlist on the target IP.
                """
                url, api_key = _caldera_config(config)
                if not url:
                    return "ERROR: caldera.url not set in config.yaml."
                if not ability_id:
                    return "ERROR: ability_id is required."
                if not api_key:
                    return "ERROR: caldera API key not set (env var from caldera.api_key_env)."
                return (
                    f"CALDERA_RUN: stub ability={ability_id} target={target_ip} "
                    f"caldera={url}\n"
                    f"Wire urllib.request to POST {url}/api/v2/operations "
                    f"with the ability + target agent to execute."
                )

        registry.register_mcp_tools(register_mcp_tools)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return CalderaPlugin()
