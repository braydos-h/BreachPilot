"""GitHub dorks plugin for authorized code-leak discovery.

Finds leaked credentials/secrets in a target ORGANIZATION's public GitHub
repos by running curated dork queries against the GitHub Code Search API.
Pre-recon OSINT: the operator authorizes a target org, this plugin runs a
fixed set of dorks (``org:<target> password``, ``org:<target> API_KEY``,
etc.), and returns the matching file paths + repo names. It NEVER fetches
the raw file content (that would be a separate, audited step the agent
takes deliberately), and it NEVER touches the target's infrastructure.

Two-gate enablement:
  1. ``plugins.enabled`` must list ``github_dorks``.
  2. ``GITHUB_TOKEN`` (shared with ``cve_lookup.github.token_env``) must be
     set -- the GitHub Code Search API is auth-gated and returns 401 without
     a token. The MCP tool refuses with ``BLOCKED:`` when the token is unset.

Prompt-injection surface: GitHub repo/file names and code snippets are
untrusted third-party text. Mitigations: (1) return structured JSON (no raw
code -- only file path + repo + match excerpt, capped); (2) ``_clean``
every string (strip control chars + cap at 200 chars); (3) never auto-
execute returned strings; (4) the agent's system prompt carries the
``auditing-mcp-servers-for-tool-poisoning`` skill (default-enabled).

Pure stdlib (urllib) -- reuses the same GitHub Search API path as
``tools/exploit_search.py:cve_to_poc``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from tools.opsec import process_user_agent
from tools.plugins import Plugin, PluginManifest, PluginRegistry

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"
_GH_CODE_SEARCH_URL = "https://api.github.com/search/code"
_MAX_STR = 200
# Curated dork templates. ``{org}`` is interpolated via str.format; the org
# is validated to ``[A-Za-z0-9_-]`` so no query-injection is possible.
_DEFAULT_DORKS = [
    "org:{org} password",
    "org:{org} API_KEY",
    "org:{org} SECRET",
    "org:{org} BEGIN PRIVATE KEY",
    "org:{org} AWS_ACCESS_KEY",
    "org:{org} extension:env",
    "org:{org} filename:.npmrc",
    "org:{org} filename:.dockercfg",
    "org:{org} filename:id_rsa",
]


def _clean(value: Any) -> Any:
    """Strip control chars + cap string length on GitHub search results."""
    if isinstance(value, str):
        return "".join(c for c in value if c >= " ")[:_MAX_STR]
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k)[:_MAX_STR]: _clean(v) for k, v in value.items()}
    return value


def _github_token(config: dict[str, Any] | None) -> str:
    # Reuse cve_lookup.github.token_env (default GITHUB_TOKEN) so the
    # operator sets one token for all GitHub-touching features.
    cve_cfg = (config or {}).get("cve_lookup", {}) or {}
    gh_cfg = cve_cfg.get("github", {}) or {}
    env_name = str(gh_cfg.get("token_env", "GITHUB_TOKEN"))
    return os.environ.get(env_name, "").strip()


def _gh_search(
    query: str,
    token: str,
    *,
    timeout: int = 30,
    per_page: int = 30,
    fetch_fn: Callable[[str, str, dict[str, str]], Any] | None = None,
) -> dict[str, Any]:
    """Run one GitHub Code Search API query. ``fetch_fn(url, method, headers)``
    overrides the real urllib path so tests never touch the network."""
    params = {"q": query, "per_page": str(per_page)}
    url = _GH_CODE_SEARCH_URL + "?" + urllib.parse.urlencode(params)
    headers = {
        "User-Agent": process_user_agent("breachpilot-github-dorks/1.0"),
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    if fetch_fn is not None:
        try:
            payload = fetch_fn(url, "GET", headers)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                body = str(getattr(exc, "filename", ""))[:200]
            return {"error": f"github HTTP {exc.code}", "body": body}
        except Exception as exc:
            return {"error": f"github fetch failed: {exc}"}
    else:
        try:
            req = urllib.request.Request(url, method="GET", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                body = str(getattr(exc, "filename", ""))[:200]
            return {"error": f"github HTTP {exc.code}", "body": body}
        except Exception as exc:
            return {"error": f"github fetch failed: {exc}"}
    matches = []
    for item in (payload.get("items") or [])[:per_page]:
        matches.append(
            {
                "repo": (item.get("repository") or {}).get("full_name", ""),
                "path": item.get("path", ""),
                "name": item.get("name", ""),
                "html_url": item.get("html_url", ""),
                "score": item.get("score", 0),
            }
        )
    return {"matches": matches, "total_count": payload.get("total_count", 0)}


def run_dorks(
    org: str,
    token: str,
    *,
    dorks: list[str] | None = None,
    timeout: int = 30,
    fetch_fn: Callable[[str, str, dict[str, str]], Any] | None = None,
) -> dict[str, Any]:
    """Run the curated dork set against ``org``. Returns
    ``{"org": ..., "results": [{dork, matches, total_count}], "summary": {...}}``.

    ``org`` is validated to ``[A-Za-z0-9_-]`` (1-39 chars, GitHub's org name
    rules) so a prompt-injected ``org`` cannot smuggle arbitrary query text
    into the GitHub Search API.
    """
    if not token:
        return {"error": "github token missing"}
    org_clean = (org or "").strip()
    if not org_clean or len(org_clean) > 39 or not all(c.isalnum() or c in "-_" for c in org_clean):
        return {"error": "invalid org name (must be [A-Za-z0-9_-], 1-39 chars)"}
    dork_list = dorks if dorks is not None else _DEFAULT_DORKS
    results = []
    total_hits = 0
    for dork_tmpl in dork_list:
        query = dork_tmpl.format(org=org_clean)
        res = _gh_search(query, token, timeout=timeout, fetch_fn=fetch_fn)
        if "error" in res:
            # One dork failing (e.g. rate-limit) shouldn't abort the rest.
            results.append({"dork": query, "error": res["error"]})
            continue
        results.append(
            {
                "dork": query,
                "matches": res["matches"],
                "total_count": res["total_count"],
            }
        )
        total_hits += len(res["matches"])
    return _clean(
        {
            "org": org_clean,
            "results": results,
            "summary": {"total_dorks": len(dork_list), "total_hits": total_hits},
        }
    )


class GithubDorksPlugin(Plugin):
    """Plugin wrapper registering the github-dorks MCP tool (default-off)."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_config_section(
            "github_dorks",
            {
                "enabled": {"type": "bool", "default": False},
            },
        )
        registry.register_mcp_tools(_register_github_dorks_tools)


def _register_github_dorks_tools(mcp: Any, ctx: Any) -> None:
    audit_tool = ctx.audit_tool
    config = ctx.config

    @mcp.tool()
    @audit_tool
    def search_github_dorks(org: str) -> str:
        """Run curated GitHub dorks against an authorized target ORGANIZATION's public repos to find leaked creds/secrets (password, API_KEY, PRIVATE KEY, AWS keys, .env, id_rsa, .npmrc, .dockercfg). Advisory-only -- never touches the target's infrastructure, never fetches raw file content. Requires GITHUB_TOKEN (shared with cve_lookup.github.token_env); returns BLOCKED when unset. ``org`` must be a valid GitHub org name ([A-Za-z0-9_-], 1-39 chars)."""
        token = _github_token(config)
        if not token:
            return "BLOCKED: GITHUB_TOKEN not set (cve_lookup.github.token_env)."
        result = run_dorks(org, token)
        return json.dumps(result, indent=2, default=str)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return GithubDorksPlugin()
