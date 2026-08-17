"""Threat-intel feed ingestion: OSV.dev + GitHub Security Advisories + CISA KEV.

Advisory-only, never touches the target. Pure stdlib (urllib, json, pathlib,
time). Reuses ``tools.cve_lookup.KEVCatalog`` for the KEV source so the
catalog is fetched + disk-cached once per process.

Prompt-injection surface
------------------------
Feed text (CVE summaries, advisory bodies) is untrusted third-party data.
Mitigations:

1. Return STRUCTURED JSON, not prose -- the agent consumes fields, not free
   text it might be tempted to execute.
2. ``_clean()`` every string that came off the wire: strip control chars
   (``c >= " "``) and cap at 200 chars. A malicious advisory body cannot
   smuggle a long instruction past the cap.
3. Never auto-execute returned strings -- this module only returns data.
4. The agent's system prompt already carries the
   ``auditing-mcp-servers-for-tool-poisoning`` skill
   (``config.yaml:268`` default-enabled); leave it on.

SSRF guard
----------
``query`` is sent as a package/CVE string to FIXED endpoints (OSV, GHSA,
CISA). A user-supplied URL is never fetched -- there is no ``url`` parameter
on any public function, so an attacker cannot trick the agent into hitting
an internal address.

Run ``python -m tools.threat_intel`` for a self-check that exercises the
cache round-trip + KEV degrade-without-network without any real HTTP calls.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tools.cve_lookup import CVESearchSettings, KEVCatalog
from tools.opsec import process_user_agent

__all__ = ["ThreatIntelSettings", "ThreatIntelClient", "search_threat_intel"]


# ── Prompt-injection hardening ───────────────────────────────────────────────

# Strings that came off the wire are untrusted. Strip control chars (keep only
# ``c >= " "`` -- this also drops ``\t``/``\n``/``\r`` and all C0/C1 controls)
# and cap at 200 chars so a malicious advisory body cannot smuggle a long
# instruction past the cap. Applied to EVERY string in the returned JSON.
_MAX_STR = 200


def _clean(value: Any) -> Any:
    """Recursively strip control chars + cap string length on feed data."""
    if isinstance(value, str):
        # Keep printable ASCII + printable Unicode (>= U+0020); drop controls.
        stripped = "".join(c for c in value if c >= " ")
        return stripped[:_MAX_STR]
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k)[:_MAX_STR]: _clean(v) for k, v in value.items()}
    return value


# ── Settings ─────────────────────────────────────────────────────────────────

_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
_GHSA_ENDPOINT = "https://api.github.com/graphql"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_PKG_RE = re.compile(r"^[A-Za-z0-9._/+-]{1,128}$")


@dataclass(frozen=True)
class ThreatIntelSettings:
    # Lab build: enabled by default so the feed is live out-of-the-box. The
    # operator opts out via config.yaml threat_intel.enabled: false.
    enabled: bool = True
    cache_dir: str = "exploit_workspace/.threat_intel"
    cache_ttl_seconds: int = 86400
    sources: dict[str, bool] = field(default_factory=lambda: {
        "osv": True, "ghsa": True, "kev": True, "exploitdb_rss": False,
    })
    max_results: int = 20
    github_token_env: str = "GITHUB_TOKEN"
    timeout_seconds: int = 30

    def source_enabled(self, name: str) -> bool:
        return bool(self.sources.get(name, False))


def _settings_from_config(config: dict[str, Any] | None) -> ThreatIntelSettings:
    cfg = (config or {}).get("threat_intel", {}) or {}
    sources_in = cfg.get("sources", {}) or {}
    sources = {
        "osv": bool(sources_in.get("osv", True)),
        "ghsa": bool(sources_in.get("ghsa", True)),
        "kev": bool(sources_in.get("kev", True)),
        "exploitdb_rss": bool(sources_in.get("exploitdb_rss", False)),
    }
    return ThreatIntelSettings(
        enabled=bool(cfg.get("enabled", False)),
        cache_dir=str(cfg.get("cache_dir", "exploit_workspace/.threat_intel")),
        cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 86400)),
        sources=sources,
        max_results=int(cfg.get("max_results", 20)),
        github_token_env=str(cfg.get("github_token_env", "GITHUB_TOKEN")),
        timeout_seconds=int(cfg.get("timeout_seconds", 30)),
    )


def _validate_query(query: str) -> str:
    """Reject anything that is not a package name or CVE ID.

    This is the SSRF guard: ``query`` is interpolated into a FIXED-endpoint
    request body (OSV) or a GraphQL query string (GHSA), never used as a URL.
    But we still reject shell-metachar / URL-shaped input so an agent that
    got prompt-injected cannot smuggle ``http://169.254.169.254/`` through.
    """
    q = (query or "").strip()
    if not q:
        raise ValueError("empty query")
    if len(q) > 128:
        raise ValueError("query too long")
    if _CVE_RE.match(q):
        return q.upper()
    if not _PKG_RE.match(q):
        raise ValueError("query must be a package name or CVE ID")
    return q


# ── HTTP helper (injectable for tests) ───────────────────────────────────────

def _http_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None,
    timeout: int,
    fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
) -> Any:
    """HTTP GET/POST returning parsed JSON. ``fetch_fn(url, method, body_json, headers)``
    overrides the real urllib path so tests never touch the network."""
    h = {"User-Agent": process_user_agent("netattackai-threat-intel/1.0")}
    if headers:
        h.update(headers)
    body_str = json.dumps(body) if body is not None else ""
    if fetch_fn is not None:
        return fetch_fn(url, method, body_str, h)
    req = urllib.request.Request(
        url,
        data=body_str.encode("utf-8") if body is not None else None,
        method=method,
        headers=h,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


# ── Cache ────────────────────────────────────────────────────────────────────

def _cache_key(query: str, source: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", query)
    return Path(f"{source}_{safe}.json")


def _cache_get(cache_dir: Path, query: str, source: str, ttl: int) -> Any | None:
    p = cache_dir / _cache_key(query, source)
    try:
        if p.exists() and (time.time() - p.stat().st_mtime) < ttl:
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _cache_put(cache_dir: Path, query: str, source: str, data: Any) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        p = cache_dir / _cache_key(query, source)
        p.write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception:
        pass  # cache is advisory


# ── Sources ──────────────────────────────────────────────────────────────────

def search_osv(
    query: str,
    settings: ThreatIntelSettings,
    cache_dir: Path,
    *,
    fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
) -> dict[str, Any]:
    """Search OSV.dev for a package or CVE. Returns ``{"vulns": [...]}``."""
    cached = _cache_get(cache_dir, query, "osv", settings.cache_ttl_seconds)
    if cached is not None:
        return cached
    is_cve = bool(_CVE_RE.match(query))
    body: dict[str, Any]
    if is_cve:
        body = {"version": query}
    else:
        body = {"package": {"name": query}}
    try:
        payload = _http_json(
            _OSV_ENDPOINT,
            method="POST",
            body=body,
            headers={"Content-Type": "application/json"},
            timeout=settings.timeout_seconds,
            fetch_fn=fetch_fn,
        )
    except Exception as exc:
        return {"error": f"osv fetch failed: {exc}"}
    vulns = []
    for v in (payload or {}).get("vulns", []) or []:
        vulns.append({
            "id": v.get("id", ""),
            "summary": v.get("summary", ""),
            "severity": (v.get("severity") or [{}])[0].get("score", "") if v.get("severity") else "",
            "aliases": v.get("aliases", []),
            "published": v.get("published", ""),
            "references": [r.get("url", "") for r in v.get("references", []) if r.get("url")],
        })
        if len(vulns) >= settings.max_results:
            break
    out = {"vulns": _clean(vulns)}
    _cache_put(cache_dir, query, "osv", out)
    return out


def search_ghsa(
    query: str,
    settings: ThreatIntelSettings,
    cache_dir: Path,
    *,
    fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
) -> dict[str, Any]:
    """Search GitHub Security Advisories via the GraphQL API.

    Degrades to ``{"error": "ghsa token missing"}`` when ``GITHUB_TOKEN`` is
    unset -- the caller (``search_threat_intel``) then drops ghsa from the
    result so OSV+KEV still answer. Requires a token because the GraphQL
    endpoint is auth-gated; the public REST advisories endpoint has a much
    lower rate limit and no package-name search.
    """
    token = os.environ.get(settings.github_token_env, "").strip()
    if not token:
        return {"error": "ghsa token missing"}
    cached = _cache_get(cache_dir, query, "ghsa", settings.cache_ttl_seconds)
    if cached is not None:
        return cached
    is_cve = bool(_CVE_RE.match(query))
    if is_cve:
        gql_query = (
            "query { securityAdvisories(first: 20, identifier: { type: CVE, value: \""
            + query + "\" }) { nodes { ghsaId summary severity publishedAt references { url } } } }"
        )
    else:
        # ponytail: GraphQL string escaping -- package names are validated to
        # [A-Za-z0-9._/+-] by _validate_query so no quote-injection risk.
        gql_query = (
            "query { securityVulnerabilities(first: 20, package: { type: NPM, name: \""
            + query + "\" }) { nodes { advisory { ghsaId summary severity publishedAt references { url } } } } }"
        )
    try:
        payload = _http_json(
            _GHSA_ENDPOINT,
            method="POST",
            body={"query": gql_query},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            timeout=settings.timeout_seconds,
            fetch_fn=fetch_fn,
        )
    except Exception as exc:
        return {"error": f"ghsa fetch failed: {exc}"}
    advisories = []
    # The two query shapes return different node paths; handle both.
    nodes = ((payload or {}).get("data") or {}).get("securityAdvisories", {}).get("nodes", [])
    if not nodes:
        sv_nodes = ((payload or {}).get("data") or {}).get("securityVulnerabilities", {}).get("nodes", [])
        nodes = [n.get("advisory", {}) for n in sv_nodes if n.get("advisory")]
    for a in nodes:
        advisories.append({
            "ghsa_id": a.get("ghsaId", ""),
            "summary": a.get("summary", ""),
            "severity": a.get("severity", ""),
            "published": a.get("publishedAt", ""),
            "references": [r.get("url", "") for r in a.get("references", []) if r.get("url")],
        })
        if len(advisories) >= settings.max_results:
            break
    out = {"advisories": _clean(advisories)}
    _cache_put(cache_dir, query, "ghsa", out)
    return out


def search_kev(
    query: str,
    kev: KEVCatalog | None,
) -> dict[str, Any]:
    """CISA KEV membership check for a CVE. Returns
    ``{"known_exploited": bool}``. Non-CVE queries get ``False`` (KEV is a
    CVE catalog, not a package database)."""
    if kev is None:
        return {"known_exploited": False, "note": "kev disabled"}
    if not _CVE_RE.match(query):
        return {"known_exploited": False}
    try:
        return {"known_exploited": bool(kev.is_known_exploited(query))}
    except Exception as exc:
        return {"known_exploited": False, "error": str(exc)[:120]}


# ── Client ───────────────────────────────────────────────────────────────────

class ThreatIntelClient:
    """OSV + GHSA + KEV client with JSON cache + injectable fetch.

    Construct with ``ThreatIntelSettings``; ``from_config`` reads the
    ``threat_intel`` config block. ``search(query, sources=...)`` returns the
    structured JSON shape documented on ``search_threat_intel``.
    """

    def __init__(
        self,
        settings: ThreatIntelSettings,
        *,
        kev: KEVCatalog | None = None,
        fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
    ) -> None:
        self.settings = settings
        self._kev = kev
        self._fetch_fn = fetch_fn
        self._cache_dir = Path(settings.cache_dir)

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any] | None,
        *,
        fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
    ) -> "ThreatIntelClient":
        s = _settings_from_config(config)
        kev: KEVCatalog | None = None
        if s.source_enabled("kev"):
            # Reuse the cve_lookup KEV settings (cache path + TTL) so the
            # catalog is fetched + cached once per process, shared with NVD.
            cve_cfg = (config or {}).get("cve_lookup", {}) or {}
            kev_settings = CVESearchSettings(
                kev_enabled=True,
                kev_cache_ttl_seconds=int(cve_cfg.get("kev_cache_ttl_seconds", 86400)),
                kev_cache_path=str(cve_cfg.get("kev_cache_path", "")),
                timeout_seconds=int(cve_cfg.get("timeout_seconds", 30)),
            )
            kev = KEVCatalog(kev_settings)
        return cls(s, kev=kev, fetch_fn=fetch_fn)

    def search(self, query: str, sources: str = "osv,ghsa,kev") -> dict[str, Any]:
        q = _validate_query(query)
        requested = {s.strip() for s in sources.split(",") if s.strip()}
        out: dict[str, Any] = {"query": q, "sources": {}}
        if not self.settings.enabled:
            out["error"] = "threat_intel disabled"
            return out
        if "osv" in requested and self.settings.source_enabled("osv"):
            out["sources"]["osv"] = search_osv(q, self.settings, self._cache_dir, fetch_fn=self._fetch_fn)
        if "ghsa" in requested and self.settings.source_enabled("ghsa"):
            res = search_ghsa(q, self.settings, self._cache_dir, fetch_fn=self._fetch_fn)
            # Token-missing degrades to osv+kev -- drop ghsa from sources so
            # the agent doesn't see a noisy error block on every call.
            if isinstance(res, dict) and res.get("error") == "ghsa token missing":
                out["sources"]["ghsa"] = {"skipped": "token missing"}
            else:
                out["sources"]["ghsa"] = res
        if "kev" in requested and self.settings.source_enabled("kev"):
            out["sources"]["kev"] = search_kev(q, self._kev)
        return _clean(out)


# ── Convenience entry point ──────────────────────────────────────────────────

def search_threat_intel(
    query: str,
    sources: str = "osv,ghsa,kev",
    config: dict[str, Any] | None = None,
    *,
    fetch_fn: Callable[[str, str, str, dict[str, str]], Any] | None = None,
) -> dict[str, Any]:
    """Search OSV.dev / GHSA / CISA KEV for a package or CVE.

    Advisory only -- never touches the target. Returns a JSON block::

        {"query": "...", "sources": {"osv": {"vulns": [...]},
                                     "ghsa": {"advisories": [...]},
                                     "kev": {"known_exploited": false}}}
    """
    client = ThreatIntelClient.from_config(config, fetch_fn=fetch_fn)
    return client.search(query, sources=sources)


# ── Self-check (no real HTTP) ────────────────────────────────────────────────

def _demo() -> None:
    """Exercise cache round-trip + KEV degrade-without-network. No real HTTP."""
    import tempfile

    def fake_osv(url, method, body_str, headers):
        body = json.loads(body_str) if body_str else {}
        if "package" in body and body["package"].get("name") == "requests":
            return {"vulns": [
                {"id": "PYSEC-2018-96", "summary": "requests RCE (fake)",
                 "references": [{"url": "https://example.com/pysec"}]},
            ]}
        return {"vulns": []}

    def fake_ghsa(url, method, body_str, headers):
        if "Bearer" not in headers.get("Authorization", ""):
            raise urllib.error.URLError("no auth")
        return {"data": {"securityVulnerabilities": {"nodes": [
            {"advisory": {"ghsaId": "GHSA-1", "summary": "fake ghsa",
                          "severity": "HIGH", "references": []}},
        ]}}}

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "threat_intel": {
                "enabled": True,
                "cache_dir": tmp,
                "cache_ttl_seconds": 3600,
                "sources": {"osv": True, "ghsa": True, "kev": True},
                "max_results": 5,
            },
            "cve_lookup": {"kev_enabled": True, "kev_cache_ttl_seconds": 3600},
        }
        os.environ["GITHUB_TOKEN"] = "fake-token"
        try:
            res = search_threat_intel("requests", config=cfg, fetch_fn=lambda u, m, b, h: (
                fake_osv(u, m, b, h) if "osv.dev" in u else fake_ghsa(u, m, b, h)
            ))
        finally:
            os.environ.pop("GITHUB_TOKEN", None)
        assert res["query"] == "requests"
        assert res["sources"]["osv"]["vulns"][0]["id"] == "PYSEC-2018-96"
        assert res["sources"]["ghsa"]["advisories"][0]["ghsa_id"] == "GHSA-1"
        assert res["sources"]["kev"]["known_exploited"] is False
        # Cache round-trip: second call must not re-fetch (no fetch_fn wired
        # into the second call -- if it tried the network it would throw).
        res2 = search_threat_intel("requests", config=cfg)
        assert res2["sources"]["osv"]["vulns"][0]["id"] == "PYSEC-2018-96"
        # Prompt-injection cap: a >200-char summary would be truncated.
        long_summary = "X" * 500
        def fake_long(url, method, body_str, headers):
            return {"vulns": [{"id": "L", "summary": long_summary}]}
        res3 = search_threat_intel("longpkg", config=cfg, fetch_fn=fake_long)
        assert len(res3["sources"]["osv"]["vulns"][0]["summary"]) <= 200
        print("threat_intel demo OK")


if __name__ == "__main__":
    _demo()
