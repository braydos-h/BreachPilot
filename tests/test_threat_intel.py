"""Tests for the threat-intel feed (OSV + GHSA + KEV).

All HTTP is mocked via the injectable ``fetch_fn`` -- no live network. The
tests cover:
  - OSV parsing + caching round-trip (second call served from cache, no fetch)
  - GHSA parsing + token-missing degrade (ghsa dropped from sources)
  - KEV membership check via the shared KEVCatalog
  - Prompt-injection hardening: every returned string is ``_clean``-capped
    at 200 chars and control chars are stripped
  - SSRF guard: a URL-shaped query is rejected (only package/CVE accepted)
  - ``demo()`` self-check runs without real HTTP
"""
from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from tools.cve_lookup import CVESearchSettings, KEVCatalog
from tools.threat_intel import (
    ThreatIntelClient,
    ThreatIntelSettings,
    _clean,
    _validate_query,
    search_ghsa,
    search_kev,
    search_osv,
    search_threat_intel,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

def _cfg(tmp_path: Path, **overrides) -> dict:
    base = {
        "threat_intel": {
            "enabled": True,
            "cache_dir": str(tmp_path),
            "cache_ttl_seconds": 3600,
            "sources": {"osv": True, "ghsa": True, "kev": True},
            "max_results": 5,
            "github_token_env": "GITHUB_TOKEN",
        },
        "cve_lookup": {"kev_enabled": True, "kev_cache_ttl_seconds": 3600},
    }
    base.update(overrides)
    return base


_OSV_PAYLOAD_REQUESTS = {
    "vulns": [
        {
            "id": "PYSEC-2018-96",
            "summary": "requests RCE (fake)",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "aliases": ["CVE-2018-1000001"],
            "published": "2018-01-01T00:00:00Z",
            "references": [{"url": "https://example.com/pysec"}, {"url": "https://example.com/advisory"}],
        },
    ],
}

_GHSA_PAYLOAD = {
    "data": {
        "securityVulnerabilities": {
            "nodes": [
                {
                    "advisory": {
                        "ghsaId": "GHSA-1",
                        "summary": "fake ghsa",
                        "severity": "HIGH",
                        "publishedAt": "2020-01-01T00:00:00Z",
                        "references": [{"url": "https://github.com/advisories/GHSA-1"}],
                    },
                },
            ],
        },
    },
}


def _fetch_router(osv_fn=None, ghsa_fn=None):
    """Return a fetch_fn that routes by URL so one callable handles both."""
    def _fetch(url, method, body_str, headers):
        if "osv.dev" in url:
            if osv_fn is None:
                return _OSV_PAYLOAD_REQUESTS
            return osv_fn(url, method, body_str, headers)
        if "api.github.com" in url:
            if ghsa_fn is None:
                return _GHSA_PAYLOAD
            return ghsa_fn(url, method, body_str, headers)
        raise ValueError(f"unexpected url {url}")
    return _fetch


# ── _clean / _validate_query ─────────────────────────────────────────────────

def test_clean_strips_control_chars_and_caps_length():
    assert _clean("abc\x00def\t\n") == "abcdef"
    assert _clean("X" * 500) == "X" * 200
    assert _clean(["a\x01b", {"k": "v\x02"}]) == ["ab", {"k": "v"}]
    assert _clean(123) == 123  # non-strings pass through


def test_validate_query_accepts_package_and_cve():
    assert _validate_query("requests") == "requests"
    assert _validate_query("cve-2021-44228") == "CVE-2021-44228"
    assert _validate_query("CVE-2021-44228") == "CVE-2021-44228"


def test_validate_query_rejects_url_and_metachar():
    with pytest.raises(ValueError):
        _validate_query("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        _validate_query("foo; rm -rf /")
    with pytest.raises(ValueError):
        _validate_query("")
    with pytest.raises(ValueError):
        _validate_query("x" * 200)


# ── OSV ──────────────────────────────────────────────────────────────────────

def test_search_osv_parses_and_caches(tmp_path: Path):
    calls = {"n": 0}
    def osv_fn(url, method, body_str, headers):
        calls["n"] += 1
        return _OSV_PAYLOAD_REQUESTS
    settings = ThreatIntelSettings(enabled=True, cache_dir=str(tmp_path), cache_ttl_seconds=3600,
                                   sources={"osv": True, "ghsa": False, "kev": False, "exploitdb_rss": False},
                                   max_results=5)
    res1 = search_osv("requests", settings, tmp_path, fetch_fn=_fetch_router(osv_fn=osv_fn))
    assert res1["vulns"][0]["id"] == "PYSEC-2018-96"
    assert res1["vulns"][0]["references"][0] == "https://example.com/pysec"
    # Second call served from cache -> no new fetch.
    res2 = search_osv("requests", settings, tmp_path, fetch_fn=_fetch_router(osv_fn=osv_fn))
    assert res2["vulns"][0]["id"] == "PYSEC-2018-96"
    assert calls["n"] == 1


def test_search_osv_network_error_returns_error_dict(tmp_path: Path):
    def boom(url, method, body_str, headers):
        raise urllib.error.URLError("net down")
    settings = ThreatIntelSettings(enabled=True, cache_dir=str(tmp_path),
                                   sources={"osv": True, "ghsa": False, "kev": False, "exploitdb_rss": False})
    res = search_osv("requests", settings, tmp_path, fetch_fn=boom)
    assert "error" in res
    assert "osv fetch failed" in res["error"]


def test_search_osv_cve_query_uses_version_field(tmp_path: Path):
    captured = {}
    def osv_fn(url, method, body_str, headers):
        captured["body"] = json.loads(body_str)
        return {"vulns": []}
    settings = ThreatIntelSettings(enabled=True, cache_dir=str(tmp_path),
                                   sources={"osv": True, "ghsa": False, "kev": False, "exploitdb_rss": False})
    search_osv("CVE-2021-44228", settings, tmp_path, fetch_fn=_fetch_router(osv_fn=osv_fn))
    # CVE queries go to the version field, not the package field.
    assert "version" in captured["body"]
    assert captured["body"]["version"] == "CVE-2021-44228"


# ── GHSA ─────────────────────────────────────────────────────────────────────

def test_search_ghsa_parses_and_requires_token(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    settings = ThreatIntelSettings(enabled=True, cache_dir=str(tmp_path),
                                   sources={"osv": False, "ghsa": True, "kev": False, "exploitdb_rss": False},
                                   github_token_env="GITHUB_TOKEN")
    res = search_ghsa("requests", settings, tmp_path, fetch_fn=_fetch_router(ghsa_fn=lambda *a: _GHSA_PAYLOAD))
    assert res["advisories"][0]["ghsa_id"] == "GHSA-1"
    assert res["advisories"][0]["severity"] == "HIGH"


def test_search_ghsa_token_missing_returns_error(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    settings = ThreatIntelSettings(enabled=True, cache_dir=str(tmp_path),
                                   sources={"osv": False, "ghsa": True, "kev": False, "exploitdb_rss": False})
    res = search_ghsa("requests", settings, tmp_path, fetch_fn=_fetch_router())
    assert res.get("error") == "ghsa token missing"


# ── KEV ──────────────────────────────────────────────────────────────────────

_KEV_FEED = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}


def test_search_kev_true_for_listed_cve(tmp_path: Path):
    kev = KEVCatalog(
        CVESearchSettings(kev_enabled=True, kev_cache_ttl_seconds=3600),
        cache_path=str(tmp_path / "kev.json"),
        fetch_fn=lambda u: _KEV_FEED,
    )
    res = search_kev("CVE-2021-44228", kev)
    assert res["known_exploited"] is True


def test_search_kev_false_for_unlisted_cve(tmp_path: Path):
    kev = KEVCatalog(
        CVESearchSettings(kev_enabled=True),
        cache_path=str(tmp_path / "kev.json"),
        fetch_fn=lambda u: _KEV_FEED,
    )
    assert search_kev("CVE-9999-0000", kev)["known_exploited"] is False


def test_search_kev_false_for_package_query(tmp_path: Path):
    """KEV is a CVE catalog -- a package query gets ``known_exploited: False``."""
    kev = KEVCatalog(
        CVESearchSettings(kev_enabled=True),
        cache_path=str(tmp_path / "kev.json"),
        fetch_fn=lambda u: _KEV_FEED,
    )
    res = search_kev("requests", kev)
    assert res["known_exploited"] is False


def test_search_kev_none_catalog_returns_disabled_note():
    res = search_kev("CVE-2021-44228", None)
    assert res["known_exploited"] is False
    assert "disabled" in res.get("note", "")


# ── ThreatIntelClient.search end-to-end ─────────────────────────────────────

def test_client_search_combines_sources(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    client = ThreatIntelClient.from_config(_cfg(tmp_path), fetch_fn=_fetch_router())
    res = client.search("requests", sources="osv,ghsa,kev")
    assert res["query"] == "requests"
    assert res["sources"]["osv"]["vulns"][0]["id"] == "PYSEC-2018-96"
    assert res["sources"]["ghsa"]["advisories"][0]["ghsa_id"] == "GHSA-1"
    assert res["sources"]["kev"]["known_exploited"] is False


def test_client_search_ghsa_token_missing_degrades(tmp_path: Path, monkeypatch):
    """When GITHUB_TOKEN is unset, ghsa is dropped from sources (not a noisy
    error block) and osv+kev still answer."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    client = ThreatIntelClient.from_config(_cfg(tmp_path), fetch_fn=_fetch_router())
    res = client.search("requests", sources="osv,ghsa,kev")
    assert res["sources"]["osv"]["vulns"][0]["id"] == "PYSEC-2018-96"
    assert res["sources"]["ghsa"] == {"skipped": "token missing"}
    assert res["sources"]["kev"]["known_exploited"] is False


def test_client_search_disabled_returns_error(tmp_path: Path):
    cfg = {"threat_intel": {"enabled": False, "cache_dir": str(tmp_path)}}
    client = ThreatIntelClient.from_config(cfg, fetch_fn=_fetch_router())
    res = client.search("requests")
    assert res.get("error") == "threat_intel disabled"


def test_client_search_source_filtering(tmp_path: Path, monkeypatch):
    """When sources='osv' only, ghsa and kev are not in the result."""
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    client = ThreatIntelClient.from_config(_cfg(tmp_path), fetch_fn=_fetch_router())
    res = client.search("requests", sources="osv")
    assert "osv" in res["sources"]
    assert "ghsa" not in res["sources"]
    assert "kev" not in res["sources"]


def test_client_search_prompt_injection_cap(tmp_path: Path):
    """A >200-char summary in the feed is capped by _clean."""
    long = "X" * 500
    def osv_fn(url, method, body_str, headers):
        return {"vulns": [{"id": "L", "summary": long, "references": []}]}
    client = ThreatIntelClient.from_config(_cfg(tmp_path), fetch_fn=_fetch_router(osv_fn=osv_fn))
    res = client.search("longpkg", sources="osv")
    assert len(res["sources"]["osv"]["vulns"][0]["summary"]) <= 200


def test_client_search_max_results_enforced(tmp_path: Path, monkeypatch):
    """max_results caps the returned vuln list."""
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    def osv_fn(url, method, body_str, headers):
        return {"vulns": [{"id": f"V{i}", "summary": "s"} for i in range(50)]}
    cfg = _cfg(tmp_path)
    cfg["threat_intel"]["max_results"] = 3
    client = ThreatIntelClient.from_config(cfg, fetch_fn=_fetch_router(osv_fn=osv_fn))
    res = client.search("requests", sources="osv")
    assert len(res["sources"]["osv"]["vulns"]) == 3


def test_search_threat_intel_module_entry_point(tmp_path: Path, monkeypatch):
    """The module-level search_threat_intel() reads config + returns JSON."""
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    res = search_threat_intel("requests", config=_cfg(tmp_path), fetch_fn=_fetch_router())
    assert res["sources"]["osv"]["vulns"][0]["id"] == "PYSEC-2018-96"


# ── demo() self-check ────────────────────────────────────────────────────────

def test_demo_runs_without_network(monkeypatch):
    """The ``python -m tools.threat_intel`` self-check passes with fakes."""
    from tools.threat_intel import _demo
    # _demo manages its own tempdir + GITHUB_TOKEN; just confirm it doesn't raise.
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    _demo()
