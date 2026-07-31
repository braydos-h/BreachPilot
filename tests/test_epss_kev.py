"""Phase 2 — EPSS + KEV vuln-intel enrichment (opt-in, default OFF).

Both enrichers are pure stdlib (urllib) with injectable ``fetch_fn`` so no
live network is touched. When the corresponding ``CVESearchSettings`` flag is
off, ``NVDClient`` does not construct the enricher and ``_parse`` output is
unchanged. EPSS batches CVEs per call; KEV caches the CISA catalog to disk
with a TTL.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tools.cve_lookup import (
    CVEEntry,
    CVESearchSettings,
    EPSSClient,
    KEVCatalog,
    NVDClient,
)


def _settings(**kw) -> CVESearchSettings:
    base = dict(timeout_seconds=5, max_results=5, cache_ttl_seconds=0)
    base.update(kw)
    return CVESearchSettings(**base)


def _nvd_payload(cve_id: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "test vuln"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
                    "published": "2021-12-10T00:00:00.000Z",
                    "references": [{"url": "https://example.com/ref"}],
                }
            }
        ]
    }


# ── EPSSClient ────────────────────────────────────────────────────────────────

def test_epss_get_batch_parses_response() -> None:
    def fake_fetch(url):
        return {"data": [
            {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"},
            {"cve": "CVE-2020-1234", "epss": "0.50", "percentile": "0.90"},
        ]}
    client = EPSSClient(_settings(epss_enabled=True))
    recs = client.get_batch(["CVE-2021-44228", "CVE-2020-1234"], fetch_fn=fake_fetch)
    assert recs["CVE-2021-44228"]["epss"] == pytest.approx(0.97)
    assert recs["CVE-2021-44228"]["percentile"] == pytest.approx(0.999)
    assert recs["CVE-2020-1234"]["epss"] == pytest.approx(0.50)


def test_epss_get_batch_caches_results() -> None:
    calls = {"n": 0}
    def fake_fetch(url):
        calls["n"] += 1
        return {"data": [{"cve": "CVE-X", "epss": "0.1", "percentile": "0.2"}]}
    client = EPSSClient(_settings(epss_enabled=True))
    client.get_batch(["CVE-X"], fetch_fn=fake_fetch)
    client.get_batch(["CVE-X"], fetch_fn=fake_fetch)  # second call served from cache
    assert calls["n"] == 1


def test_epss_get_batch_empty_input() -> None:
    client = EPSSClient(_settings(epss_enabled=True))
    assert client.get_batch([], fetch_fn=lambda u: {}) == {}


def test_epss_get_batch_failure_returns_empty() -> None:
    def boom(url):
        raise RuntimeError("net down")
    client = EPSSClient(_settings(epss_enabled=True))
    assert client.get_batch(["CVE-1"], fetch_fn=boom) == {}


def test_epss_get_batch_skips_garbage_rows() -> None:
    def fake_fetch(url):
        return {"data": [
            {"cve": "CVE-1", "epss": "not-a-number", "percentile": "0.5"},
            {"cve": "CVE-2", "epss": "0.3", "percentile": "0.4"},
        ]}
    client = EPSSClient(_settings(epss_enabled=True))
    recs = client.get_batch(["CVE-1", "CVE-2"], fetch_fn=fake_fetch)
    assert "CVE-1" not in recs  # garbage epss dropped
    assert "CVE-2" in recs


# ── KEVCatalog ───────────────────────────────────────────────────────────────

_KEV_FEED = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
        {"cveID": "CVE-2021-26855", "vendorProject": "Microsoft", "product": "Exchange"},
    ]
}


def test_kev_is_known_exploited_from_fetch(tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    cat = KEVCatalog(_settings(kev_enabled=True), cache_path=str(cache), fetch_fn=lambda u: _KEV_FEED)
    assert cat.is_known_exploited("CVE-2021-44228") is True
    assert cat.is_known_exploited("CVE-2021-26855") is True
    assert cat.is_known_exploited("CVE-9999-0000") is False


def test_kev_caches_to_disk(tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    calls = {"n": 0}
    def fake_fetch(url):
        calls["n"] += 1
        return _KEV_FEED
    cat = KEVCatalog(_settings(kev_enabled=True), cache_path=str(cache), fetch_fn=fake_fetch)
    cat.is_known_exploited("CVE-2021-44228")
    assert cache.exists(), "KEV catalog should be written to disk cache"
    # A second instance reads from cache (no new fetch).
    cat2 = KEVCatalog(_settings(kev_enabled=True), cache_path=str(cache), fetch_fn=fake_fetch)
    assert cat2.is_known_exploited("CVE-2021-44228")
    assert calls["n"] == 1


def test_kev_refreshes_after_ttl(tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    calls = {"n": 0}
    def fake_fetch(url):
        calls["n"] += 1
        return _KEV_FEED
    # TTL of 1s so we can expire it.
    cat = KEVCatalog(_settings(kev_enabled=True, kev_cache_ttl_seconds=1), cache_path=str(cache), fetch_fn=fake_fetch)
    cat.is_known_exploited("CVE-2021-44228")
    assert calls["n"] == 1
    # Backdate the cache file so it's older than TTL.
    import os
    old = time.time() - 10
    os.utime(cache, (old, old))
    cat2 = KEVCatalog(_settings(kev_enabled=True, kev_cache_ttl_seconds=1), cache_path=str(cache), fetch_fn=fake_fetch)
    cat2.is_known_exploited("CVE-2021-44228")
    assert calls["n"] == 2, "expired cache should re-fetch"


def test_kev_failure_returns_false(tmp_path: Path) -> None:
    def boom(url):
        raise RuntimeError("cisa down")
    cat = KEVCatalog(_settings(kev_enabled=True), cache_path=str(tmp_path / "kev.json"), fetch_fn=boom)
    assert cat.is_known_exploited("CVE-2021-44228") is False


# ── NVDClient enrichment wiring ───────────────────────────────────────────────

def test_nvd_parse_enriches_when_enabled(tmp_path: Path) -> None:
    """With epss_enabled + kev_enabled ON, _parse populates CVEEntry fields."""
    settings = _settings(epss_enabled=True, kev_enabled=True)
    client = NVDClient(settings)
    # Inject the enrichers' I/O so no live network is touched.
    client._epss._cache["CVE-2021-44228"] = {"epss": 0.97, "percentile": 0.999}
    # KEV: point at a fresh cache path and inject the feed.
    client._kev._path = str(tmp_path / "kev.json")
    client._kev._fetch_fn = lambda u: _KEV_FEED

    entries = client._parse(_nvd_payload("CVE-2021-44228"))
    assert len(entries) == 1
    e = entries[0]
    assert e.epss == pytest.approx(0.97)
    assert e.epss_percentile == pytest.approx(0.999)
    assert e.kev is True
    s = e.summary()
    assert "EPSS: 0.9700" in s
    assert "KEV: yes" in s


def test_nvd_parse_off_baseline_unchanged() -> None:
    """With both flags OFF (default), _parse produces entries with no EPSS/KEV
    and the enrichers are None. This is the first-run invariant."""
    settings = _settings()  # epss_enabled=False, kev_enabled=False
    client = NVDClient(settings)
    assert client._epss is None
    assert client._kev is None
    entries = client._parse(_nvd_payload("CVE-2021-44228"))
    e = entries[0]
    assert e.epss is None
    assert e.epss_percentile is None
    assert e.kev is False
    assert "EPSS" not in e.summary()
    assert "KEV" not in e.summary()


def test_nvd_parse_kev_only_when_epss_off(tmp_path: Path) -> None:
    settings = _settings(kev_enabled=True)
    client = NVDClient(settings)
    assert client._epss is None and client._kev is not None
    client._kev._path = str(tmp_path / "kev2.json")
    client._kev._fetch_fn = lambda u: _KEV_FEED
    entries = client._parse(_nvd_payload("CVE-2021-44228"))
    e = entries[0]
    assert e.epss is None       # EPSS off -> untouched
    assert e.kev is True        # KEV on -> populated


def test_search_by_cpe_sync_builds_cpe_param(monkeypatch) -> None:
    """search_by_cpe_sync issues an NVD request with the cpeName parameter."""
    captured = {}
    settings = _settings()
    client = NVDClient(settings)

    def fake_fetch_by_params(params):
        captured.update(params)
        return []

    monkeypatch.setattr(client, "_fetch_by_params", fake_fetch_by_params)
    client.search_by_cpe_sync("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")
    assert captured.get("cpeName") == "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"


def test_search_by_cpe_sync_empty_cpe_returns_empty() -> None:
    client = NVDClient(_settings())
    assert client.search_by_cpe_sync("") == []


def test_format_cve_results_renders_epss_kev() -> None:
    e = CVEEntry(cve_id="CVE-2021-44228", severity="CRITICAL", cvss_score=9.8,
                 epss=0.97, epss_percentile=0.999, kev=True)
    out = __import__("tools.cve_lookup", fromlist=["format_cve_results"]).format_cve_results([e], "log4j")
    assert "EPSS: 0.9700" in out
    assert "KEV: yes" in out
    assert "CVSS: 9.8" in out