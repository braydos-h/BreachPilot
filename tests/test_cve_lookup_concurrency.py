"""Concurrency regression tests for tools/cve_lookup.py (M23).

The NVDClient LRU cache is shared between the sync and async search paths and
may be touched from multiple threads (``search_sync`` runs the network fetch in
the calling thread). Without the ``_cache_lock`` guard, two concurrent
``search_sync`` calls for the same query can race on ``move_to_end`` / ``del``
/ ``popitem`` and corrupt the OrderedDict or raise ``KeyError``.

These tests mock ``urlopen`` with a threading barrier so both threads land in
the cache-miss branch simultaneously, then assert the cache is left consistent.
"""

from __future__ import annotations

import threading
from unittest.mock import patch

from tools.cve_lookup import CVEEntry, CVESearchSettings, NVDClient

SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI feature exploit."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                "references": [{"url": "https://example.com/ref"}],
            }
        }
    ]
}


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        import json

        return json.dumps(self._payload).encode("utf-8")


def _make_client() -> NVDClient:
    # Tiny TTL so the cache entry is fresh; small max_entries to exercise popitem.
    settings = CVESearchSettings(
        enabled=True,
        timeout_seconds=5,
        max_results=5,
        cache_ttl_seconds=3600,
        cache_max_entries=2,
        rate_limit_seconds=0.0,
    )
    return NVDClient(settings)


def test_search_sync_concurrent_same_query_no_cache_corruption() -> None:
    """Two concurrent search_sync calls for the same query must not corrupt the
    cache. A threading barrier makes both threads reach the cache-miss fetch
    simultaneously, then both write; the lock serializes move_to_end/popitem."""
    client = _make_client()

    barrier = threading.Barrier(2)
    fetch_count = {"n": 0}
    fetch_lock = threading.Lock()

    def fake_urlopen(request, timeout):  # noqa: ANN001
        # Both threads block here until both have entered the fetch path
        # (i.e. both saw a cache miss simultaneously).
        barrier.wait(timeout=5)
        with fetch_lock:
            fetch_count["n"] += 1
        return _FakeResponse(SAMPLE_NVD_RESPONSE)

    results: dict[str, list[CVEEntry]] = {}
    errors: list[BaseException] = []

    def worker(name: str) -> None:
        try:
            results[name] = client.search_sync("nginx 1.18.0")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        t1 = threading.Thread(target=worker, args=("a",))
        t2 = threading.Thread(target=worker, args=("b",))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

    assert not errors, f"workers raised: {errors}"
    # Both workers must return parsed entries.
    assert len(results.get("a", [])) == 1
    assert len(results.get("b", [])) == 1
    assert results["a"][0].cve_id == "CVE-2021-44228"
    # The cache must be left in a consistent state: exactly one entry for the
    # query key, retrievable from the same client.
    assert "nginx 1.18.0" in client._cache
    # Repeating the query must hit the cache (no additional fetch).
    cached = client.search_sync("nginx 1.18.0")
    assert len(cached) == 1
    assert fetch_count["n"] == 2  # only the two racing calls hit the network


def test_search_sync_cache_eviction_under_lock() -> None:
    """cache_max_entries=2 with 3 distinct queries: the popitem eviction path
    must run under the lock without raising. Drives the write/popitem block."""
    client = _make_client()

    def fake_urlopen(request, timeout):  # noqa: ANN001
        return _FakeResponse(SAMPLE_NVD_RESPONSE)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        for q in ("nginx 1.18.0", "apache 2.4.41", "openssh 8.5p1"):
            entries = client.search_sync(q)
            assert len(entries) == 1

    # Cache should have evicted to at most cache_max_entries.
    assert len(client._cache) <= client.settings.cache_max_entries


def test_cache_lock_is_a_threading_lock() -> None:
    """Smoke test that the guard attribute exists and is a threading.Lock."""
    client = _make_client()
    assert isinstance(client._cache_lock, type(threading.Lock()))


def test_fetch_sync_sends_user_agent_header() -> None:
    """M23b: _fetch_sync must attach a User-Agent header to the request."""
    client = _make_client()
    captured: dict[str, str] = {}

    def fake_urlopen(request, timeout):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["ua"] = request.headers.get("User-agent", "")
        return _FakeResponse(SAMPLE_NVD_RESPONSE)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client.search_sync("nginx 1.18.0")

    assert "netattackai-cve-lookup" in captured["ua"]
