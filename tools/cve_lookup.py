"""NVD CVE API 2.0 lookup with rate limiting and caching.

Queries the National Vulnerability Database by keyword (e.g. 'nginx 1.18.0')
and returns structured CVE entries with CVSS scores, severity, CWE, and refs.

Without an API key, NVD enforces a ~6-second rate limit between requests.
This wrapper handles that limit automatically.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from tools.opsec import process_user_agent

from tools.reliability import CircuitBreaker, RateLimiter


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _sanitize_query(query: str) -> str:
    text = " ".join(str(query or "").strip().split())
    if not text:
        raise ValueError("empty query.")
    if len(text) > 180:
        raise ValueError("query too long.")
    if re.search(r"[&;|<>\`$\\\n\r]", text):
        raise ValueError("shell metacharacters in query.")
    return text


@dataclass(frozen=True)
class CVESearchSettings:
    enabled: bool = True
    timeout_seconds: int = 30
    max_results: int = 5
    cache_ttl_seconds: int = 3600
    cache_max_entries: int = 100
    rate_limit_seconds: float = 6.0  # NVD recommended without API key
    api_key_env: str = "NVD_API_KEY"
    # Tier 1.2: circuit-breaker tuning. After ``circuit_failure_threshold``
    # consecutive fetch failures the breaker opens and ``search``/``search_sync``
    # short-circuit to ``[]`` (graceful degradation -- stop hammering a dead NVD
    # API) until ``circuit_recovery_timeout`` seconds elapse, then a half-open
    # probe call is allowed. A fetch failure while CLOSED still records the
    # failure and re-raises (existing RuntimeError contract preserved).
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: float = 60.0


@dataclass
class CVEEntry:
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    severity: str = ""  # LOW, MEDIUM, HIGH, CRITICAL
    cwe: str = ""  # e.g. CWE-79
    published: str = ""  # YYYY-MM-DD
    references: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"- {self.cve_id} ({self.severity or 'unknown severity'})"]
        if self.cvss_score is not None:
            lines.append(f"  CVSS: {self.cvss_score}")
        if self.cwe:
            lines.append(f"  CWE: {self.cwe}")
        if self.published:
            lines.append(f"  Published: {self.published}")
        if self.description:
            lines.append(f"  Description: {self.description[:300]}")
        if self.references:
            lines.append(f"  References: {', '.join(self.references[:3])}")
        return "\n".join(lines)


class NVDClient:
    """Async-safe NVD API 2.0 client with rate limiting and LRU cache."""

    def __init__(self, settings: CVESearchSettings,
                 rate_limiter: RateLimiter | None = None) -> None:
        self.settings = settings
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        self._cache: OrderedDict[str, tuple[float, list[CVEEntry]]] = OrderedDict()
        # M23: the LRU cache is shared between the sync and async search paths
        # (and across threads when search_sync is called concurrently), so all
        # read/move_to_end/del and write/popitem mutations must hold this lock.
        self._cache_lock = threading.Lock()
        self._breaker = CircuitBreaker(
            "nvd",
            failure_threshold=settings.circuit_failure_threshold,
            recovery_timeout=settings.circuit_recovery_timeout,
        )
        # Tier 1.8: optional shared, cross-instance/cross-loop rate limiter.
        # When provided, search/search_sync throttle through it (key "nvd")
        # instead of the per-instance _lock+_last_request_time block, so
        # multiple NVDClient instances in one process (e.g. concurrent MCP
        # requests each building a client) share ONE NVD rate budget rather
        # than each hammering at its own 6s gap. When None, the original
        # per-instance throttle is used (back-compat -- vuln_agent and tests
        # construct NVDClient without a shared limiter).
        self._rate_limiter = rate_limiter

    async def search(self, query: str) -> list[CVEEntry]:
        if not self.settings.enabled:
            return []

        try:
            clean_query = _sanitize_query(query)
        except ValueError:
            return []

        cache_key = clean_query.lower()
        now = time.monotonic()
        with self._cache_lock:
            if cache_key in self._cache:
                cached_at, entries = self._cache[cache_key]
                if now - cached_at < self.settings.cache_ttl_seconds:
                    self._cache.move_to_end(cache_key)
                    return entries
                else:
                    del self._cache[cache_key]

        if not self._breaker.can_execute():
            # Circuit open (NVD has been failing) -- degrade gracefully to an
            # empty result instead of sleeping + hammering a dead API. Do NOT
            # cache the empty result, so a recovered NVD is picked up on the
            # next half-open probe.
            return []

        if self._rate_limiter is not None:
            # Tier 1.8: shared limiter path -- one NVD budget across all
            # NVDClient instances in this process.
            await self._rate_limiter.acquire("nvd")
        else:
            async with self._lock:
                elapsed = time.monotonic() - self._last_request_time
                if elapsed < self.settings.rate_limit_seconds:
                    await asyncio.sleep(self.settings.rate_limit_seconds - elapsed)
                self._last_request_time = time.monotonic()

        try:
            entries = await self._fetch_async(clean_query)
        except Exception:
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        with self._cache_lock:
            self._cache[cache_key] = (time.monotonic(), entries)
            if len(self._cache) > self.settings.cache_max_entries:
                self._cache.popitem(last=False)
        return entries

    def search_sync(self, query: str) -> list[CVEEntry]:
        """Synchronous wrapper that reuses the same fetching/caching logic."""
        if not self.settings.enabled:
            return []
        try:
            clean_query = _sanitize_query(query)
        except ValueError:
            return []

        cache_key = clean_query.lower()
        now = time.monotonic()
        with self._cache_lock:
            if cache_key in self._cache:
                cached_at, entries = self._cache[cache_key]
                if now - cached_at < self.settings.cache_ttl_seconds:
                    self._cache.move_to_end(cache_key)
                    return entries
                else:
                    del self._cache[cache_key]

        if not self._breaker.can_execute():
            return []

        if self._rate_limiter is not None:
            # Tier 1.8: shared limiter path (sync variant).
            self._rate_limiter.acquire_sync("nvd")
        else:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self.settings.rate_limit_seconds:
                time.sleep(self.settings.rate_limit_seconds - elapsed)
            self._last_request_time = time.monotonic()

        try:
            entries = self._fetch_sync(clean_query)
        except Exception:
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        with self._cache_lock:
            self._cache[cache_key] = (time.monotonic(), entries)
            if len(self._cache) > self.settings.cache_max_entries:
                self._cache.popitem(last=False)
        return entries

    async def _fetch_async(self, query: str) -> list[CVEEntry]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch_sync, query)

    def _fetch_sync(self, query: str) -> list[CVEEntry]:
        """Perform the actual HTTP GET to NVD API."""
        params: dict[str, str] = {
            "keywordSearch": query,
            "resultsPerPage": str(self.settings.max_results),
        }
        api_key = os.environ.get(self.settings.api_key_env, "").strip()
        if api_key:
            params["apiKey"] = api_key

        url = NVD_API_BASE + "?" + urllib.parse.urlencode(params)
        # M23b: NVD rejects requests without a User-Agent. Send an identifying
        # UA so the request is not filtered/blocked at the edge.
        request = urllib.request.Request(
            url,
            headers={"User-Agent": process_user_agent("netattackai-cve-lookup/1.0")},
        )
        try:
            response = urllib.request.urlopen(request, timeout=self.settings.timeout_seconds)
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:800]
            raise RuntimeError(f"NVD HTTP {exc.code}: {body}") from exc
        except Exception as exc:
            raise RuntimeError(f"NVD request failed: {exc}") from exc

        return self._parse(payload)

    def _parse(self, payload: dict[str, Any]) -> list[CVEEntry]:
        entries: list[CVEEntry] = []
        vulnerabilities = payload.get("vulnerabilities") or []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss_score: float | None = None
            severity = ""
            for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if version in metrics and metrics[version]:
                    data = metrics[version][0].get("cvssData", {})
                    if "baseScore" in data:
                        cvss_score = data["baseScore"]
                    if "baseSeverity" in data:
                        severity = data["baseSeverity"]
                    elif version == "cvssMetricV2" and "severity" in metrics[version][0]:
                        severity = metrics[version][0]["severity"]
                    break

            cwe = ""
            weaknesses = cve.get("weaknesses", [])
            if weaknesses:
                desc_list = weaknesses[0].get("description", [])
                for wd in desc_list:
                    if wd.get("lang") == "en":
                        cwe = wd.get("value", "")
                        break

            published = cve.get("published", "")[:10]
            references: list[str] = []
            refs = cve.get("references", [])
            for ref in refs[:3]:
                ref_url = ref.get("url", "")
                if ref_url:
                    references.append(ref_url)

            entries.append(
                CVEEntry(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    cwe=cwe,
                    published=published,
                    references=references,
                )
            )
        return entries


def format_cve_results(entries: list[CVEEntry], query: str) -> str:
    lines = [f"CVE results for: {query}", ""]
    if not entries:
        lines.append("No CVEs found in NVD for this query.")
        return "\n".join(lines)
    for entry in entries:
        lines.append(entry.summary())
        lines.append("")
    return "\n".join(lines)
