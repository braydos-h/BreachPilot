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


class NVDHTTPError(RuntimeError):
    """Raised on an NVD HTTP error response. Carries the status code so callers
    can treat 4xx (intermittent 404 / not-found) as a soft miss that must NOT
    open the circuit breaker, while 5xx/timeout still count as hard failures."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


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
    # Phase 2: EPSS + KEV vuln-intel enrichment (opt-in, default OFF). When
    # off, CVEEntry carries None/False and the NVD output is unchanged.
    epss_enabled: bool = False
    kev_enabled: bool = False
    kev_cache_ttl_seconds: int = 86400  # 24h catalog refresh
    kev_cache_path: str = ""  # "" = exploit_workspace/.kev_catalog.json


@dataclass
class CVEEntry:
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    severity: str = ""  # LOW, MEDIUM, HIGH, CRITICAL
    cwe: str = ""  # e.g. CWE-79
    published: str = ""  # YYYY-MM-DD
    references: list[str] = field(default_factory=list)
    # Phase 2: EPSS exploit-likelihood score (0-1) + percentile (0-1), and
    # CISA KEV (Known Exploited Vulnerability) membership. Populated only
    # when the corresponding CVESearchSettings flag is enabled.
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False

    def summary(self) -> str:
        lines = [f"- {self.cve_id} ({self.severity or 'unknown severity'})"]
        if self.cvss_score is not None:
            lines.append(f"  CVSS: {self.cvss_score}")
        if self.epss is not None:
            lines.append(f"  EPSS: {self.epss:.4f} (percentile {self.epss_percentile:.4f})")
        if self.kev:
            lines.append("  KEV: yes (CISA Known Exploited Vulnerability)")
        if self.cwe:
            lines.append(f"  CWE: {self.cwe}")
        if self.published:
            lines.append(f"  Published: {self.published}")
        if self.description:
            lines.append(f"  Description: {self.description[:300]}")
        if self.references:
            lines.append(f"  References: {', '.join(self.references[:3])}")
        return "\n".join(lines)


class EPSSClient:
    """EPSS (Exploit Prediction Scoring System) enrichment.

    One batched HTTP GET to ``https://api.first.org/data/v1/epss?cve=...`` per
    NVD result set. Pure stdlib (urllib); injectable ``fetch_fn`` for tests.
    Failures degrade to no enrichment (never raise -- vuln intel is advisory).
    """

    def __init__(self, settings: CVESearchSettings) -> None:
        self.settings = settings
        self._cache: dict[str, dict[str, float]] = {}

    def get_batch(self, cve_ids: list[str], *, fetch_fn=None) -> dict[str, dict[str, float]]:
        if not cve_ids:
            return {}
        ids = [c for c in cve_ids if c]
        cached = {c: self._cache[c] for c in ids if c in self._cache}
        missing = [c for c in ids if c not in self._cache]
        if not missing:
            return cached
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(missing[:100])
        try:
            if fetch_fn is None:
                req = urllib.request.Request(url, headers={"User-Agent": process_user_agent("netattackai-epss/1.0")})
                with urllib.request.urlopen(req, timeout=self.settings.timeout_seconds) as resp:
                    payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            else:
                payload = fetch_fn(url)
            for item in (payload or {}).get("data", []) or []:
                cve = item.get("cve", "")
                if cve:
                    try:
                        rec = {"epss": float(item.get("epss", 0.0)), "percentile": float(item.get("percentile", 0.0))}
                        self._cache[cve] = rec
                        cached[cve] = rec
                    except (TypeError, ValueError):
                        continue
        except Exception:
            pass  # advisory only
        return cached


class KEVCatalog:
    """CISA Known Exploited Vulnerabilities catalog with file-cache + TTL.

    Downloads the canonical JSON feed once, caches it to disk (default
    ``exploit_workspace/.kev_catalog.json``) with a 24h TTL, and exposes
    ``is_known_exploited(cve)``. Injectable ``fetch_fn``/``cache_path`` for
    tests. Failures degrade to ``False`` (never raise).
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, settings: CVESearchSettings, *, cache_path: str = "", fetch_fn=None) -> None:
        self.settings = settings
        self._fetch_fn = fetch_fn
        self._path = cache_path or settings.kev_cache_path or os.path.join(
            os.environ.get("EXPLOIT_WORKSPACE", "exploit_workspace"), ".kev_catalog.json"
        )
        self._cves: set[str] | None = None

    def _load(self) -> set[str]:
        if self._cves is not None:
            return self._cves
        cves: set[str] = set()
        data: dict[str, Any] | None = None
        try:
            fresh = True
            if os.path.exists(self._path) and (time.time() - os.path.getmtime(self._path)) < self.settings.kev_cache_ttl_seconds:
                with open(self._path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                fresh = False
            if data is None:
                if self._fetch_fn is not None:
                    data = self._fetch_fn(self.KEV_URL)
                else:
                    req = urllib.request.Request(self.KEV_URL, headers={"User-Agent": process_user_agent("netattackai-kev/1.0")})
                    with urllib.request.urlopen(req, timeout=self.settings.timeout_seconds) as resp:
                        raw = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(raw)
                if fresh and data:
                    try:
                        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
                        with open(self._path, "w", encoding="utf-8") as fh:
                            json.dump(data, fh)
                    except Exception:
                        pass
        except Exception:
            data = None
        for item in (data or {}).get("vulnerabilities", []) or []:
            cve = (item.get("cveID") or "").strip()
            if cve:
                cves.add(cve)
        self._cves = cves
        return self._cves

    def is_known_exploited(self, cve: str) -> bool:
        try:
            return cve in self._load()
        except Exception:
            return False


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
        # Phase 2: EPSS + KEV enrichers. Constructed only when the
        # corresponding flag is on; None otherwise (zero behavior change).
        self._epss = EPSSClient(settings) if settings.epss_enabled else None
        self._kev = KEVCatalog(settings) if settings.kev_enabled else None

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
        except NVDHTTPError as exc:
            if 400 <= exc.code < 500:
                # 4xx (e.g. intermittent NVD 404) is a soft miss -- the API
                # responded, the query just had no match. Do NOT open the
                # circuit breaker over it; a later lookup may still succeed.
                self._breaker.record_success()
            else:
                self._breaker.record_failure()
            raise
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
        except NVDHTTPError as exc:
            if 400 <= exc.code < 500:
                self._breaker.record_success()
            else:
                self._breaker.record_failure()
            raise
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
        """Perform the actual HTTP GET to NVD API (keyword search).

        ponytail: NVD's ``keywordSearch`` matches CVE *descriptions* only,
        not CPE/version data — so ``"OpenSSH 9.6p1"`` misses CVE-2024-6387
        (regreSSHion) because the description never contains ``9.6p1``.
        When a product+version query returns nothing, retry with just the
        product name (``"OpenSSH"``) which matches the description. This
        finds regreSSHion without needing CPE construction.
        """
        try:
            entries = self._fetch_by_params({
                "keywordSearch": query,
                "resultsPerPage": str(self.settings.max_results),
            })
        except NVDHTTPError as exc:
            # 404 on a product+version query is NVD's intermittent no-match
            # edge — fall back to product-only if the query had a version.
            if 400 <= exc.code < 500 and " " in query.strip():
                product_only = query.split(" ", 1)[0]
                return self._fetch_by_params({
                    "keywordSearch": product_only,
                    "resultsPerPage": str(self.settings.max_results),
                })
            raise
        if not entries and " " in query.strip():
            # Zero results for product+version — try product-only.
            product_only = query.split(" ", 1)[0]
            return self._fetch_by_params({
                "keywordSearch": product_only,
                "resultsPerPage": str(self.settings.max_results),
            })
        return entries

    def _fetch_by_params(self, params: dict[str, str]) -> list[CVEEntry]:
        """Shared NVD HTTP GET + parse for an arbitrary params dict."""
        api_key = os.environ.get(self.settings.api_key_env, "").strip()
        if api_key:
            params = dict(params)
            params["apiKey"] = api_key

        # ponytail: NVD doc requires spaces encoded as %20, not '+'. The
        # stdlib urlencode defaults to '+' (via quote_via=quote_plus); pass
        # quote_via=urllib.parse.quote to emit %20. '+' is a contributing
        # cause of intermittent 404s on keywordSearch queries.
        url = NVD_API_BASE + "?" + urllib.parse.urlencode(
            params, quote_via=urllib.parse.quote
        )
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
            raise NVDHTTPError(exc.code, f"NVD HTTP {exc.code}: {body}") from exc
        except Exception as exc:
            raise RuntimeError(f"NVD request failed: {exc}") from exc

        return self._parse(payload)

    # Phase 2: NVD CPE-name search (vuln-intel by product configuration).
    def search_by_cpe_sync(self, cpe: str) -> list[CVEEntry]:
        """Synchronous NVD search by CPE name (cpeName parameter)."""
        if not self.settings.enabled or not cpe:
            return []
        return self._fetch_by_params({
            "cpeName": cpe,
            "resultsPerPage": str(self.settings.max_results),
        })

    async def search_by_cpe(self, cpe: str) -> list[CVEEntry]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.search_by_cpe_sync, cpe)

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
        # Phase 2: EPSS + KEV enrichment (only when the enrichers are
        # present, i.e. the corresponding settings flag is ON). Advisory;
        # failures never raise out of _parse.
        if self._epss is not None and entries:
            try:
                epss = self._epss.get_batch([e.cve_id for e in entries])
                for e in entries:
                    rec = epss.get(e.cve_id)
                    if rec:
                        e.epss = rec["epss"]
                        e.epss_percentile = rec["percentile"]
            except Exception:
                pass
        if self._kev is not None:
            try:
                for e in entries:
                    e.kev = self._kev.is_known_exploited(e.cve_id)
            except Exception:
                pass
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
