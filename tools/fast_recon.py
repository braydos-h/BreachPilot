"""Fast Recon coordinator — dependency-aware parallel reconnaissance preset.

Reuses the existing MCP recon tools (check_os, quick_scan, search_cve_intel,
get_service_fingerprint, run_osint_recon, run_udp_recon) but schedules them
with dependency awareness and bounded concurrency instead of the sequential
``tools/recon_assessment_cli.py`` path.

Flow:
    Stage A (independent, parallel):
        OS probe | TCP discovery | passive OSINT | UDP quick scan
            └─────────────┬──────────────┘
                          ▼
               Discovered services
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
     fingerprint    HTTP/SMB/etc       CVE intel
          └───────────────┼────────────────┘
                          ▼
               Normalize + persist (fast_recon.json + recon_assessment.json)

Key properties:
- One failed task never kills the run (return_exceptions=True).
- CVE queries are deduplicated (product+version) + cached per-run.
- Task keys prevent duplicate ports/URLs/CVEs.
- Global deadline cancels optional work cleanly.
- Short-lived cache (5 min default) avoids rescanning on rapid re-runs.
- Every task is timed; aggregate metrics are emitted.
- Progress events flow through the existing EventSink.

Ponytail: this file is the *only* new recon orchestration. It delegates to
existing MCP tools and ``ReconAssessment`` rather than reimplementing parsing.
# ponytail: global semaphores on the coordinator, not per-caller — prevents
# 8 categories × 5 tools × N ports from becoming hundreds of subprocesses.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.goal_suggester import ReconAssessment, build_assessment_from_mcp_results
from tools.recon.config import HostReconResult, ServiceInfo
from tools.recon_assessment_cli import _cve_query_from_banner, _extract_tool_text
from tools.validation_utils import parse_service_banners

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class FastReconConfig:
    enabled: bool = True
    max_concurrency: int = 8
    service_concurrency: int = 6
    cve_concurrency: int = 8
    per_task_timeout_seconds: int = 60
    overall_timeout_seconds: int = 180
    tcp_discovery: bool = True
    udp_top_ports: int = 50
    passive_osint: bool = True
    service_enumeration: bool = True
    cve_lookup: bool = True
    cache_ttl_seconds: int = 300

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> "FastReconConfig":
        raw = ((config or {}).get("recon") or {}).get("fast") or {}
        if not isinstance(raw, dict):
            raw = {}
        return cls(
            enabled=bool(raw.get("enabled", True)),
            max_concurrency=int(raw.get("max_concurrency", 8) or 8),
            service_concurrency=int(raw.get("service_concurrency", 6) or 6),
            cve_concurrency=int(raw.get("cve_concurrency", 8) or 8),
            per_task_timeout_seconds=int(raw.get("per_task_timeout_seconds", 60) or 60),
            overall_timeout_seconds=int(raw.get("overall_timeout_seconds", 180) or 180),
            tcp_discovery=bool(raw.get("tcp_discovery", True)),
            udp_top_ports=int(raw.get("udp_top_ports", 50) or 50),
            passive_osint=bool(raw.get("passive_osint", True)),
            service_enumeration=bool(raw.get("service_enumeration", True)),
            cve_lookup=bool(raw.get("cve_lookup", True)),
            cache_ttl_seconds=int(raw.get("cache_ttl_seconds", 300) or 300),
        )


# ---------------------------------------------------------------------------
# Result bundle
# ---------------------------------------------------------------------------


@dataclass
class FastReconResult:
    target: str
    recon_complete: bool = False
    recon_mode: str = "fast"
    duration_seconds: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    os: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    web: dict[str, Any] = field(default_factory=dict)
    osint: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    task_timings: dict[str, dict[str, Any]] = field(default_factory=dict)
    cache_hit: bool = False
    assessment: ReconAssessment | None = None
    # compact model-facing summary (not huge raw outputs)
    summary_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "recon_mode": self.recon_mode,
            "recon_complete": self.recon_complete,
            "duration_seconds": self.duration_seconds,
            "open_ports": self.open_ports,
            "udp_ports": self.udp_ports,
            "services": self.services,
            "os": self.os,
            "technologies": self.technologies,
            "cves": self.cves,
            "web": self.web,
            "osint": self.osint,
            "warnings": self.warnings,
            "errors": self.errors,
            "coverage": self.coverage,
            "task_timings": self.task_timings,
            "cache_hit": self.cache_hit,
            "summary_text": self.summary_text,
        }

    def to_assessment(self) -> ReconAssessment | None:
        return self.assessment

    def to_host_recon_result(self) -> HostReconResult:
        """Bridge to the canonical recon type for downstream consumers.

        The coordinator schedules MCP tools and keeps a compact dict-shaped
        bundle; this converts it to ``tools.recon.config.HostReconResult``
        (``ServiceInfo`` entries) so attack modules reuse one type instead of
        a second parallel schema.
        """
        result = HostReconResult(
            target_ip=self.target,
            open_ports=list(self.open_ports),
            udp_ports=list(self.udp_ports),
            scan_tool="fast-recon",
            scan_duration=self.duration_seconds,
            warnings=list(self.warnings),
            errors=list(self.errors),
        )
        for svc in self.services:
            try:
                port = int(svc.get("port", 0) or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            result.services.append(
                ServiceInfo(
                    port=port,
                    protocol=str(svc.get("protocol", "tcp") or "tcp"),
                    service=str(svc.get("service", "unknown") or "unknown"),
                    banner=str(svc.get("banner", "") or ""),
                )
            )
        return result


# ---------------------------------------------------------------------------
# Helpers (thin shims over canonical parsers -- no local regex dialects)
# ---------------------------------------------------------------------------

# ponytail: _cve_query_from_banner + _extract_tool_text live in
# tools.recon_assessment_cli (imported above) -- this module used to carry
# byte-identical copies. _parse_scan_ports delegates to the canonical
# validation_utils.parse_service_banners for the same reason.


def _parse_os_result(text: str) -> dict[str, Any]:
    verdict = "UNKNOWN"
    m = re.search(r"OS_VERDICT:\s*(\S+)", text)
    if m:
        verdict = m.group(1).strip()
    hints: list[str] = []
    hm = re.search(r"HINTS:\s*(.+)$", text, re.MULTILINE)
    if hm:
        hints = [h.strip() for h in hm.group(1).split(";") if h.strip()]
    return {"verdict": verdict, "hints": hints, "raw": text[:2000]}


def _parse_scan_ports(text: str) -> tuple[list[int], list[dict[str, Any]]]:
    """Parse quick_scan text via the canonical banner parser (no local regex)."""
    open_ports: list[int] = []
    services: list[dict[str, Any]] = []
    for rec in parse_service_banners(text or ""):
        open_ports.append(rec["port"])
        services.append(
            {"port": rec["port"], "protocol": rec["protocol"], "service": rec["service"], "banner": rec["raw_banner"]}
        )
    return open_ports, services


def _build_compact_summary(result: FastReconResult, scan_raw: str, os_raw: str) -> str:
    lines: list[str] = []
    lines.append(f"Target: {result.target}")
    os_v = result.os.get("verdict", "UNKNOWN")
    lines.append(f"OS: {os_v}")
    lines.append(f"Open TCP: {', '.join(str(p) for p in result.open_ports) if result.open_ports else '(none)'}")
    if result.udp_ports:
        lines.append(f"Open UDP: {', '.join(str(p) for p in result.udp_ports)}")
    for svc in result.services[:8]:
        banner = svc.get("banner", "")
        # keep banner short
        if len(banner) > 80:
            banner = banner[:77] + "..."
        lines.append(f"{svc.get('port')}: {svc.get('service', 'unknown')} {banner}")
    if result.technologies:
        lines.append(f"Likely technologies: {', '.join(result.technologies[:6])}")
    if result.cves:
        lines.append(f"Relevant CVE candidates: {len(result.cves)} service(s) with CVEs")
        for c in result.cves[:3]:
            lines.append(f"  - {c.get('product')} {c.get('version')} (port {c.get('port')})")
    if result.web.get("paths"):
        lines.append(f"HTTP paths discovered: {len(result.web['paths'])}")
    if result.warnings:
        lines.append(f"Warnings: {'; '.join(result.warnings[:3])}")
    lines.append(f"Recon completed in {result.duration_seconds:.1f}s")
    # do NOT dump raw scanner output (token bloat)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


def _cache_key(target: str, config: FastReconConfig) -> str:
    # normalized target + preset/version + relevant recon config
    payload = json.dumps({"target": target.strip().lower(), "fast": config.__dict__}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _cache_path(reports_dir: Path, target: str, config: FastReconConfig) -> Path:
    # global cache under exploit_workspace/.fast_recon_cache (not per-run)
    # also mirrored per-run for resume reuse
    key = _cache_key(target, config)
    return Path("exploit_workspace") / ".fast_recon_cache" / f"{key}.json"


def _try_load_cache(target: str, config: FastReconConfig, reports_dir: Path) -> FastReconResult | None:
    if config.cache_ttl_seconds <= 0:
        return None
    cpath = _cache_path(reports_dir, target, config)
    if not cpath.exists():
        return None
    try:
        age = time.time() - cpath.stat().st_mtime
        if age > config.cache_ttl_seconds:
            return None
        data = json.loads(cpath.read_text(encoding="utf-8"))
        # rebuild minimal result (assessment from dict)
        ra = ReconAssessment.from_dict(data.get("assessment", {})) if data.get("assessment") else None
        res = FastReconResult(
            target=target,
            recon_complete=True,
            duration_seconds=float(data.get("duration_seconds", 0)),
            open_ports=list(data.get("open_ports", [])),
            udp_ports=list(data.get("udp_ports", [])),
            services=list(data.get("services", [])),
            os=dict(data.get("os", {})),
            cves=list(data.get("cves", [])),
            osint=dict(data.get("osint", {})),
            warnings=list(data.get("warnings", [])),
            errors=list(data.get("errors", [])),
            task_timings=dict(data.get("task_timings", {})),
            cache_hit=True,
            assessment=ra,
            summary_text=str(data.get("summary_text", "")),
        )
        res.coverage = dict(data.get("coverage", {}))
        res.web = dict(data.get("web", {}))
        res.technologies = list(data.get("technologies", []))
        return res
    except Exception:
        return None


def _save_cache(result: FastReconResult, config: FastReconConfig, reports_dir: Path) -> None:
    if config.cache_ttl_seconds <= 0:
        return
    try:
        cpath = _cache_path(reports_dir, result.target, config)
        cpath.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": result.target,
            "assessment": result.assessment.to_dict() if result.assessment else {},
            "open_ports": result.open_ports,
            "udp_ports": result.udp_ports,
            "services": result.services,
            "os": result.os,
            "cves": result.cves,
            "osint": result.osint,
            "warnings": result.warnings,
            "errors": result.errors,
            "task_timings": result.task_timings,
            "coverage": result.coverage,
            "web": result.web,
            "technologies": result.technologies,
            "summary_text": result.summary_text,
            "duration_seconds": result.duration_seconds,
        }
        cpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


class FastReconCoordinator:
    """Dependency-aware parallel recon preset."""

    def __init__(
        self,
        config: FastReconConfig | dict[str, Any] | None = None,
        *,
        reports_dir: Path | None = None,
        event_sink: Any | None = None,
        cancellation: Any | None = None,
    ) -> None:
        if isinstance(config, FastReconConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = FastReconConfig.from_config(config)
        else:
            self.config = FastReconConfig()
        self.reports_dir = reports_dir or Path("reports")
        self.event_sink = event_sink
        self.cancellation = cancellation
        # bounded concurrency
        self._global_sem = asyncio.Semaphore(self.config.max_concurrency)
        self._svc_sem = asyncio.Semaphore(self.config.service_concurrency)
        self._cve_sem = asyncio.Semaphore(self.config.cve_concurrency)
        self._cve_cache: dict[str, str] = {}
        self._seen_keys: set[str] = set()
        self._timings: dict[str, dict[str, Any]] = {}
        self._start_monotonic = 0.0

    async def _emit(self, type_: str, payload: dict[str, Any]) -> None:
        if self.event_sink is None:
            return
        try:
            await self.event_sink.emit(type_, payload)
        except Exception:
            pass

    def _record_timing(self, task: str, started: float, status: str, result_count: int = 0) -> None:
        dur_ms = int((time.monotonic() - started) * 1000)
        self._timings[task] = {
            "task": task,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": dur_ms,
            "status": status,
            "result_count": result_count,
        }

    async def _call_with_timeout(self, session: Any, tool: str, args: dict[str, Any], task_key: str) -> str | None:
        # dedup
        if task_key in self._seen_keys:
            return None
        self._seen_keys.add(task_key)
        started = time.monotonic()
        await self._emit("fast_recon_task_started", {"task": task_key, "label": tool, "status": "running"})
        try:
            async with self._global_sem:
                if self.cancellation and getattr(self.cancellation, "cancelled", False):
                    raise asyncio.CancelledError()
                raw = await asyncio.wait_for(
                    session.call_tool(tool, args), timeout=self.config.per_task_timeout_seconds
                )
                text = _extract_tool_text(raw)
                self._record_timing(task_key, started, "completed", len(text))
                await self._emit(
                    "fast_recon_task_completed",
                    {
                        "task": task_key,
                        "label": tool,
                        "status": "completed",
                        "duration_ms": self._timings[task_key]["duration_ms"],
                    },
                )
                return text
        except asyncio.TimeoutError:
            self._record_timing(task_key, started, "timeout")
            await self._emit(
                "fast_recon_task_failed",
                {
                    "task": task_key,
                    "label": tool,
                    "status": "timeout",
                    "duration_ms": self._timings[task_key]["duration_ms"],
                },
            )
            return None
        except asyncio.CancelledError:
            self._record_timing(task_key, started, "cancelled")
            await self._emit("fast_recon_task_failed", {"task": task_key, "label": tool, "status": "cancelled"})
            return None
        except _EXC_GROUP_CATCH as exc:
            self._record_timing(task_key, started, "failed")
            await self._emit(
                "fast_recon_task_failed", {"task": task_key, "label": tool, "status": "failed", "error": str(exc)[:300]}
            )
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            return None
        except Exception as exc:
            self._record_timing(task_key, started, "failed")
            await self._emit(
                "fast_recon_task_failed", {"task": task_key, "label": tool, "status": "failed", "error": str(exc)[:300]}
            )
            return None

    async def run(self, session: Any, target_ip: str) -> FastReconResult:
        overall_start = time.monotonic()
        self._start_monotonic = overall_start
        await self._emit("fast_recon_started", {"target": target_ip, "config": self.config.__dict__})

        # ---- cache check ----
        cached = _try_load_cache(target_ip, self.config, self.reports_dir)
        if cached is not None:
            # emit cache hit progress
            await self._emit(
                "fast_recon_completed",
                {
                    "target": target_ip,
                    "cache_hit": True,
                    "duration_seconds": cached.duration_seconds,
                    "open_ports": cached.open_ports,
                },
            )
            # also persist per-run copy for resume
            try:
                out = self.reports_dir / "fast_recon.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(cached.to_dict(), indent=2), encoding="utf-8")
                if cached.assessment:
                    (self.reports_dir / "recon_assessment.json").write_text(
                        json.dumps(cached.assessment.to_dict(), indent=2), encoding="utf-8"
                    )
            except Exception:
                pass
            return cached

        # Use asyncio timeout for overall deadline
        try:
            result = await asyncio.wait_for(
                self._run_inner(session, target_ip, overall_start),
                timeout=self.config.overall_timeout_seconds,
            )
        except asyncio.TimeoutError:
            # deadline exceeded: return partial result with timeout marker
            elapsed = time.monotonic() - overall_start
            # Build partial from what we have (best-effort)
            result = FastReconResult(target=target_ip, duration_seconds=elapsed)
            result.warnings.append(
                f"Fast recon overall timeout after {self.config.overall_timeout_seconds}s — partial results"
            )
            result.coverage = {"timed_out": True, "overall_timeout_seconds": self.config.overall_timeout_seconds}
            result.task_timings = dict(self._timings)
            result.summary_text = f"Target: {target_ip}\nRecon timed out after {elapsed:.1f}s (partial)"
            await self._emit(
                "fast_recon_completed",
                {"target": target_ip, "timed_out": True, "duration_seconds": elapsed, "warnings": result.warnings},
            )
        return result

    async def _run_inner(self, session: Any, target_ip: str, overall_start: float) -> FastReconResult:
        result = FastReconResult(target=target_ip)
        warnings: list[str] = []
        errors: list[str] = []
        os_text = ""
        scan_text = ""
        osint_text = ""
        udp_text = ""

        # ------------------------------------------------------------------
        # Stage A — independent discovery (parallel)
        # ------------------------------------------------------------------
        async def os_task():
            return await self._call_with_timeout(
                session,
                "check_os",
                {"target_ip": target_ip},
                f"osint:{target_ip}" if False else f"os-probe:{target_ip}",
            )

        async def tcp_task():
            if not self.config.tcp_discovery:
                return None
            return await self._call_with_timeout(
                session,
                "quick_scan",
                {
                    "target_ip": target_ip,
                    "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,27017,6379",
                },
                f"tcp-discovery:{target_ip}",
            )

        async def osint_task():
            if not self.config.passive_osint:
                return None
            return await self._call_with_timeout(
                session, "run_osint_recon", {"target_ip": target_ip}, f"osint:{target_ip}"
            )

        async def udp_task():
            if self.config.udp_top_ports <= 0:
                return None
            return await self._call_with_timeout(
                session,
                "run_udp_recon",
                {"target_ip": target_ip, "top_ports": self.config.udp_top_ports},
                f"udp-discovery:{target_ip}",
            )

        # fire Stage A concurrently
        stage_a = await asyncio.gather(os_task(), tcp_task(), osint_task(), udp_task(), return_exceptions=True)

        # unpack with resilience
        def _unpack(v: Any) -> str | None:
            if isinstance(v, Exception):
                warnings.append(str(v)[:300])
                return None
            return v

        os_text = (
            _unpack(stage_a[0]) or f"OS_CHECK_RESULTS:\nTARGET: {target_ip}\nOS_VERDICT: UNKNOWN\nHINTS: unavailable"
        )
        scan_text = (
            _unpack(stage_a[1]) or f"QUICK_SCAN_RESULTS: {target_ip}\nSUMMARY: 0/0 ports open\nNOTE: scan unavailable"
        )
        osint_text = _unpack(stage_a[2]) or ""
        udp_text = _unpack(stage_a[3]) or ""

        # parse scan results
        open_ports, services = _parse_scan_ports(scan_text)
        udp_ports: list[int] = []
        # parse udp ports from udp_text if present
        if udp_text:
            m = re.search(r"UDP_PORTS:\s*\[([^\]]*)\]", udp_text)
            if m:
                try:
                    # extract ints
                    nums = re.findall(r"\d+", m.group(1))
                    udp_ports = [int(n) for n in nums]
                except Exception:
                    pass
            # also try "UDP_PORTS: [1, 2, 3]" lines
            if not udp_ports:
                for line in udp_text.splitlines():
                    if "UDP_PORTS:" in line and "[" in line:
                        nums = re.findall(r"\d+", line)
                        udp_ports = [int(n) for n in nums]
                        break
        os_info = _parse_os_result(os_text)
        result.os = os_info
        result.open_ports = open_ports
        result.udp_ports = udp_ports
        result.services = services
        # osint parsing (best-effort)
        if osint_text:
            result.osint = {"raw": osint_text[:4000]}
            # extract ipv6 if present
            m = re.search(r"IPV6_ADDRESSES:\s*(\[.*?\]|\S+)", osint_text)
            if m:
                result.osint["ipv6_hint"] = m.group(1)[:200]

        # ------------------------------------------------------------------
        # Short-circuit empty targets (no attack surface)
        # ------------------------------------------------------------------
        if not open_ports:
            warnings.append("No open TCP ports discovered — skipping enrichment")
            result.warnings = warnings
            result.errors = errors
            # need assessment even for empty
            assessment = build_assessment_from_mcp_results(target_ip, os_text, scan_text, [])
            result.assessment = assessment
            result.recon_complete = True
            result.duration_seconds = time.monotonic() - overall_start
            result.task_timings = dict(self._timings)
            result.coverage = {"tier0": "complete", "tier1": "skipped_no_surface", "tier2": "skipped"}
            result.summary_text = _build_compact_summary(result, scan_text, os_text)
            result.warnings = warnings
            # persist + cache
            await self._finalize(result, os_text, scan_text, overall_start)
            return result

        # ------------------------------------------------------------------
        # Stage B — dependent enumeration (fingerprint + CVE)
        # ------------------------------------------------------------------
        # Tier 0/1 required; Tier 2 expensive optional is omitted by default.
        # Fingerprint each open port with bounded concurrency.

        # Two-stage port discovery: discovered ports -> targeted service detection.
        # We already have banners from quick_scan; fingerprint enriches with TLS/cert etc.
        fingerprints: dict[int, str] = {}

        async def fp_one(port: int, svc_name: str):
            key = f"service-fingerprint:{target_ip}:{port}"
            # dedup key already handled in _call_with_timeout, but also check locally
            async with self._svc_sem:
                text = await self._call_with_timeout(
                    session, "get_service_fingerprint", {"target_ip": target_ip, "port": port}, key
                )
                if text:
                    fingerprints[port] = text

        if self.config.service_enumeration:
            # launch fingerprint tasks with global limiter (already inside _call)
            await asyncio.gather(
                *(fp_one(svc["port"], svc["service"]) for svc in services),
                return_exceptions=True,
            )
            # merge fingerprint banners into services (extract banner lines)
            for svc in services:
                fp = fingerprints.get(svc["port"])
                if fp:
                    # extract BANNER line
                    m = re.search(r"BANNER:\s*(.+)", fp)
                    if m and m.group(1).strip() and m.group(1).strip() != "(no banner)":
                        # prefer longer banner
                        if len(m.group(1).strip()) > len(svc.get("banner", "")):
                            svc["banner"] = m.group(1).strip()[:400]
                    # technologies from TLS etc could be extracted
                    if "SSL/TLS INFO" in fp:
                        svc["tls"] = True

        # ------------------------------------------------------------------
        # CVE correlation — bounded, deduped, cached per-run
        # ------------------------------------------------------------------
        cve_results: list[dict[str, Any]] = []
        if self.config.cve_lookup:
            # deduplicate product+version
            dedup: dict[str, tuple[str, str, str, str]] = {}  # query -> (port, proto, service, product, version)
            for svc in services:
                banner = svc.get("banner", "")
                if banner.strip() == "(no banner)":
                    banner = ""
                qv = _cve_query_from_banner(banner)
                if qv is None:
                    continue
                product, version = qv
                query = f"{product} {version}"
                if query not in dedup:
                    dedup[query] = (svc["port"], svc["protocol"], svc["service"], product, version)

            async def cve_one(query: str, meta: tuple[str, str, str, str, str]):
                port, proto, service, product, version = meta
                ckey = f"cve:{product}:{version}"
                if ckey in self._seen_keys and ckey in self._cve_cache:
                    # already fetched this run
                    cached_text = self._cve_cache[ckey]
                    return {
                        "service": service,
                        "product": product,
                        "version": version,
                        "port": str(port),
                        "results": cached_text,
                    }
                async with self._cve_sem:
                    # per-tool dedup already; check cache
                    if ckey in self._cve_cache:
                        return {
                            "service": service,
                            "product": product,
                            "version": version,
                            "port": str(port),
                            "results": self._cve_cache[ckey],
                        }
                    text = await self._call_with_timeout(session, "search_cve_intel", {"query": query}, ckey)
                    if text is None:
                        text = "NO_CVE_RESULTS: timeout or error"
                    self._cve_cache[ckey] = text[:4000]
                    return {
                        "service": service,
                        "product": product,
                        "version": version,
                        "port": str(port),
                        "results": text[:4000],
                    }

            # Build tasks; semaphore bounds concurrency inside cve_one
            if dedup:
                await self._emit(
                    "fast_recon_progress",
                    {"task": "cve_lookup", "completed": 0, "total": len(dedup), "status": "running"},
                )
                coros = [cve_one(q, meta) for q, meta in dedup.items()]
                cve_outs = await asyncio.gather(*coros, return_exceptions=True)
                for item in cve_outs:
                    if isinstance(item, Exception):
                        warnings.append(f"CVE lookup failed: {item}")
                        continue
                    if isinstance(item, dict):
                        cve_results.append(item)
                await self._emit(
                    "fast_recon_progress",
                    {"task": "cve_lookup", "completed": len(cve_results), "total": len(dedup), "status": "completed"},
                )

        result.cves = cve_results

        # ------------------------------------------------------------------
        # Build assessment + summary
        # ------------------------------------------------------------------
        assessment = build_assessment_from_mcp_results(
            target_ip=target_ip,
            os_result=os_text,
            scan_result=scan_text,
            cve_results=cve_results,
        )
        result.assessment = assessment
        result.warnings = warnings
        result.errors = errors
        result.recon_complete = True
        result.duration_seconds = time.monotonic() - overall_start
        result.task_timings = dict(self._timings)
        # coverage tiers
        result.coverage = {
            "tier0": "complete",  # target resolution, port discovery, OS signals
            "tier1": "complete" if (self.config.service_enumeration and self.config.cve_lookup) else "partial",
            "tier2": "skipped",  # expensive optional enrichment not run by default
            "udp_top_ports": self.config.udp_top_ports,
            "service_enumeration": self.config.service_enumeration,
            "cve_lookup": self.config.cve_lookup,
        }
        # web placeholder (could be filled from fingerprint http headers)
        # collect technologies from cves? keep simple
        result.summary_text = _build_compact_summary(result, scan_text, os_text)

        await self._finalize(result, os_text, scan_text, overall_start)
        return result

    async def _finalize(self, result: FastReconResult, os_text: str, scan_text: str, overall_start: float) -> None:
        elapsed = time.monotonic() - overall_start
        result.duration_seconds = elapsed
        # persist fast_recon.json
        try:
            out = self.reports_dir / "fast_recon.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        except Exception:
            pass
        # keep existing recon_assessment.json for consumers
        try:
            if result.assessment:
                (self.reports_dir / "recon_assessment.json").write_text(
                    json.dumps(result.assessment.to_dict(), indent=2), encoding="utf-8"
                )
        except Exception:
            pass
        # cache
        _save_cache(result, self.config, self.reports_dir)
        # emit completion
        await self._emit(
            "fast_recon_completed",
            {
                "target": result.target,
                "duration_seconds": elapsed,
                "open_ports": result.open_ports,
                "udp_ports": result.udp_ports,
                "services": len(result.services),
                "cves": len(result.cves),
                "cache_hit": result.cache_hit,
                "task_timings": result.task_timings,
                "coverage": result.coverage,
            },
        )
        # emit recon_assessment for legacy consumers
        await self._emit("recon_assessment", {"assessment": result.assessment.to_dict() if result.assessment else {}})
        # emit progress summary log
        try:
            from tools.attack_ui import get_ui

            ui = get_ui()
            ui.info(
                f"Fast Recon completed in {elapsed:.1f}s: {len(result.open_ports)} ports, {len(result.services)} services, {len(result.cves)} CVE lookups"
            )
            # timing breakdown
            for task, t in result.task_timings.items():
                ui.info(f"  {task}: {t.get('duration_ms', 0) / 1000:.1f}s ({t.get('status')})")
        except Exception:
            pass
