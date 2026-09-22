"""Unified recon service — single entry point for the full + fast recon paths.

Before this module, recon lived in two parallel orchestrations:

- **Full** (``tools/recon/pipeline.py`` ``ReconPipeline``): direct-subprocess
  Nmap/RustScan/Masscan primary scan + ``SecondaryEnumerator`` deep
  enumeration (HTTP/SSH/SMB/LDAP/FTP/Redis/ES/Docker/RDP + opt-in TLS/SMTP/
  DB/spider/OSINT + extended depth enumerators). Used by MCP
  ``run_full_recon`` / ``run_udp_recon``, the swarm recon agent, and legacy.
- **Fast / budget-limited** (``tools/fast_recon.py`` ``FastReconCoordinator``):
  dependency-aware parallel preset over the MCP session tools (``check_os``,
  ``quick_scan``, ``get_service_fingerprint``, ``search_cve_intel``,
  ``run_osint_recon``, ``run_udp_recon``) with bounded concurrency, global
  deadline, dedup, and a short-lived disk cache. Used by run-service fast
  mode.
- **Sequential assessment** (``tools/recon_assessment_cli.py``
  ``run_recon_assessment``): the original sequential OS → scan → CVE path
  over the MCP session. Used by ``main.py`` / run-service recon-first.

``ReconService`` unifies them behind **profiles** (``full`` vs ``fast``,
plus ``assessment`` for the legacy sequential MCP path) while sharing:

- CVE/EPSS/KEV enrichment: banner → product/version query planning
  (``plan_cve_queries`` / ``cve_query_from_banner``) plus the per-run
  ``CveEnrichmentCache``. The actual CVE/EPSS/KEV lookup still executes
  inside ``NVDClient`` behind the MCP ``search_cve_intel`` tool (advisory
  only, never touches the target), so EPSS/KEV flags in
  ``cve_lookup.*`` config keep working unchanged for both paths.
- Fast-result disk caching (``fast_cache_key`` / ``try_load_fast_cache`` /
  ``save_fast_cache``) and scan-text parsing helpers.

``tools/fast_recon.py`` and ``tools/recon_assessment_cli.py`` are thin
wrappers re-exporting this module; their public signatures are unchanged.

Safety: this module adds NO new network paths and NO host-subprocess
execution of agent commands. Target-touching goes through either the
existing ``ReconPipeline`` (invoked by already-gated callers) or the
MCP session tools (gated by ``require_allowlist`` at the MCP layer).
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
from typing import Any, Literal

from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.goal_suggester import ReconAssessment, build_assessment_from_mcp_results
from tools.logging_setup import get_logger
from tools.recon.config import HostReconResult, ReconConfig, ServiceInfo
from tools.validation_utils import parse_service_banners

logger = get_logger()

ReconProfile = Literal["full", "fast", "assessment"]

PROFILES: tuple[str, str, str] = ("full", "fast", "assessment")

#: Port list shared by the fast preset and the sequential assessment path
#: (previously hardcoded twice, byte-identical).
DEFAULT_FAST_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,27017,6379"
)

__all__ = [
    "DEFAULT_FAST_PORTS",
    "PROFILES",
    "CveEnrichmentCache",
    "FastReconConfig",
    "FastReconCoordinator",
    "FastReconResult",
    "ReconProfile",
    "ReconService",
    "build_compact_summary",
    "cve_query_from_banner",
    "extract_tool_text",
    "fast_cache_key",
    "fast_cache_path",
    "parse_os_result",
    "parse_scan_ports",
    "plan_cve_queries",
    "run_sequential_assessment",
    "save_fast_cache",
    "try_load_fast_cache",
]


# ---------------------------------------------------------------------------
# Shared parsing helpers (canonical home — wrappers re-export these)
# ---------------------------------------------------------------------------

_GENERIC_SERVICE_NAMES = frozenset(
    {
        "dns",
        "ftp",
        "http",
        "https",
        "imap",
        "pop3",
        "smtp",
        "ssh",
        "telnet",
    }
)


def cve_query_from_banner(banner: str) -> tuple[str, str] | None:
    """Return a product/version pair suitable for a CVE search.

    A port/service name is not proof of a particular implementation or version.
    In particular, querying NVD for just ``ssh`` returns broad historical results
    that are not attributable to the host. Only search when the banner identifies
    a concrete product and version.
    """
    if not banner:
        return None

    # SSH banners commonly start with a protocol identifier (``SSH-2.0-``).
    # Match OpenSSH first so we do not mistake the protocol version for the
    # server version.
    openssh_match = re.search(
        r"\b(?P<product>OpenSSH)[_\s/-]*v?(?P<version>\d+(?:\.\d+)+(?:p\d+)?)",
        banner,
        re.IGNORECASE,
    )
    if openssh_match:
        return "OpenSSH", openssh_match.group("version")

    for match in re.finditer(
        r"\b(?P<product>[A-Za-z][A-Za-z0-9_.+-]*)[\s/_-]+v?"
        r"(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._+-]*)?)",
        banner,
    ):
        product = match.group("product")
        if product.lower() not in _GENERIC_SERVICE_NAMES:
            return product, match.group("version")
    return None


def extract_tool_text(raw: Any) -> str:
    """Extract text content from an MCP tool call result."""
    if isinstance(raw, str):
        return raw
    if hasattr(raw, "content"):
        content = raw.content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        if isinstance(content, str):
            return content
    return str(raw)


def parse_os_result(text: str) -> dict[str, Any]:
    """Parse ``check_os`` output into ``{verdict, hints, raw}``."""
    verdict = "UNKNOWN"
    m = re.search(r"OS_VERDICT:\s*(\S+)", text)
    if m:
        verdict = m.group(1).strip()
    hints: list[str] = []
    hm = re.search(r"HINTS:\s*(.+)$", text, re.MULTILINE)
    if hm:
        hints = [h.strip() for h in hm.group(1).split(";") if h.strip()]
    return {"verdict": verdict, "hints": hints, "raw": text[:2000]}


def parse_scan_ports(text: str) -> tuple[list[int], list[dict[str, Any]]]:
    """Parse quick_scan text via the canonical banner parser (no local regex)."""
    open_ports: list[int] = []
    services: list[dict[str, Any]] = []
    for rec in parse_service_banners(text or ""):
        open_ports.append(rec["port"])
        services.append(
            {"port": rec["port"], "protocol": rec["protocol"], "service": rec["service"], "banner": rec["raw_banner"]}
        )
    return open_ports, services


def build_compact_summary(result: FastReconResult, scan_raw: str, os_raw: str) -> str:
    """Compact model-facing summary (not huge raw outputs)."""
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
# Shared CVE enrichment: query planning + per-run cache
# ---------------------------------------------------------------------------


def plan_cve_queries(services: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Plan deduplicated CVE queries for a list of service dicts.

    Each service dict carries ``port``/``protocol``/``service``/``banner``.
    Returns an ordered ``query -> meta`` map (first-seen port wins) so the
    fast (parallel) and sequential paths issue the same minimal query set.
    Banners that do not identify a concrete product+version (empty,
    ``(no banner)``, generic service names) are skipped.
    """
    planned: dict[str, dict[str, str]] = {}
    for svc in services:
        banner = str(svc.get("banner", "") or "")
        if banner.strip() == "(no banner)":
            banner = ""
        qv = cve_query_from_banner(banner)
        if qv is None:
            continue
        product, version = qv
        query = f"{product} {version}"
        if query not in planned:
            planned[query] = {
                "port": str(svc.get("port", "")),
                "protocol": str(svc.get("protocol", "tcp") or "tcp"),
                "service": str(svc.get("service", "unknown") or "unknown"),
                "product": product,
                "version": version,
            }
    return planned


class CveEnrichmentCache:
    """Per-run in-memory CVE text cache shared by the fast + sequential paths.

    Dict-like (``in`` / ``[]``) so call sites stay terse. Optional
    ``ttl_seconds`` expiry (0 = no expiry, the per-run default).
    """

    def __init__(self, ttl_seconds: float = 0) -> None:
        self._store: dict[str, tuple[float, str]] = {}
        self._ttl = max(0.0, float(ttl_seconds or 0))

    def __contains__(self, query: object) -> bool:
        if not isinstance(query, str) or query not in self._store:
            return False
        if self._ttl > 0 and (time.monotonic() - self._store[query][0]) > self._ttl:
            del self._store[query]
            return False
        return True

    def __getitem__(self, query: str) -> str:
        return self._store[query][1]

    def __setitem__(self, query: str, text: str) -> None:
        self._store[query] = (time.monotonic(), text[:4000])

    def __len__(self) -> int:
        return len(self._store)

    def clear(self) -> None:
        self._store.clear()


# ---------------------------------------------------------------------------
# Fast preset config + result bundle
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
# Fast-result disk cache (shared — previously fast_recon-private)
# ---------------------------------------------------------------------------


def fast_cache_key(target: str, config: FastReconConfig) -> str:
    # normalized target + preset/version + relevant recon config
    payload = json.dumps({"target": target.strip().lower(), "fast": config.__dict__}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def fast_cache_path(reports_dir: Path, target: str, config: FastReconConfig) -> Path:
    # global cache under exploit_workspace/.fast_recon_cache (not per-run)
    # also mirrored per-run for resume reuse
    key = fast_cache_key(target, config)
    return Path("exploit_workspace") / ".fast_recon_cache" / f"{key}.json"


def try_load_fast_cache(target: str, config: FastReconConfig, reports_dir: Path) -> FastReconResult | None:
    if config.cache_ttl_seconds <= 0:
        return None
    cpath = fast_cache_path(reports_dir, target, config)
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


def save_fast_cache(result: FastReconResult, config: FastReconConfig, reports_dir: Path) -> None:
    if config.cache_ttl_seconds <= 0:
        return
    try:
        cpath = fast_cache_path(reports_dir, result.target, config)
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
# Fast coordinator (dependency-aware parallel preset)
# ---------------------------------------------------------------------------


class FastReconCoordinator:
    """Dependency-aware parallel recon preset (the ``fast`` profile)."""

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
        # shared per-run CVE text cache (see CveEnrichmentCache)
        self._cve_cache = CveEnrichmentCache()
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
                text = extract_tool_text(raw)
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
        cached = try_load_fast_cache(target_ip, self.config, self.reports_dir)
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
                f"os-probe:{target_ip}",
            )

        async def tcp_task():
            if not self.config.tcp_discovery:
                return None
            return await self._call_with_timeout(
                session,
                "quick_scan",
                {
                    "target_ip": target_ip,
                    "ports": DEFAULT_FAST_PORTS,
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
        open_ports, services = parse_scan_ports(scan_text)
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
        os_info = parse_os_result(os_text)
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
            result.summary_text = build_compact_summary(result, scan_text, os_text)
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
        # CVE correlation — bounded, deduplicated, cached per-run (shared
        # planner + shared cache with the sequential assessment path)
        # ------------------------------------------------------------------
        cve_results: list[dict[str, Any]] = []
        if self.config.cve_lookup:
            planned = plan_cve_queries(services)

            async def cve_one(query: str, meta: dict[str, str]):
                port, service, product, version = meta["port"], meta["service"], meta["product"], meta["version"]
                ckey = f"cve:{product}:{version}"
                if ckey in self._cve_cache:
                    return {
                        "service": service,
                        "product": product,
                        "version": version,
                        "port": port,
                        "results": self._cve_cache[ckey],
                    }
                async with self._cve_sem:
                    # per-tool dedup already; check cache
                    if ckey in self._cve_cache:
                        return {
                            "service": service,
                            "product": product,
                            "version": version,
                            "port": port,
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
                        "port": port,
                        "results": text[:4000],
                    }

            # Build tasks; semaphore bounds concurrency inside cve_one
            if planned:
                await self._emit(
                    "fast_recon_progress",
                    {"task": "cve_lookup", "completed": 0, "total": len(planned), "status": "running"},
                )
                coros = [cve_one(q, meta) for q, meta in planned.items()]
                cve_outs = await asyncio.gather(*coros, return_exceptions=True)
                for item in cve_outs:
                    if isinstance(item, Exception):
                        warnings.append(f"CVE lookup failed: {item}")
                        continue
                    if isinstance(item, dict):
                        cve_results.append(item)
                await self._emit(
                    "fast_recon_progress",
                    {"task": "cve_lookup", "completed": len(cve_results), "total": len(planned), "status": "completed"},
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
        result.summary_text = build_compact_summary(result, scan_text, os_text)

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
        save_fast_cache(result, self.config, self.reports_dir)
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


# ---------------------------------------------------------------------------
# Sequential assessment path (the ``assessment`` profile)
# ---------------------------------------------------------------------------


async def run_sequential_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
    ui: Any | None = None,
    ctx: Any | None = None,
) -> ReconAssessment:
    """Run quick recon against target and build a structured assessment.

    Sequential OS → scan → CVE path over the MCP session tools. CVE query
    planning uses the shared ``plan_cve_queries`` (same dedup/minimal query
    set as the fast profile); the actual ``search_cve_intel`` calls stay
    serial to preserve the legacy one-spinner-per-query UX.
    """
    if ctx is not None:
        _ui = ctx.ui
    elif ui is not None:
        _ui = ui
    else:
        from tools.attack_ui import AttackUi

        _ui = AttackUi(plain=False)
    _ui.status("Running reconnaissance assessment...")
    _ui.divider()

    # ── Step 1: OS detection ──
    with _ui.spinner("Probing OS via TTL and port analysis...", soft_fail=True):
        try:
            os_raw = await session.call_tool("check_os", {"target_ip": target_ip})
            os_result = extract_tool_text(os_raw)
        except _EXC_GROUP_CATCH as exc:
            # ``BaseExceptionGroup`` is *not* an ``Exception`` subclass — must be
            # listed explicitly or the spinner exits with a confusing [ERROR] line
            # and the user sees no underlying cause.
            _ui.warning(f"OS detection failed: {exc}")
            os_result = f"OS_CHECK_RESULTS:\nTARGET: {target_ip}\nOS_VERDICT: UNKNOWN\nHINTS: Error: {exc}"
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    _ui.result("OS Detection", os_result[:800])

    # ── Step 2: Quick port scan ──
    with _ui.spinner("Scanning top 24 ports...", soft_fail=True):
        try:
            scan_raw = await session.call_tool(
                "quick_scan",
                {
                    "target_ip": target_ip,
                    "ports": DEFAULT_FAST_PORTS,
                },
            )
            scan_result = extract_tool_text(scan_raw)
        except _EXC_GROUP_CATCH as exc:
            _ui.warning(f"Port scan failed: {exc}")
            scan_result = f"QUICK_SCAN_RESULTS: {target_ip}\nSUMMARY: 0/0 ports open\nNOTE: Scan error: {exc}"
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    _ui.result("Port Scan", scan_result[:1200])

    # ── Step 3: CVE lookup per discovered service (shared planner) ──
    cve_results: list[dict[str, Any]] = []
    open_ports: list[tuple[str, str, str, str]] = []
    for line in scan_result.splitlines():
        port_match = re.match(
            r"\s*Port\s+(\d+)/(tcp|udp)\s+OPEN\s*\((\w*)\)\s*-\s*(.*)",
            line,
        )
        if port_match:
            open_ports.append(port_match.groups())

    if open_ports:
        # Shared planner: pre-filter to the queryable subset (banner identifies
        # a concrete product+version) and deduplicate identical queries. The
        # skip predicate is a pure function of the banner already in hand, so
        # we compute it once instead of iterating all ports and logging
        # "Skipping..." per port. Also makes the announcement count honest
        # ("N of M") instead of implying all M will be queried.
        planned = plan_cve_queries(
            [
                {"port": port, "protocol": proto, "service": service, "banner": banner}
                for port, proto, service, banner in open_ports
            ]
        )
        _ui.info(f"Looking up CVEs for {len(planned)} of {len(open_ports)} discovered service(s)...")
        for query, meta in planned.items():
            product, version, port = meta["product"], meta["version"], meta["port"]
            with _ui.spinner(f"Looking up CVEs for {product} {version} on port {port}..."):
                try:
                    cve_raw = await session.call_tool("search_cve_intel", {"query": query})
                    cve_text = extract_tool_text(cve_raw)
                    cve_results.append(
                        {
                            "service": meta["service"],
                            "product": product,
                            "version": version,
                            "port": port,
                            "results": cve_text[:2000],
                        }
                    )
                    _ui.result(f"CVEs for {product} {version}", cve_text[:600])
                except _EXC_GROUP_CATCH as exc:
                    _ui.warning(f"CVE lookup skipped for {meta['service']}: {exc}")
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)

    # ── Build assessment ──
    assessment = build_assessment_from_mcp_results(
        target_ip=target_ip,
        os_result=os_result,
        scan_result=scan_result,
        cve_results=cve_results,
    )

    # ── Persist to reports dir ──
    assessment_path = reports_dir / "recon_assessment.json"
    assessment_path.write_text(json.dumps(assessment.to_dict(), indent=2), encoding="utf-8")
    _ui.info(f"Recon assessment saved to: {assessment_path}")

    return assessment


# ---------------------------------------------------------------------------
# ReconService — single entry point, profile-dispatched
# ---------------------------------------------------------------------------


class ReconService:
    """Single entry point for reconnaissance, profile-dispatched.

    Profiles:

    - ``full``: ``ReconPipeline`` (direct-subprocess Nmap + secondary
      enumerators). No MCP session needed.
    - ``fast``: ``FastReconCoordinator`` (budget-limited parallel preset over
      the MCP session tools: bounded concurrency, per-task + overall
      deadlines, dedup, short-lived disk cache).
    - ``assessment``: legacy sequential MCP assessment (OS → scan → CVE).

    Usage::

        service = ReconService.from_config(config, reports_dir=reports_dir)
        full_result = await service.run_full("10.0.0.50")
        fast_result = await service.run_fast(session, "10.0.0.50")
        assessment = await service.run_assessment(session, "10.0.0.50")
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        recon_config: ReconConfig | None = None,
        fast_config: FastReconConfig | dict[str, Any] | None = None,
        reports_dir: Path | None = None,
        event_sink: Any | None = None,
        cancellation: Any | None = None,
    ) -> None:
        self._config: dict[str, Any] = config or {}
        self._recon_config = recon_config or ReconConfig.from_config(self._config)
        if isinstance(fast_config, FastReconConfig):
            self._fast_config = fast_config
        elif isinstance(fast_config, dict):
            self._fast_config = FastReconConfig.from_config(fast_config)
        else:
            self._fast_config = FastReconConfig.from_config(self._config)
        self._reports_dir = reports_dir or Path("reports")
        self._event_sink = event_sink
        self._cancellation = cancellation

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any] | None,
        *,
        reports_dir: Path | None = None,
        event_sink: Any | None = None,
        cancellation: Any | None = None,
        **overrides: Any,
    ) -> "ReconService":
        """Build a service from the raw config dict (``config.yaml``)."""
        recon_config = ReconConfig.from_config(config, **overrides.pop("recon_overrides", {}))
        fast_config = FastReconConfig.from_config(config)
        for key in ("enabled", "max_concurrency", "overall_timeout_seconds", "cache_ttl_seconds"):
            if key in overrides:
                setattr(fast_config, key, overrides.pop(key))
        if overrides:
            recon_config = ReconConfig.from_config(config, **overrides)
        return cls(
            config,
            recon_config=recon_config,
            fast_config=fast_config,
            reports_dir=reports_dir,
            event_sink=event_sink,
            cancellation=cancellation,
        )

    @property
    def recon_config(self) -> ReconConfig:
        return self._recon_config

    @property
    def fast_config(self) -> FastReconConfig:
        return self._fast_config

    @property
    def reports_dir(self) -> Path:
        return self._reports_dir

    def enrichment_status(self) -> dict[str, Any]:
        """Report which vuln-intel enrichment stages are active.

        CVE/EPSS/KEV enrichment executes inside ``NVDClient`` behind the MCP
        ``search_cve_intel`` tool; this reports the effective flags from
        ``cve_lookup.*`` plus the fast-profile ``cve_lookup`` toggle so both
        paths share one introspection point.
        """
        cve_cfg = (self._config.get("cve_lookup") or {}) if isinstance(self._config, dict) else {}
        return {
            "cve_lookup": bool(cve_cfg.get("enabled", True)) and self._fast_config.cve_lookup,
            "epss_enabled": bool(cve_cfg.get("epss_enabled", False)),
            "kev_enabled": bool(cve_cfg.get("kev_enabled", False)),
        }

    async def run_full(self, target: str, aggression: str = "normal") -> HostReconResult:
        """Run the full pipeline (primary scan + secondary enumeration)."""
        from tools.recon.pipeline import ReconPipeline

        if aggression != self._recon_config.aggression_level:
            pipeline = ReconPipeline(ReconConfig.from_config(self._config, aggression_level=aggression))
        else:
            pipeline = ReconPipeline(self._recon_config)
        return await pipeline.recon_host(target)

    async def run_udp(self, target: str, top_ports: int | None = None) -> HostReconResult:
        """Run the additive UDP recon path against the single target."""
        from tools.recon.pipeline import ReconPipeline

        pipeline = ReconPipeline(self._recon_config)
        return await pipeline.recon_udp(target, top_ports=top_ports)

    async def run_fast(self, session: Any, target: str) -> FastReconResult:
        """Run the budget-limited fast preset over an MCP session."""
        coordinator = FastReconCoordinator(
            config=self._fast_config,
            reports_dir=self._reports_dir,
            event_sink=self._event_sink,
            cancellation=self._cancellation,
        )
        return await coordinator.run(session, target)

    async def run_assessment(
        self,
        session: Any,
        target: str,
        reports_dir: Path | None = None,
        ctx: Any | None = None,
    ) -> ReconAssessment:
        """Run the legacy sequential MCP assessment path."""
        return await run_sequential_assessment(
            session=session,
            target_ip=target,
            reports_dir=reports_dir or self._reports_dir,
            ctx=ctx,
        )

    async def run(
        self,
        target: str,
        profile: ReconProfile = "full",
        session: Any | None = None,
        *,
        aggression: str = "normal",
        reports_dir: Path | None = None,
        ctx: Any | None = None,
    ) -> HostReconResult | FastReconResult | ReconAssessment:
        """Dispatch to a recon profile.

        ``full`` needs no session; ``fast`` and ``assessment`` require the
        target-locked MCP ``session`` (allowlist enforced at the MCP layer).
        """
        if profile == "fast":
            if session is None:
                raise ValueError("fast profile requires an MCP session")
            return await self.run_fast(session, target)
        if profile == "assessment":
            if session is None:
                raise ValueError("assessment profile requires an MCP session")
            return await self.run_assessment(session, target, reports_dir, ctx)
        if profile == "full":
            return await self.run_full(target, aggression=aggression)
        raise ValueError(f"unknown recon profile: {profile!r} (expected one of {PROFILES})")

    def get_attack_surface_summary(self, result: HostReconResult) -> dict[str, Any]:
        """Attack-surface summary for downstream attack modules (full path)."""
        from tools.recon.pipeline import ReconPipeline

        return ReconPipeline(self._recon_config).get_attack_surface_summary(result)
