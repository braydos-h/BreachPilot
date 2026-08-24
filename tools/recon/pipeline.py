"""Recon pipeline orchestrator — Phase 4b real implementation.

Moved from ``tools.recon_pipeline.ReconPipeline`` (167 lines) to break the
2385 LOC god file. ``tools.recon_pipeline`` now re-exports this class for the
1-release shim window (``from tools.recon_pipeline import ReconPipeline`` still
works). See ``docs/phase2-audit/architecture-debt.md`` §12-13.

Ponytail: one class per PR <400, deletion > addition, reuse existing helpers.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from tools.logging_setup import get_logger

logger = get_logger()


class ReconPipeline:
    """Main entry point for adaptive reconnaissance.

    Usage::
        pipeline = ReconPipeline(config)
        result = await pipeline.recon_host("10.0.0.50")
    """

    def __init__(self, config: ReconConfig | None = None) -> None:  # noqa: F821
        # Local imports to avoid circular at top-level (original still defines these)
        from tools.recon_pipeline import PrimaryReconScanner, ReconConfig, SecondaryEnumerator

        self._config = config or ReconConfig()
        self._primary = PrimaryReconScanner(self._config)
        self._secondary = SecondaryEnumerator(self._config)

    async def recon_host(self, target: str) -> HostReconResult:  # noqa: F821
        """Run full reconnaissance pipeline against a single host."""
        from tools.recon_pipeline import HostReconResult

        logger.info(f"Starting full reconnaissance pipeline for {target}")
        start = time.monotonic()

        # Pre-flight reachability probe (Phase 5, opt-in). Runs a couple of
        # bare TCP connects *before* the expensive Nmap -p- scan. A host whose
        # probe ports are all definitively refused would only confirm the same
        # thing after a full 65535-port scan, so skip it now. Ambiguous results
        # (timeout/filtered) fall through -- a firewalled host can still be
        # attackable on a port the probe didn't cover, and this path can only
        # skip work, never add it.
        if self._config.preflight_probe:
            from tools.socket_scan import probe_reachable

            reachable = await probe_reachable(
                target,
                ports=list(self._config.preflight_ports),
                timeout=self._config.preflight_timeout_ms / 1000.0,
            )
            if reachable is False:
                logger.warning(
                    f"Preflight probe: {target} refused on all probe ports "
                    f"{self._config.preflight_ports} -- skipping full scan"
                )
                result = HostReconResult(target_ip=target)
                result.errors.append(f"target unreachable (preflight probe refused on {self._config.preflight_ports})")
                result.scan_duration = max(time.monotonic() - start, 0.0001)
                return result
            elif reachable is None:
                logger.info(f"Preflight probe: {target} ambiguous (timeout/filtered) -- proceeding with full scan")

        # Primary reconnaissance
        result = await self._primary.scan_host(target)

        if not result.open_ports:
            logger.warning(f"No open ports found on {target}, skipping secondary enumeration")
            result.scan_duration = max(time.monotonic() - start, 0.0001)
            return result

        # Secondary enumeration
        if self._config.parallel_secondary:
            result = await self._secondary.enumerate_host(result)

        result.scan_duration = max(time.monotonic() - start, 0.0001)
        logger.info(
            f"Recon complete for {target}: {len(result.open_ports)} ports, "
            f"{len(result.services)} services, {len(result.warnings)} warnings, "
            f"{len(result.errors)} errors ({result.scan_duration:.1f}s)"
        )
        return result

    async def recon_hosts(self, targets: list[str]) -> list[HostReconResult]:  # noqa: F821
        """Run reconnaissance against multiple hosts in parallel."""
        logger.info(f"Starting parallel reconnaissance for {len(targets)} targets")
        tasks = [self.recon_host(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def recon_udp(self, target: str, top_ports: int | None = None) -> HostReconResult:  # noqa: F821
        """Run the additive UDP recon path against the single target.

        Does NOT run the TCP primary scan or the secondary enumerators — it is
        a standalone UDP pass that populates ``udp_ports`` and udp
        ``ServiceInfo`` entries. The TCP :meth:`recon_host` path is unchanged.
        Targets ONLY the single authorized ``target``.
        """
        if top_ports is None:
            top_ports = self._config.udp_top_ports
        return await self._primary.recon_udp(target, top_ports=top_ports)

    def get_attack_surface_summary(self, result: HostReconResult) -> dict[str, Any]:  # noqa: F821
        """Generate a structured attack surface summary for downstream attack modules."""
        attack_surface = {
            "target_ip": result.target_ip,
            "os_family": result.os_family,
            "os_name": result.os_name,
            "total_open_ports": len(result.open_ports),
            "total_services": len(result.services),
            "services_by_name": {},
            "high_value_targets": [],
            "credential_targets": [],
            "web_targets": [],
            "lateral_movement_targets": [],
            "privilege_escalation_hints": [],
            "recommended_attack_modules": [],
        }

        for svc in result.services:
            name = svc.service.lower()
            if name not in attack_surface["services_by_name"]:
                attack_surface["services_by_name"][name] = []
            attack_surface["services_by_name"][name].append(svc.to_dict())

            # High-value targets
            if name in ("ssh", "rdp", "smb", "microsoft-ds"):
                attack_surface["high_value_targets"].append(
                    {
                        "port": svc.port,
                        "service": svc.service,
                        "version": svc.version,
                        "cves": svc.scripts.get("openssh_cves", []),
                    }
                )
                attack_surface["credential_targets"].append(
                    {
                        "port": svc.port,
                        "service": svc.service,
                        "version": svc.version,
                    }
                )

            # Web targets
            if name in ("http", "https", "http-proxy"):
                attack_surface["web_targets"].append(
                    {
                        "port": svc.port,
                        "service": svc.service,
                        "technologies": svc.scripts.get("http_headers", ""),
                        "directories": svc.scripts.get("feroxbuster", ""),
                        "vulns": svc.scripts.get("nuclei", ""),
                    }
                )

            # Lateral movement
            if name in ("smb", "microsoft-ds", "ldap", "ldaps"):
                attack_surface["lateral_movement_targets"].append(
                    {
                        "port": svc.port,
                        "service": svc.service,
                        "version": svc.version,
                    }
                )

            # Privilege escalation hints
            if "docker" in name or svc.port in (2375, 2376, 10250):
                attack_surface["privilege_escalation_hints"].append(
                    {
                        "port": svc.port,
                        "service": svc.service,
                        "hint": "Container/Docker access may allow privilege escalation",
                    }
                )

        # Map to attack modules
        from tools.attack_modules import ModuleContext, find_modules

        ctx = ModuleContext(
            target_ip=result.target_ip,
            target_os=result.os_family,
            services=[{"service": s.service, "port": f"{s.port}/{s.protocol}"} for s in result.services],
            cves=[cve for s in result.services for cve in s.scripts.get("openssh_cves", [])],
        )
        scored_modules = find_modules(ctx)
        attack_surface["recommended_attack_modules"] = [
            {"name": mod.name, "score": score, "description": mod.description} for score, mod in scored_modules[:10]
        ]

        return attack_surface
