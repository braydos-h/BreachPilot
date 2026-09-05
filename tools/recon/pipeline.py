"""Recon pipeline orchestrator — canonical implementation.

Moved from ``tools.recon_pipeline.ReconPipeline`` (2337 LOC god file) into
``tools/recon/``. ``tools.recon_pipeline`` is now a 5-line deprecated shim.
``ReconConfig.from_config`` is the sole config entry point.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from tools.logging_setup import get_logger
from tools.recon.config import HostReconResult, ReconConfig
from tools.recon.enumerator import SecondaryEnumerator
from tools.recon.scanner import PrimaryReconScanner
from tools.socket_scan import COMMON_PORTS, probe_reachable

logger = get_logger()


class ReconPipeline:
    """Main entry point for adaptive reconnaissance.

    Usage::
        pipeline = ReconPipeline(config)
        result = await pipeline.recon_host("10.0.0.50")
    """

    def __init__(self, config: ReconConfig | None = None) -> None:
        self._config = config or ReconConfig()
        self._primary = PrimaryReconScanner(self._config)
        self._secondary = SecondaryEnumerator(self._config)

    async def recon_host(self, target: str) -> HostReconResult:
        """Run full reconnaissance pipeline against a single host."""
        logger.info(f"Starting full reconnaissance pipeline for {target}")
        start = time.monotonic()

        # Pre-flight reachability probe (Phase 5, opt-in). Runs a couple of
        # bare TCP connects *before* the expensive Nmap -p- scan. Refused means
        # the host is UP (an RST is an answer), so an all-refused verdict on a
        # small probe set (default [80, 443]) only proves those ports are
        # closed -- the host may still be attackable on an off-default port.
        # Skip the full scan ONLY when every port of a COMMON_PORTS-sized
        # sample was refused. Ambiguous results (timeout/filtered) and
        # small-sample refused verdicts fall through -- this path can only
        # skip work, never add it.
        if self._config.preflight_probe:
            reachable = await probe_reachable(
                target,
                ports=list(self._config.preflight_ports),
                timeout=self._config.preflight_timeout_ms / 1000.0,
            )
            if reachable is False:
                if len(list(self._config.preflight_ports)) >= len(COMMON_PORTS):
                    logger.warning(
                        f"Preflight probe: {target} refused on all probe ports "
                        f"{self._config.preflight_ports} -- skipping full scan"
                    )
                    result = HostReconResult(target_ip=target)
                    result.errors.append(
                        f"target unreachable (preflight probe refused on {self._config.preflight_ports})"
                    )
                    result.scan_duration = max(time.monotonic() - start, 0.0001)
                    return result
                logger.info(
                    f"Preflight probe: {target} refused on small probe set "
                    f"{self._config.preflight_ports} -- proceeding with full scan (refused = host up)"
                )
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

    async def recon_hosts(self, targets: list[str]) -> list[HostReconResult]:
        """Run reconnaissance against multiple hosts in parallel."""
        logger.info(f"Starting parallel reconnaissance for {len(targets)} targets")
        tasks = [self.recon_host(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def recon_udp(self, target: str, top_ports: int | None = None) -> HostReconResult:
        """Run the additive UDP recon path against the single target.

        Does NOT run the TCP primary scan or the secondary enumerators — it is
        a standalone UDP pass that populates ``udp_ports`` and udp
        ``ServiceInfo`` entries. The TCP :meth:`recon_host` path is unchanged.
        Targets ONLY the single authorized ``target``.
        """
        if top_ports is None:
            top_ports = self._config.udp_top_ports
        return await self._primary.recon_udp(target, top_ports=top_ports)

    def get_attack_surface_summary(self, result: HostReconResult) -> dict[str, Any]:
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
