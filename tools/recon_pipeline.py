"""Adaptive Reconnaissance Pipeline — deep, service-aware, fallback-enabled scanning.

Replaces shallow banner grabs with a comprehensive reconnaissance engine:

1. Primary scan: Nmap comprehensive (-sS -sV -O -Pn -T4 --script=vuln,default -p-)
2. Fallback chain: Nmap → RustScan → Masscan
3. Service-aware secondary enumeration:
   - HTTP/HTTPS → Nikto, Feroxbuster, Nuclei, SQLMap
   - SSH → Hydra, CVE checks, weak cipher analysis
   - SMB → enum4linux, smbclient, null-session tests
   - LDAP → anonymous bind tests + directory extraction
   - Docker/K8s → exposed API checks
   - FTP → anonymous login, version checks
   - Redis → unauth checks, info extraction
   - Elasticsearch → cluster info, index enumeration
4. Intelligent OS detection combining multiple signals
5. Evidence capture and structured output for downstream attack modules

All operations are async-safe with retries, timeouts, and graceful degradation.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Coroutine

from tools.logging_setup import get_logger
from tools.nmap_priv import apply_nmap_privilege, is_privilege_error
from tools.validation_utils import validate_ipv4, is_fqdn

logger = get_logger()

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ServiceInfo:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    smtp_info: dict[str, Any] = field(default_factory=dict)
    db_info: dict[str, Any] = field(default_factory=dict)
    os_guess: str = ""
    confidence: int = 0
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "cpe": self.cpe,
            "scripts": self.scripts,
            "ssl_info": self.ssl_info,
            "smtp_info": self.smtp_info,
            "db_info": self.db_info,
            "os_guess": self.os_guess,
            "confidence": self.confidence,
            "technologies": self.technologies,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServiceInfo":
        """Reconstruct a ServiceInfo from its serialized form.

        Tier 1.3: needed by ``HostReconResult.from_dict`` so a resumed
        autonomous campaign can rebuild the prior run's recon result (the
        largest, most-expensive-to-regenerate piece of attack state) instead
        of re-scanning from scratch. Tolerant of missing keys (older state
        files) and coerces port/confidence to int defensively.
        """
        if not isinstance(data, dict):
            return cls(port=0)
        return cls(
            port=int(data.get("port", 0) or 0),
            protocol=str(data.get("protocol", "tcp") or "tcp"),
            service=str(data.get("service", "unknown") or "unknown"),
            version=str(data.get("version", "") or ""),
            banner=str(data.get("banner", "") or ""),
            cpe=list(data.get("cpe", []) or []),
            scripts=dict(data.get("scripts", {}) or {}),
            ssl_info=dict(data.get("ssl_info", {}) or {}),
            smtp_info=dict(data.get("smtp_info", {}) or {}),
            db_info=dict(data.get("db_info", {}) or {}),
            os_guess=str(data.get("os_guess", "") or ""),
            confidence=int(data.get("confidence", 0) or 0),
            technologies=list(data.get("technologies", []) or []),
        )


@dataclass
class HostReconResult:
    target_ip: str
    hostname: str = ""
    os_name: str = ""
    os_family: str = ""
    os_accuracy: int = 0
    ttl: int | None = None
    mac_address: str = ""
    vendor: str = ""
    services: list[ServiceInfo] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    filtered_ports: list[int] = field(default_factory=list)
    scan_duration: float = 0.0
    scan_tool: str = ""
    raw_output: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # --- Phase 3 Round 2 additive recon fields (UDP / spider / OSINT) ---
    udp_ports: list[int] = field(default_factory=list)
    spider_results: list[dict[str, Any]] = field(default_factory=list)
    osint: dict[str, Any] = field(default_factory=dict)
    ipv6_addresses: list[str] = field(default_factory=list)
    # Phase: extended depth enumerator outputs (subdomains / vhosts / waf /
    # asn / cloud_metadata / snmp / dns_zone). Each enumerator writes its key.
    extended: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_family": self.os_family,
            "os_accuracy": self.os_accuracy,
            "ttl": self.ttl,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "services": [s.to_dict() for s in self.services],
            "open_ports": self.open_ports,
            "filtered_ports": self.filtered_ports,
            "scan_duration": self.scan_duration,
            "scan_tool": self.scan_tool,
            "evidence_refs": self.evidence_refs,
            "errors": self.errors,
            "warnings": self.warnings,
            "udp_ports": self.udp_ports,
            "spider_results": self.spider_results,
            "osint": self.osint,
            "ipv6_addresses": self.ipv6_addresses,
            "extended": self.extended,
        }

    def get_services_by_name(self, name: str) -> list[ServiceInfo]:
        return [s for s in self.services if s.service.lower() == name.lower()]

    def get_services_by_port(self, port: int) -> list[ServiceInfo]:
        return [s for s in self.services if s.port == port]

    def has_service(self, name: str) -> bool:
        return any(s.service.lower() == name.lower() for s in self.services)

    def has_port(self, port: int) -> bool:
        return port in self.open_ports

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HostReconResult":
        """Reconstruct a HostReconResult from its serialized form.

        Tier 1.3: the autonomous orchestrator persists ``AttackState`` (which
        embeds a ``recon_result``) to ``attack_states.json``; on resume it must
        rebuild the recon result so the campaign continues from known open
        ports/services instead of re-running the (loud, slow) nmap scan. The
        ``raw_output`` field is intentionally dropped on round-trip — it can be
        huge and is regenerable from evidence, not from the state file.
        """
        if not isinstance(data, dict):
            return cls(target_ip=str(data) if data else "")
        services = [
            ServiceInfo.from_dict(s) for s in (data.get("services", []) or [])
            if isinstance(s, dict)
        ]
        ttl = data.get("ttl")
        return cls(
            target_ip=str(data.get("target_ip", "") or ""),
            hostname=str(data.get("hostname", "") or ""),
            os_name=str(data.get("os_name", "") or ""),
            os_family=str(data.get("os_family", "") or ""),
            os_accuracy=int(data.get("os_accuracy", 0) or 0),
            ttl=int(ttl) if ttl is not None else None,
            mac_address=str(data.get("mac_address", "") or ""),
            vendor=str(data.get("vendor", "") or ""),
            services=services,
            open_ports=list(data.get("open_ports", []) or []),
            filtered_ports=list(data.get("filtered_ports", []) or []),
            scan_duration=float(data.get("scan_duration", 0.0) or 0.0),
            scan_tool=str(data.get("scan_tool", "") or ""),
            raw_output="",  # not round-tripped (regenerable from evidence)
            evidence_refs=list(data.get("evidence_refs", []) or []),
            errors=list(data.get("errors", []) or []),
            warnings=list(data.get("warnings", []) or []),
            udp_ports=list(data.get("udp_ports", []) or []),
            spider_results=list(data.get("spider_results", []) or []),
            osint=dict(data.get("osint", {}) or {}),
            ipv6_addresses=list(data.get("ipv6_addresses", []) or []),
            extended=dict(data.get("extended", {}) or {}),
        )


@dataclass
class ReconConfig:
    nmap_path: str = "nmap"
    rustscan_path: str = "rustscan"
    masscan_path: str = "masscan"
    nikto_path: str = "nikto"
    feroxbuster_path: str = "feroxbuster"
    gobuster_path: str = "gobuster"
    nuclei_path: str = "nuclei"
    sqlmap_path: str = "sqlmap"
    hydra_path: str = "hydra"
    enum4linux_path: str = "enum4linux"
    smbclient_path: str = "smbclient"
    ldapsearch_path: str = "ldapsearch"
    curl_path: str = "curl"
    timeout_seconds: int = 300
    max_retries: int = 2
    retry_delay: float = 5.0
    aggression_level: str = "normal"  # stealth, normal, aggressive
    stealth_options: list[str] = field(default_factory=list)
    wordlist_path: str = "/usr/share/wordlists/dirb/common.txt"
    fallback_enabled: bool = True
    parallel_secondary: bool = True
    max_concurrent_secondary: int = 3
    # Nmap privilege handling (mirrors config.yaml ``nmap.sudo`` /
    # ``nmap.priv_fallback``). When unprivileged: ``sudo`` runs nmap via
    # ``sudo -n``; otherwise ``priv_fallback`` downgrades ``-sS``/``-O`` to
    # ``-sT`` instead of failing. See ``tools.nmap_priv``.
    sudo: bool = False
    priv_fallback: bool = True
    # UDP scan scope (Phase 3 Round 2). ``--top-ports <N>`` for the additive
    # ``recon_udp`` path. Default 100 keeps the UDP scan fast; raise it for
    # deeper coverage. TCP ``scan_host`` is unaffected.
    udp_top_ports: int = 100
    # Phase 3 Round 2 additive secondary enumerators (TLS / SMTP / DB / web
    # spider / passive OSINT). The dataclass default is False so direct
    # ``ReconConfig()`` construction (used by existing tests that mock only the
    # original nine enumerators) preserves the legacy enumerate_host behavior
    # — the new coroutines never run unmocked and cannot append evidence or
    # touch the network in those tests. ``from_config`` flips this to True
    # (reading ``recon.extended_enumerators``) so production / MCP paths opt in
    # automatically. The TCP ``scan_host`` path is unchanged regardless.
    extended_enumerators: bool = False
    # Optional Shodan API key for the passive OSINT enumerator. Empty string
    # (the default) leaves Shodan disabled — ``run_osint`` returns
    # ``{"enabled": False, ...}``. Read from ``recon.shodan_api_key`` (or the
    # ``SHODAN_API_KEY`` env var as a fallback) in ``from_config``.
    shodan_api_key: str = ""
    # Phase: extended depth enumerators. Each is independently gated (default
    # OFF) and additive — when the flag is False the coroutine never runs, so
    # existing tests that mock only the original nine enumerators are
    # unaffected. Read from ``recon.<flag>`` in ``from_config``.
    subdomain_enum: bool = False
    vhost_discovery: bool = False
    waf_fingerprint: bool = False
    asn_whois: bool = False
    cloud_metadata_probe: bool = False
    snmp_enum: bool = False
    dns_zone_transfer: bool = False

    @classmethod
    def from_config(cls, config: dict | None, **overrides: Any) -> "ReconConfig":
        """Build a ReconConfig from a config dict, reading the ``nmap`` section
        for path/sudo/priv_fallback. Extra keyword overrides (e.g.
        ``aggression_level``) are applied on top so callers don't lose fields
        they used to pass positionally."""
        nmap = ((config or {}).get("nmap") or {})
        recon_cfg = ((config or {}).get("recon") or {})
        import os as _os
        shodan_key = (recon_cfg.get("shodan_api_key") or _os.environ.get("SHODAN_API_KEY", "") or "")
        fields: dict[str, Any] = dict(
            nmap_path=nmap.get("path") or "nmap",
            sudo=bool(nmap.get("sudo", False)),
            priv_fallback=bool(nmap.get("priv_fallback", True)),
            # Production opts into the Phase 3 additive enumerators by
            # default; ``recon.extended_enumerators: false`` disables them.
            extended_enumerators=bool(recon_cfg.get("extended_enumerators", True)),
            shodan_api_key=shodan_key,
        )
        # Phase: extended depth enumerators (all default False / opt-in).
        for flag in (
            "subdomain_enum", "vhost_discovery", "waf_fingerprint",
            "asn_whois", "cloud_metadata_probe", "snmp_enum", "dns_zone_transfer",
        ):
            fields[flag] = bool(recon_cfg.get(flag, False))
        fields.update(overrides)
        return cls(**fields)


# ---------------------------------------------------------------------------
# Tool availability checker
# ---------------------------------------------------------------------------

class ToolAvailability:
    """Cache of which external tools are available on the system."""

    _cache: dict[str, bool] = {}

    @classmethod
    def check(cls, tool_name: str) -> bool:
        if tool_name not in cls._cache:
            cls._cache[tool_name] = shutil.which(tool_name) is not None
        return cls._cache[tool_name]

    @classmethod
    def reset(cls) -> None:
        cls._cache.clear()


# ---------------------------------------------------------------------------
# Async command runner with retries
# ---------------------------------------------------------------------------

async def _kill_process(proc: Any) -> None:
    """Kill a subprocess and wait for it.

    On POSIX, kills the whole process group (the subprocess is started with
    ``start_new_session=True`` in :func:`run_command`, so it leads its own
    process group). This ensures child processes spawned by the command die
    with it rather than outliving the timeout. Falls back to a plain
    ``proc.kill()`` on Windows or if the process-group kill fails.
    """
    if hasattr(os, "killpg"):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            # Process already exited; nothing to clean up.
            pass
        except Exception:
            kill_result = proc.kill()
            if inspect.isawaitable(kill_result):
                await kill_result
    else:
        kill_result = proc.kill()
        if inspect.isawaitable(kill_result):
            await kill_result
    await proc.wait()


async def run_command(
    cmd: list[str],
    *,
    timeout: int = 300,
    max_retries: int = 2,
    retry_delay: float = 5.0,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
) -> tuple[bool, str, str, float]:
    """Run a command asynchronously with retries and timeout.

    Returns: (success, stdout, stderr, elapsed_seconds)
    """
    last_error = ""
    for attempt in range(max_retries + 1):
        proc = None
        start = time.monotonic()
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None,
                    cwd=cwd,
                    env=env,
                    start_new_session=True,
                ),
                timeout=timeout,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            elapsed = max(time.monotonic() - start, 0.0001)
            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            if proc.returncode == 0:
                logger.debug(f"Command succeeded: {' '.join(cmd[:5])}... ({elapsed:.1f}s)")
                return True, stdout, stderr, elapsed
            else:
                last_error = f"Exit code {proc.returncode}: {stderr[:500]}"
                logger.warning(f"Command failed (attempt {attempt+1}): {last_error}")
                # A raw-socket scan that fails for lack of root fails
                # identically on every retry. Don't burn the retry budget --
                # return now so the caller can downgrade the argv (``-sS`` ->
                # ``-sT``) and retry once with the corrected command.
                if is_privilege_error(stderr):
                    logger.warning(f"Privilege-related failure, not retrying: {last_error}")
                    return False, stdout, stderr, elapsed

        except asyncio.TimeoutError:
            last_error = f"Timeout after {timeout}s"
            logger.warning(f"Command timeout (attempt {attempt+1}): {' '.join(cmd[:5])}...")
            if proc and proc.returncode is None:
                try:
                    await _kill_process(proc)
                except Exception:
                    pass

        except Exception as exc:
            if proc is not None:
                try:
                    await _kill_process(proc)
                except Exception:
                    pass
            last_error = str(exc)
            logger.warning(f"Command exception (attempt {attempt+1}): {last_error}")

        if attempt < max_retries:
            logger.info(f"Retrying in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay *= 1.5  # Exponential backoff

    return False, "", last_error, 0.0


# ---------------------------------------------------------------------------
# Primary reconnaissance: Nmap with fallback chain
# ---------------------------------------------------------------------------

class PrimaryReconScanner:
    """Runs comprehensive host scanning with automatic fallback."""

    def __init__(self, config: ReconConfig) -> None:
        self._config = config

    async def scan_host(self, target: str) -> HostReconResult:
        """Run primary reconnaissance against a single target."""
        result = HostReconResult(target_ip=target)
        start_time = time.monotonic()

        # Try Nmap first
        if ToolAvailability.check(self._config.nmap_path):
            logger.info(f"Starting Nmap comprehensive scan against {target}")
            nmap_result = await self._run_nmap(target)
            if nmap_result and nmap_result.open_ports:
                result = nmap_result
                result.scan_duration = max(time.monotonic() - start_time, 0.0001)
                logger.info(f"Nmap scan complete: {len(result.open_ports)} ports on {target}")
                return result
            elif nmap_result:
                result.errors.extend(nmap_result.errors)
                result.warnings.extend(nmap_result.warnings)

        # Fallback to RustScan
        if self._config.fallback_enabled and ToolAvailability.check(self._config.rustscan_path):
            logger.info(f"Falling back to RustScan for {target}")
            rust_result = await self._run_rustscan(target)
            if rust_result and rust_result.open_ports:
                result = rust_result
                result.scan_duration = max(time.monotonic() - start_time, 0.0001)
                logger.info(f"RustScan complete: {len(result.open_ports)} ports on {target}")
                return result
            elif rust_result:
                result.errors.extend(rust_result.errors)

        # Fallback to Masscan
        if self._config.fallback_enabled and ToolAvailability.check(self._config.masscan_path):
            logger.info(f"Falling back to Masscan for {target}")
            mass_result = await self._run_masscan(target)
            if mass_result and mass_result.open_ports:
                result = mass_result
                result.scan_duration = max(time.monotonic() - start_time, 0.0001)
                logger.info(f"Masscan complete: {len(result.open_ports)} ports on {target}")
                return result
            elif mass_result:
                result.errors.extend(mass_result.errors)

        # Final fallback: native Python socket scan (no privileges needed).
        # Used when nmap/rustscan/masscan are unavailable OR failed for lack of
        # root (a non-root operator box). Covers a conservative common-ports
        # set rather than ``-p-`` so it stays fast.
        if self._config.fallback_enabled and not result.open_ports:
            logger.info(f"Falling back to native Python socket scan for {target}")
            try:
                from tools.socket_scan import COMMON_PORTS, socket_scan

                sock_results = await socket_scan(target, COMMON_PORTS)
                open_results = [r for r in sock_results if r["open"]]
                if open_results:
                    result.open_ports = [r["port"] for r in open_results]
                    result.scan_tool = "python_socket"
                    for r in open_results:
                        result.services.append(
                            ServiceInfo(
                                port=r["port"],
                                service=r["service_guess"] or "unknown",
                                banner=r.get("banner", ""),
                            )
                        )
                    result.warnings.append(
                        "Native socket scan used (nmap/rustscan/masscan "
                        "unavailable or failed). Service versions are guesses."
                    )
                    result.scan_duration = max(time.monotonic() - start_time, 0.0001)
                    logger.info(
                        f"Socket scan complete: {len(result.open_ports)} ports on {target}"
                    )
                    return result
            except Exception as exc:
                result.errors.append(f"Socket scan fallback failed: {exc}")

        # If all failed, return empty result with errors
        result.scan_duration = max(time.monotonic() - start_time, 0.0001)
        if not result.errors:
            result.errors.append("All scanning tools failed or found no open ports.")
        logger.error(f"Primary recon failed for {target}: {result.errors[-1]}")
        return result

    async def _run_nmap(self, target: str) -> HostReconResult | None:
        """Run comprehensive Nmap scan."""
        result = HostReconResult(target_ip=target, scan_tool="nmap")
        cmd = [
            self._config.nmap_path,
            "-sS", "-sV", "-O", "-Pn", "-T4",
            "--script=vuln,default",
            "-p-",
            "-oX", "-",  # XML output to stdout
            target,
        ]

        if self._config.aggression_level == "stealth":
            cmd = [
                self._config.nmap_path,
                "-sS", "-Pn", "--data-length", "50",
                "--randomize-hosts", "-T2",
                "-p-",
                "-oX", "-",
                target,
            ]
        elif self._config.aggression_level == "aggressive":
            cmd = [
                self._config.nmap_path,
                "-sS", "-sV", "-O", "-Pn", "-T5",
                "--script=vuln,default",
                "-p-",
                "-oX", "-",
                target,
            ]

        # Apply sudo-prefix / unprivileged downgrade (``-sS``/``-O`` -> ``-sT``)
        # up front so a non-root operator box does not fail on raw-packet scans.
        cmd, note = apply_nmap_privilege(
            cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback
        )
        if note:
            result.warnings.append(note)

        success, stdout, stderr, elapsed = await run_command(
            cmd,
            timeout=self._config.timeout_seconds,
            max_retries=self._config.max_retries,
            retry_delay=self._config.retry_delay,
        )

        # If the operator ran unprivileged with priv_fallback OFF, the first
        # attempt keeps ``-sS``/``-O`` and fails with a privilege error.
        # run_command returns immediately on privilege errors (no retry), so
        # downgrade once and retry a single time instead of aborting recon.
        if not success and is_privilege_error(stderr) and not note:
            cmd2, note2 = apply_nmap_privilege(
                cmd, sudo=self._config.sudo, priv_fallback=True
            )
            if note2:
                result.warnings.append(note2)
            success, stdout, stderr, elapsed = await run_command(
                cmd2,
                timeout=self._config.timeout_seconds,
                max_retries=0,
            )
            cmd = cmd2

        result.scan_duration = elapsed
        result.raw_output = stdout + "\n" + stderr

        if not success:
            result.errors.append(f"Nmap failed: {stderr[:500]}")
            return result

        # Parse Nmap XML output
        try:
            result = self._parse_nmap_xml(stdout, result)
        except Exception as exc:
            logger.warning(f"Nmap XML parse failed, falling back to grepable: {exc}")
            result = self._parse_nmap_grepable(stdout + "\n" + stderr, result)

        # Extract TTL for OS fingerprinting
        ttl_match = re.search(r"TTL=(\d+)", result.raw_output, re.IGNORECASE)
        if ttl_match:
            result.ttl = int(ttl_match.group(1))
            result.os_family = self._ttl_to_os_family(result.ttl)

        return result

    async def _run_nmap_udp(
        self, target: str, top_ports: int = 100
    ) -> HostReconResult | None:
        """Run a targeted UDP scan against the single target.

        Uses ``nmap -sU --top-ports <N> -sV --script=default,vuln -Pn``. UDP
        scanning requires root/raw sockets, so this mirrors the TCP
        ``_run_nmap`` privilege handling: ``apply_nmap_privilege`` is applied up
        front (sudo prefix / ``priv_fallback``), and on a privilege-related
        failure the scan is retried once with a smaller ``--top-ports`` set
        (UDP scan time grows quickly with port count) before giving up.

        Output is parsed by :func:`tools.recon_enrichers.parse_udp_nmap_output`
        into ``ServiceInfo`` entries with ``protocol="udp"``; their ports are
        also collected into ``result.udp_ports``. Routed through
        :func:`run_command` so tests can mock it. Targets ONLY the single
        authorized ``target``.
        """
        from tools.recon_enrichers import parse_udp_nmap_output

        result = HostReconResult(target_ip=target, scan_tool="nmap-udp")
        if top_ports is None or top_ports <= 0:
            top_ports = 100

        cmd = [
            self._config.nmap_path,
            "-sU", "-sV", "-Pn",
            "--top-ports", str(top_ports),
            "--script=default,vuln",
            "-oX", "-",
            target,
        ]

        cmd, note = apply_nmap_privilege(
            cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback
        )
        if note:
            result.warnings.append(note)

        success, stdout, stderr, elapsed = await run_command(
            cmd,
            timeout=self._config.timeout_seconds,
            max_retries=self._config.max_retries,
            retry_delay=self._config.retry_delay,
        )

        # Privilege-related failure: retry once with a smaller port set so a
        # non-root operator box still gets *some* UDP coverage rather than
        # aborting. run_command returns immediately on privilege errors.
        if not success and is_privilege_error(stderr) and not note:
            reduced = max(min(top_ports // 2, 50), 10)
            cmd2 = [
                self._config.nmap_path,
                "-sU", "-sV", "-Pn",
                "--top-ports", str(reduced),
                "--script=default",
                "-oX", "-",
                target,
            ]
            cmd2, note2 = apply_nmap_privilege(
                cmd2, sudo=self._config.sudo, priv_fallback=True
            )
            if note2:
                result.warnings.append(note2)
            success, stdout, stderr, elapsed = await run_command(
                cmd2,
                timeout=self._config.timeout_seconds,
                max_retries=0,
            )
            cmd = cmd2

        result.scan_duration = elapsed
        result.raw_output = stdout + "\n" + stderr

        if not success:
            result.errors.append(f"Nmap UDP failed: {stderr[:500]}")
            return result

        # Parse UDP output into ServiceInfo entries (protocol="udp").
        udp_entries = parse_udp_nmap_output(stdout)
        udp_ports: list[int] = []
        for entry in udp_entries:
            port = int(entry.get("port", 0) or 0)
            if port <= 0:
                continue
            udp_ports.append(port)
            result.services.append(
                ServiceInfo(
                    port=port,
                    protocol="udp",
                    service=str(entry.get("service", "") or "unknown"),
                    banner=str(entry.get("banner", "") or ""),
                )
            )
        # De-duplicate ports preserving order.
        seen: set[int] = set()
        result.udp_ports = [p for p in udp_ports if not (p in seen or seen.add(p))]

        return result

    async def recon_udp(self, target: str, top_ports: int = 100) -> HostReconResult:
        """Public UDP recon entry point against the single target.

        Runs ``_run_nmap_udp`` and returns a ``HostReconResult`` whose
        ``udp_ports`` / ``services`` (protocol="udp") are populated. The TCP
        :meth:`scan_host` path is unchanged — this is an additive, separate
        entry point so existing callers/tests are unaffected. Targets ONLY the
        single authorized ``target``.
        """
        if not ToolAvailability.check(self._config.nmap_path):
            result = HostReconResult(target_ip=target, scan_tool="nmap-udp")
            result.errors.append("nmap not available for UDP scan")
            return result
        result = await self._run_nmap_udp(target, top_ports=top_ports)
        return result or HostReconResult(target_ip=target, scan_tool="nmap-udp")

    async def _run_rustscan(self, target: str) -> HostReconResult | None:
        """Run RustScan for fast port discovery, then Nmap for service detection."""
        result = HostReconResult(target_ip=target, scan_tool="rustscan+nmap")

        # RustScan for port discovery
        rust_cmd = [
            self._config.rustscan_path,
            "-a", target,
            "-t", "2000",
            "-b", "1000",
            "--range", "1-65535",
            "--accessible",  # No emoji, machine-friendly
        ]

        success, stdout, stderr, _ = await run_command(
            rust_cmd,
            timeout=min(self._config.timeout_seconds, 180),
            max_retries=1,
        )

        if not success:
            result.errors.append(f"RustScan failed: {stderr[:500]}")
            return result

        # Extract open ports from RustScan output
        ports = self._extract_ports_from_rustscan(stdout + "\n" + stderr)
        if not ports:
            result.warnings.append("RustScan found no open ports.")
            return result

        result.open_ports = ports

        # Follow up with targeted Nmap service scan
        port_str = ",".join(str(p) for p in ports[:50])  # Limit to top 50 for speed
        nmap_cmd = [
            self._config.nmap_path,
            "-sS", "-sV", "-Pn", "-T4",
            "--script=default,vuln",
            "-p", port_str,
            "-oX", "-",
            target,
        ]
        nmap_cmd, _ = apply_nmap_privilege(
            nmap_cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback
        )

        nmap_success, nmap_stdout, nmap_stderr, nmap_elapsed = await run_command(
            nmap_cmd,
            timeout=self._config.timeout_seconds,
            max_retries=1,
        )

        if nmap_success:
            result = self._parse_nmap_xml(nmap_stdout, result)
            result.scan_tool = "rustscan+nmap"
            result.scan_duration += nmap_elapsed
        else:
            # If Nmap follow-up fails, at least we have ports
            result.warnings.append(f"Nmap service scan failed: {nmap_stderr[:500]}")
            for port in ports:
                result.services.append(ServiceInfo(port=port, service="unknown"))

        return result

    async def _run_masscan(self, target: str) -> HostReconResult | None:
        """Run Masscan for ultra-fast port discovery."""
        result = HostReconResult(target_ip=target, scan_tool="masscan")

        cmd = [
            self._config.masscan_path,
            target,
            "-p1-65535",
            "--rate", "1000",
            "--wait", "5",
            "-oJ", "-",  # JSON output to stdout
        ]

        success, stdout, stderr, elapsed = await run_command(
            cmd,
            timeout=min(self._config.timeout_seconds, 120),
            max_retries=1,
        )

        result.scan_duration = elapsed
        result.raw_output = stdout + "\n" + stderr

        if not success:
            result.errors.append(f"Masscan failed: {stderr[:500]}")
            return result

        # Parse Masscan JSON output
        ports = self._extract_ports_from_masscan(stdout)
        if not ports:
            result.warnings.append("Masscan found no open ports.")
            return result

        result.open_ports = ports

        # Follow up with Nmap for service detection on discovered ports
        if ToolAvailability.check(self._config.nmap_path) and ports:
            port_str = ",".join(str(p) for p in ports[:50])
            nmap_cmd = [
                self._config.nmap_path,
                "-sS", "-sV", "-Pn", "-T4",
                "-p", port_str,
                "-oX", "-",
                target,
            ]
            nmap_cmd, _ = apply_nmap_privilege(
                nmap_cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback
            )
            nmap_success, nmap_stdout, nmap_stderr, nmap_elapsed = await run_command(
                nmap_cmd,
                timeout=self._config.timeout_seconds,
                max_retries=1,
            )
            if nmap_success:
                result = self._parse_nmap_xml(nmap_stdout, result)
                result.scan_tool = "masscan+nmap"
                result.scan_duration += nmap_elapsed
            else:
                for port in ports:
                    result.services.append(ServiceInfo(port=port, service="unknown"))

        return result

    # -----------------------------------------------------------------------
    # Nmap output parsers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_nmap_xml(xml_data: str, result: HostReconResult) -> HostReconResult:
        """Parse Nmap XML output into structured result."""
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(xml_data.encode("utf-8", errors="replace"))
        except ET.ParseError as exc:
            result.errors.append(f"XML parse error: {exc}")
            return result

        for host in root.findall("host"):
            # Hostname
            for hostname in host.findall("hostnames/hostname"):
                if hostname.get("name"):
                    result.hostname = hostname.get("name")

            # Address info
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype", "")
                if addr_type == "ipv4":
                    pass  # Already set
                elif addr_type == "mac":
                    result.mac_address = addr.get("addr", "")
                    result.vendor = addr.get("vendor", "")

            # OS detection
            for osmatch in host.findall("os/osmatch"):
                result.os_name = osmatch.get("name", "")
                result.os_accuracy = int(osmatch.get("accuracy", "0") or "0")
                for osclass in osmatch.findall("osclass"):
                    result.os_family = osclass.get("osfamily", "")
                    break
                break

            # Ports
            for port in host.findall("ports/port"):
                port_id = int(port.get("portid", "0"))
                protocol = port.get("protocol", "tcp")
                state_elem = port.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""

                if state == "open":
                    result.open_ports.append(port_id)
                elif state == "filtered":
                    result.filtered_ports.append(port_id)

                service_elem = port.find("service")
                svc = ServiceInfo(port=port_id, protocol=protocol)

                if service_elem is not None:
                    svc.service = service_elem.get("name", "unknown")
                    svc.version = service_elem.get("version", "")
                    if service_elem.get("product"):
                        svc.version = f"{service_elem.get('product')} {svc.version}".strip()
                    svc.banner = service_elem.get("extrainfo", "")
                    for cpe in service_elem.findall("cpe"):
                        if cpe.text:
                            svc.cpe.append(cpe.text)

                # Script results
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    svc.scripts[script_id] = script_output

                if state == "open":
                    result.services.append(svc)

            # Host scripts
            for script in host.findall("hostscript/script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                for svc in result.services:
                    svc.scripts[script_id] = script_output

        return result

    @staticmethod
    def _parse_nmap_grepable(output: str, result: HostReconResult) -> HostReconResult:
        """Fallback parser for Nmap grepable (-oG) or standard output."""
        port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)")
        for match in port_pattern.finditer(output):
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)

            if state == "open":
                result.open_ports.append(port)
                result.services.append(ServiceInfo(port=port, protocol=protocol, service=service))
            elif state == "filtered":
                result.filtered_ports.append(port)

        # OS detection fallback
        os_match = re.search(r"OS details:\s*(.+)", output)
        if os_match:
            result.os_name = os_match.group(1).strip()

        return result

    @staticmethod
    def _extract_ports_from_rustscan(output: str) -> list[int]:
        """Extract open ports from RustScan output."""
        ports: list[int] = []
        # RustScan outputs lines like: "Open 192.168.1.1:80"
        pattern = re.compile(r"Open\s+\S+:(\d+)")
        for match in pattern.finditer(output):
            ports.append(int(match.group(1)))
        # Also try: "22 -> ..." format
        if not ports:
            pattern2 = re.compile(r"^(\d+)\s+->\s+Open", re.MULTILINE)
            for match in pattern2.finditer(output):
                ports.append(int(match.group(1)))
        return sorted(set(ports))

    @staticmethod
    def _extract_ports_from_masscan(output: str) -> list[int]:
        """Extract open ports from Masscan JSON output."""
        ports: list[int] = []
        try:
            for line in output.strip().split("\n"):
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                data = json.loads(line)
                if "ports" in data:
                    for p in data["ports"]:
                        if "port" in p:
                            ports.append(int(p["port"]))
                elif "port" in data:
                    ports.append(int(data["port"]))
        except (json.JSONDecodeError, ValueError, KeyError):
            # Fallback to regex
            pattern = re.compile(r'"port":\s*(\d+)')
            for match in pattern.finditer(output):
                ports.append(int(match.group(1)))
        return sorted(set(ports))

    @staticmethod
    def _ttl_to_os_family(ttl: int) -> str:
        """Map TTL value to likely OS family."""
        if 0 < ttl <= 64:
            return "Linux/Unix"
        elif 64 < ttl <= 128:
            return "Windows"
        elif 128 < ttl <= 255:
            return "Cisco/Network"
        return "Unknown"


# ---------------------------------------------------------------------------
# Secondary enumeration: service-aware deep scanning
# ---------------------------------------------------------------------------

class SecondaryEnumerator:
    """Performs deep, service-specific enumeration based on primary recon results."""

    def __init__(self, config: ReconConfig) -> None:
        self._config = config

    async def enumerate_host(self, primary_result: HostReconResult) -> HostReconResult:
        """Run all applicable secondary enumeration against a host.

        Each enumeration coroutine receives and mutates the *shared* ``result``
        in place, so there is no per-task result to merge back — merging would
        duplicate evidence/errors exponentially. We only collect exceptions.
        Coroutines are gathered through a semaphore wrapper so concurrency is
        actually bounded (pre-creating ``asyncio.Task`` objects would start
        them immediately, defeating the semaphore).
        """
        result = primary_result
        coros: list[Coroutine[Any, Any, HostReconResult]] = []

        # HTTP/HTTPS enumeration
        http_services = [s for s in result.services if s.service.lower() in ("http", "https", "http-proxy")]
        if http_services:
            coros.append(self._enumerate_http(result, http_services))

        # SSH enumeration
        ssh_services = result.get_services_by_name("ssh")
        if ssh_services:
            coros.append(self._enumerate_ssh(result, ssh_services))

        # SMB enumeration
        smb_services = [s for s in result.services if s.service.lower() in ("microsoft-ds", "smb", "netbios-ssn", "netbios-ns")]
        if smb_services:
            coros.append(self._enumerate_smb(result, smb_services))

        # LDAP enumeration
        ldap_services = [s for s in result.services if s.service.lower() in ("ldap", "ldaps", "globalcatldap")]
        if ldap_services:
            coros.append(self._enumerate_ldap(result, ldap_services))

        # FTP enumeration
        ftp_services = result.get_services_by_name("ftp")
        if ftp_services:
            coros.append(self._enumerate_ftp(result, ftp_services))

        # Redis enumeration
        redis_services = result.get_services_by_name("redis")
        if redis_services:
            coros.append(self._enumerate_redis(result, redis_services))

        # Elasticsearch enumeration
        es_services = [s for s in result.services if "elastic" in s.service.lower()]
        if es_services:
            coros.append(self._enumerate_elasticsearch(result, es_services))

        # Docker/K8s API checks
        docker_services = [s for s in result.services if s.port in (2375, 2376, 6443, 10250, 10255, 30000)]
        if docker_services:
            coros.append(self._enumerate_docker_k8s(result, docker_services))

        # RDP enumeration
        rdp_services = [s for s in result.services if s.service.lower() in ("ms-wbt-server", "rdp", "terminal-server")]
        if rdp_services:
            coros.append(self._enumerate_rdp(result, rdp_services))

        # --- Phase 3: additive enumerators (TLS / SMTP / DB / spider / OSINT) ---
        # Gated behind ``extended_enumerators`` (dataclass default False;
        # ``from_config`` defaults True). When off, enumerate_host behaves
        # exactly as before — the new coroutines never run, so existing tests
        # that mock only the original nine enumerators are unaffected.
        if getattr(self._config, "extended_enumerators", False):
            # TLS deep cert enumeration on TLS-likely ports.
            _TLS_LIKELY_PORTS = {443, 8443, 993, 995, 465, 636}
            tls_services = [
                s for s in result.services
                if s.port in _TLS_LIKELY_PORTS
                or s.service.lower() in ("https", "imaps", "pop3s", "smtps", "ldaps", "ftps")
            ]
            if tls_services:
                coros.append(self._enumerate_tls(result, tls_services))

            # SMTP banner / capability enumeration.
            smtp_services = [
                s for s in result.services
                if s.service.lower() in ("smtp", "smtps") or s.port in (25, 465, 587)
            ]
            if smtp_services:
                coros.append(self._enumerate_smtp(result, smtp_services))

            # Database banner enumeration.
            _DB_PORTS = {3306, 5432, 1433, 27017, 6379, 1521}
            _DB_SERVICE_NAMES = {
                "mysql", "postgresql", "mssql", "mongod", "mongodb", "redis", "oracle",
                "oracle-tns", "ms-sql-s",
            }
            db_services = [
                s for s in result.services
                if s.port in _DB_PORTS or s.service.lower() in _DB_SERVICE_NAMES
            ]
            if db_services:
                coros.append(self._enumerate_db(result, db_services))

            # Bounded web spider on http/https services.
            web_spider_services = [
                s for s in result.services if s.service.lower() in ("http", "https", "http-proxy")
            ]
            if web_spider_services:
                coros.append(self._enumerate_web_spider(result, web_spider_services))

            # Passive OSINT — target-level (run once per host, not per service).
            coros.append(self._enumerate_osint(result, []))

        # --- Phase: extended depth enumerators (each gated by its own flag) ---
        web_services = [s for s in result.services if s.service.lower() in ("http", "https", "http-proxy")]
        if getattr(self._config, "subdomain_enum", False):
            coros.append(self._enumerate_subdomains(result, web_services))
        if getattr(self._config, "vhost_discovery", False):
            coros.append(self._enumerate_vhosts(result, web_services))
        if getattr(self._config, "waf_fingerprint", False):
            coros.append(self._enumerate_waf(result, web_services))
        if getattr(self._config, "asn_whois", False):
            coros.append(self._enumerate_asn_whois(result, []))
        if getattr(self._config, "cloud_metadata_probe", False):
            coros.append(self._enumerate_cloud_metadata(result, []))
        if getattr(self._config, "snmp_enum", False):
            coros.append(self._enumerate_snmp(result, []))
        if getattr(self._config, "dns_zone_transfer", False):
            coros.append(self._enumerate_dns_zone_transfer(result, []))

        # Run secondary enumeration with concurrency limit
        if coros:
            semaphore = asyncio.Semaphore(self._config.max_concurrent_secondary)

            async def _run(coro: Coroutine[Any, Any, HostReconResult]) -> HostReconResult:
                async with semaphore:
                    return await coro

            results = await asyncio.gather(*[_run(c) for c in coros], return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    logger.warning(f"Secondary enumeration task failed: {r}")
                    result.errors.append(str(r))

        return result

    async def _enumerate_http(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate HTTP/HTTPS services with multiple tools."""
        logger.info(f"Starting HTTP enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port
            scheme = "https" if svc.service.lower() == "https" or port in (443, 8443) else "http"
            base_url = f"{scheme}://{result.target_ip}:{port}"

            # 1. Nikto scan
            if ToolAvailability.check(self._config.nikto_path):
                cmd = [
                    self._config.nikto_path,
                    "-h", base_url,
                    "-C", "all",
                    "-o", "-",  # Output to stdout
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=300,
                    max_retries=1,
                )
                if success:
                    svc.scripts["nikto"] = stdout[:5000]
                    result.evidence_refs.append(f"nikto:{port}")
                else:
                    result.warnings.append(f"Nikto failed on port {port}: {stderr[:200]}")

            # 2. Feroxbuster directory enumeration
            if ToolAvailability.check(self._config.feroxbuster_path):
                cmd = [
                    self._config.feroxbuster_path,
                    "-u", base_url,
                    "-w", self._config.wordlist_path,
                    "-q",  # Quiet mode
                    "--json",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=300,
                    max_retries=1,
                )
                if success:
                    svc.scripts["feroxbuster"] = stdout[:5000]
                    result.evidence_refs.append(f"feroxbuster:{port}")
                else:
                    result.warnings.append(f"Feroxbuster failed on port {port}: {stderr[:200]}")

            # 3. Gobuster fallback
            elif ToolAvailability.check(self._config.gobuster_path):
                cmd = [
                    self._config.gobuster_path,
                    "dir",
                    "-u", base_url,
                    "-w", self._config.wordlist_path,
                    "-q",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=300,
                    max_retries=1,
                )
                if success:
                    svc.scripts["gobuster"] = stdout[:5000]
                    result.evidence_refs.append(f"gobuster:{port}")

            # 4. Nuclei scan
            if ToolAvailability.check(self._config.nuclei_path):
                cmd = [
                    self._config.nuclei_path,
                    "-u", base_url,
                    "-s", "critical,high,medium",
                    "-json",
                    "-silent",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=300,
                    max_retries=1,
                )
                if success:
                    svc.scripts["nuclei"] = stdout[:5000]
                    result.evidence_refs.append(f"nuclei:{port}")

            # 5. Technology fingerprinting with curl
            if ToolAvailability.check(self._config.curl_path):
                cmd = [
                    self._config.curl_path,
                    "-sI", "-L",
                    "--max-time", "10",
                    "--connect-timeout", "5",
                    base_url,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=15,
                    max_retries=1,
                )
                if success:
                    svc.scripts["http_headers"] = stdout[:2000]
                    # Extract technologies from headers
                    techs = self._extract_technologies(stdout)
                    svc.technologies = techs

        return result

    async def _enumerate_ssh(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate SSH services: version, weak ciphers, CVE checks."""
        logger.info(f"Starting SSH enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port

            # 1. SSH version and cipher enumeration
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
                    result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=60,
                    max_retries=1,
                )
                if success:
                    svc.scripts["ssh_enum"] = stdout[:3000]
                    result.evidence_refs.append(f"ssh_enum:{port}")

                    # Check for weak algorithms
                    weak_ciphers = ["arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "rc4"]
                    for cipher in weak_ciphers:
                        if cipher in stdout.lower():
                            result.warnings.append(f"Weak SSH cipher detected on port {port}: {cipher}")

            # 2. Check for default credentials with Hydra (only if explicitly enabled)
            # Note: This is gated by risk profile, we'll add the script but not auto-run
            svc.scripts["hydra_ready"] = f"hydra -t 4 -V -f -L users.txt -P passwords.txt ssh://{result.target_ip}:{port}"

            # 3. Map OpenSSH version to known CVEs
            version = svc.version.lower()
            cves = self._map_openssh_cves(version)
            if cves:
                svc.scripts["openssh_cves"] = json.dumps(cves)
                result.warnings.append(f"OpenSSH {svc.version} may be vulnerable to: {', '.join(cves)}")

        return result

    async def _enumerate_smb(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate SMB services: shares, users, null sessions."""
        logger.info(f"Starting SMB enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port

            # 1. enum4linux
            if ToolAvailability.check(self._config.enum4linux_path):
                cmd = [
                    self._config.enum4linux_path,
                    "-a", result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=120,
                    max_retries=1,
                )
                if success:
                    svc.scripts["enum4linux"] = stdout[:5000]
                    result.evidence_refs.append(f"enum4linux:{port}")

                    # Check for null session
                    if "null session" in stdout.lower() or "mapping: ok" in stdout.lower():
                        result.warnings.append(f"SMB null session possible on {result.target_ip}:{port}")

            # 2. smbclient share enumeration
            if ToolAvailability.check(self._config.smbclient_path):
                cmd = [
                    self._config.smbclient_path,
                    "-L", f"//{result.target_ip}/",
                    "-N",  # No password (null session)
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=30,
                    max_retries=1,
                )
                if success:
                    svc.scripts["smbclient_shares"] = stdout[:3000]
                    result.evidence_refs.append(f"smbclient:{port}")

                    # Check for accessible shares
                    if "Sharename" in stdout:
                        shares = self._extract_smb_shares(stdout)
                        svc.scripts["smb_shares"] = json.dumps(shares)
                        if shares:
                            result.warnings.append(f"Accessible SMB shares on {result.target_ip}:{port}: {', '.join(shares[:5])}")

            # 3. Nmap SMB scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-*",
                    result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=120,
                    max_retries=1,
                )
                if success:
                    svc.scripts["nmap_smb"] = stdout[:5000]
                    result.evidence_refs.append(f"nmap_smb:{port}")

        return result

    async def _enumerate_ldap(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate LDAP services: anonymous bind, directory extraction."""
        logger.info(f"Starting LDAP enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port
            protocol = "ldaps" if port == 636 or svc.service.lower() == "ldaps" else "ldap"

            # 1. Anonymous bind test with ldapsearch
            if ToolAvailability.check(self._config.ldapsearch_path):
                cmd = [
                    self._config.ldapsearch_path,
                    "-x",  # Simple authentication
                    "-H", f"{protocol}://{result.target_ip}:{port}",
                    "-b", "dc=example,dc=com",  # Base DN guess
                    "-s", "base",
                    "(objectClass=*)",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=30,
                    max_retries=1,
                )
                if success:
                    svc.scripts["ldap_anonymous"] = stdout[:3000]
                    result.evidence_refs.append(f"ldap_anon:{port}")
                    result.warnings.append(f"LDAP anonymous bind succeeded on {result.target_ip}:{port}")
                elif "invalid credentials" not in stderr.lower():
                    # Other errors might indicate interesting behavior
                    svc.scripts["ldap_error"] = stderr[:1000]

            # 2. Nmap LDAP scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "ldap-search,ldap-rootdse",
                    result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=60,
                    max_retries=1,
                )
                if success:
                    svc.scripts["nmap_ldap"] = stdout[:3000]
                    result.evidence_refs.append(f"nmap_ldap:{port}")

        return result

    async def _enumerate_ftp(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate FTP services: anonymous login, version checks."""
        logger.info(f"Starting FTP enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port

            # Test anonymous login with curl
            if ToolAvailability.check(self._config.curl_path):
                cmd = [
                    self._config.curl_path,
                    "-v", f"ftp://anonymous:anonymous@{result.target_ip}:{port}/",
                    "--max-time", "10",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=15,
                    max_retries=1,
                )
                if success:
                    svc.scripts["ftp_anonymous"] = "Anonymous login succeeded"
                    result.evidence_refs.append(f"ftp_anon:{port}")
                    result.warnings.append(f"FTP anonymous login enabled on {result.target_ip}:{port}")
                else:
                    svc.scripts["ftp_anonymous"] = f"Anonymous login failed: {stderr[:500]}"

            # Nmap FTP scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie",
                    result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=60,
                    max_retries=1,
                )
                if success:
                    svc.scripts["nmap_ftp"] = stdout[:3000]
                    result.evidence_refs.append(f"nmap_ftp:{port}")

        return result

    async def _enumerate_redis(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate Redis services: unauth check, info extraction.

        Talks directly to ``nc`` via ``asyncio.create_subprocess_exec`` (argv
        list, no shell) and writes ``INFO\\n`` to its stdin. The previous
        implementation built a ``bash -c "echo 'INFO' | nc ..."`` f-string,
        which was a shell-injection sink via ``result.target_ip``/``port``.
        ``validate_ipv4`` is also enforced as defense-in-depth before any
        subprocess is spawned.
        """
        logger.info(f"Starting Redis enumeration on {result.target_ip}")

        # Defense-in-depth: refuse non-IP/non-domain targets so a malformed
        # target_ip can never reach a subprocess argument list. A domain is
        # accepted (nc/redis-cli resolve it); a bare garbage string is refused.
        if not (validate_ipv4(result.target_ip) or is_fqdn(result.target_ip)):
            logger.warning(
                f"Skipping Redis enumeration: invalid target {result.target_ip!r}"
            )
            return result

        for svc in services:
            port = svc.port

            try:
                proc = await asyncio.create_subprocess_exec(
                    "nc", "-w", "3", result.target_ip, str(port),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                logger.warning(f"nc not available for Redis enumeration on port {port}: {exc}")
                continue

            try:
                stdout_bytes, _ = await asyncio.wait_for(
                    proc.communicate(input=b"INFO\n"), timeout=10
                )
            except asyncio.TimeoutError:
                await _kill_process(proc)
                continue
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(f"Redis enumeration failed on port {port}: {exc}")
                await _kill_process(proc)
                continue

            stdout2 = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            if "redis_version" in stdout2:
                svc.scripts["redis_info"] = stdout2[:3000]
                result.evidence_refs.append(f"redis_info:{port}")
                result.warnings.append(f"Redis unauthenticated access on {result.target_ip}:{port}")

        return result

    async def _enumerate_elasticsearch(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate Elasticsearch: cluster info, indices."""
        logger.info(f"Starting Elasticsearch enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port
            base_url = f"http://{result.target_ip}:{port}"

            # Cluster info
            if ToolAvailability.check(self._config.curl_path):
                cmd = [
                    self._config.curl_path,
                    "-s", f"{base_url}/_cluster/health",
                    "--max-time", "10",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=15,
                    max_retries=1,
                )
                if success:
                    svc.scripts["es_cluster"] = stdout[:3000]
                    result.evidence_refs.append(f"es_cluster:{port}")

                # Index enumeration
                cmd = [
                    self._config.curl_path,
                    "-s", f"{base_url}/_cat/indices?v",
                    "--max-time", "10",
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=15,
                    max_retries=1,
                )
                if success:
                    svc.scripts["es_indices"] = stdout[:3000]
                    result.evidence_refs.append(f"es_indices:{port}")
                    if stdout.strip():
                        result.warnings.append(f"Elasticsearch indices exposed on {result.target_ip}:{port}")

        return result

    async def _enumerate_docker_k8s(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate Docker and Kubernetes exposed APIs."""
        logger.info(f"Starting Docker/K8s enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port

            if port == 2375 or port == 2376:
                # Docker API
                scheme = "https" if port == 2376 else "http"
                if ToolAvailability.check(self._config.curl_path):
                    cmd = [
                        self._config.curl_path,
                        "-s", f"{scheme}://{result.target_ip}:{port}/version",
                        "--max-time", "10",
                    ]
                    success, stdout, stderr, _ = await run_command(
                        cmd,
                        timeout=15,
                        max_retries=1,
                    )
                    if success and "Version" in stdout:
                        svc.scripts["docker_api"] = stdout[:2000]
                        result.evidence_refs.append(f"docker_api:{port}")
                        result.warnings.append(f"Docker API exposed without auth on {result.target_ip}:{port}")

            elif port == 6443:
                # Kubernetes API
                if ToolAvailability.check(self._config.curl_path):
                    cmd = [
                        self._config.curl_path,
                        "-s", "-k",
                        f"https://{result.target_ip}:{port}/api",
                        "--max-time", "10",
                    ]
                    success, stdout, stderr, _ = await run_command(
                        cmd,
                        timeout=15,
                        max_retries=1,
                    )
                    if success and ("versions" in stdout or "kind" in stdout):
                        svc.scripts["k8s_api"] = stdout[:2000]
                        result.evidence_refs.append(f"k8s_api:{port}")
                        result.warnings.append(f"Kubernetes API exposed on {result.target_ip}:{port}")

            elif port in (10250, 10255):
                # Kubelet API
                if ToolAvailability.check(self._config.curl_path):
                    cmd = [
                        self._config.curl_path,
                        "-s", "-k",
                        f"https://{result.target_ip}:{port}/pods",
                        "--max-time", "10",
                    ]
                    success, stdout, stderr, _ = await run_command(
                        cmd,
                        timeout=15,
                        max_retries=1,
                    )
                    if success and "items" in stdout:
                        svc.scripts["kubelet_pods"] = stdout[:2000]
                        result.evidence_refs.append(f"kubelet:{port}")
                        result.warnings.append(f"Kubelet API exposed pods on {result.target_ip}:{port}")

        return result

    async def _enumerate_rdp(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate RDP services: NLA check, encryption level."""
        logger.info(f"Starting RDP enumeration on {result.target_ip}")

        for svc in services:
            port = svc.port

            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "rdp-enum-encryption,rdp-vuln-ms12-020",
                    result.target_ip,
                ]
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=60,
                    max_retries=1,
                )
                if success:
                    svc.scripts["rdp_enum"] = stdout[:3000]
                    result.evidence_refs.append(f"rdp_enum:{port}")

                    if "NLA: Disabled" in stdout:
                        result.warnings.append(f"RDP NLA disabled on {result.target_ip}:{port}")

        return result

    # -----------------------------------------------------------------------
    # Phase 3 Round 2 additive enumerators
    # (TLS / SMTP / DB / web spider / passive OSINT). Each targets ONLY the
    # single authorized ``result.target_ip`` and is routed through
    # ``run_command`` (so tests can mock it) or the bounded Round 1 helpers.
    # -----------------------------------------------------------------------

    async def _enumerate_tls(
        self, result: HostReconResult, services: list[ServiceInfo]
    ) -> HostReconResult:
        """Deep TLS certificate enumeration on TLS-likely ports.

        Runs ``nmap --script ssl-cert,ssl-enum`` on each TLS-likely port and
        parses the output with :func:`tools.recon_enrichers.parse_tls_info`,
        populating ``svc.ssl_info``. Mirrors how ``_enumerate_ssh`` runs a
        targeted nmap script.
        """
        from tools.recon_enrichers import parse_tls_info

        logger.info(f"Starting TLS enumeration on {result.target_ip}")
        for svc in services:
            port = svc.port
            if not ToolAvailability.check(self._config.nmap_path):
                continue
            cmd = [
                self._config.nmap_path,
                "-p", str(port),
                "--script", "ssl-cert,ssl-enum",
                "-Pn",
                result.target_ip,
            ]
            try:
                success, stdout, stderr, _ = await run_command(
                    cmd, timeout=60, max_retries=1,
                )
            except Exception as exc:
                result.warnings.append(f"TLS enum failed on port {port}: {exc}")
                continue
            if success and stdout:
                svc.ssl_info = parse_tls_info(stdout)
                svc.scripts["ssl_cert"] = stdout[:3000]
                result.evidence_refs.append(f"ssl_cert:{port}")
        return result

    async def _enumerate_smtp(
        self, result: HostReconResult, services: list[ServiceInfo]
    ) -> HostReconResult:
        """SMTP banner / capability enumeration on smtp-service ports.

        Runs ``nmap --script smtp-commands,smtp-open-relay`` and parses the
        banner with :func:`tools.recon_enrichers.parse_smtp_banner`, populating
        ``svc.smtp_info`` (server_software, supports_starttls, auth_methods).
        """
        from tools.recon_enrichers import parse_smtp_banner

        logger.info(f"Starting SMTP enumeration on {result.target_ip}")
        for svc in services:
            port = svc.port
            banner_text = ""
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "smtp-commands,smtp-open-relay",
                    "-Pn",
                    result.target_ip,
                ]
                try:
                    success, stdout, stderr, _ = await run_command(
                        cmd, timeout=60, max_retries=1,
                    )
                except Exception as exc:
                    result.warnings.append(f"SMTP enum failed on port {port}: {exc}")
                    continue
                if success and stdout:
                    banner_text = stdout
                    svc.scripts["smtp_commands"] = stdout[:3000]
                    result.evidence_refs.append(f"smtp_commands:{port}")
            if banner_text:
                svc.smtp_info = parse_smtp_banner(banner_text)
        return result

    async def _enumerate_db(
        self, result: HostReconResult, services: list[ServiceInfo]
    ) -> HostReconResult:
        """Database banner enumeration on mysql/postgres/mssql/mongo/redis/oracle.

        Runs a targeted ``nmap --script`` banner grab per port and parses with
        :func:`tools.recon_enrichers.parse_db_banner`, populating
        ``svc.db_info`` (db_type, version, auth_required).
        """
        from tools.recon_enrichers import parse_db_banner

        logger.info(f"Starting DB enumeration on {result.target_ip}")
        for svc in services:
            port = svc.port
            banner_text = ""
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p", str(port),
                    "--script", "banner,default",
                    "-Pn",
                    result.target_ip,
                ]
                try:
                    success, stdout, stderr, _ = await run_command(
                        cmd, timeout=60, max_retries=1,
                    )
                except Exception as exc:
                    result.warnings.append(f"DB enum failed on port {port}: {exc}")
                    continue
                if success and stdout:
                    banner_text = stdout
                    svc.scripts["db_banner"] = stdout[:3000]
                    result.evidence_refs.append(f"db_banner:{port}")
            if banner_text:
                svc.db_info = parse_db_banner(banner_text, service=svc.service)
        return result

    async def _enumerate_web_spider(
        self, result: HostReconResult, services: list[ServiceInfo]
    ) -> HostReconResult:
        """Bounded stdlib web spider on http/https services.

        Calls :func:`tools.recon_enrichers.http_spider` (a bounded BFS spider
        that connects ONLY to the single ``target_ip:port``) and appends each
        result dict to ``result.spider_results``. This is the one place a
        Round 1 function does network — it is bounded and targets only the
        single authorized host.
        """
        from tools.recon_enrichers import http_spider

        logger.info(f"Starting web spider on {result.target_ip}")
        for svc in services:
            port = svc.port
            scheme = (
                "https"
                if svc.service.lower() == "https" or port in (443, 8443)
                else "http"
            )
            try:
                spider = http_spider(
                    result.target_ip, port, scheme=scheme, max_pages=20
                )
            except Exception as exc:
                result.warnings.append(f"Web spider failed on port {port}: {exc}")
                continue
            if isinstance(spider, dict):
                result.spider_results.append(spider)
                result.evidence_refs.append(f"spider:{port}")
        return result

    async def _enumerate_osint(
        self, result: HostReconResult, services: list[ServiceInfo]
    ) -> HostReconResult:
        """Passive OSINT aggregation for the single target.

        Calls :func:`tools.recon_osint.run_osint` (PASSIVE ONLY: reverse DNS,
        DNS AAAA for IPv6, crt.sh certificate transparency, optional Shodan)
        about the single target and stores the returned dict in
        ``result.osint``; copies the ipv6 list into ``result.ipv6_addresses``.
        Wrapped in try/except so an OSINT failure never breaks the pipeline.
        Does NOT perform any active scan.
        """
        from tools.recon_osint import run_osint

        logger.info(f"Starting passive OSINT for {result.target_ip}")
        # Shodan is optional and gated on an API key carried on ReconConfig
        # (``recon.shodan_api_key`` / ``SHODAN_API_KEY`` env). Empty -> run_osint
        # skips Shodan (returns {"enabled": False, ...}).
        shodan_key = self._config.shodan_api_key
        try:
            osint = run_osint(
                result.target_ip,
                hostname=result.hostname or "",
                shodan_api_key=shodan_key,
            )
            if isinstance(osint, dict):
                result.osint = osint
                ipv6 = osint.get("ipv6_addresses") or []
                if isinstance(ipv6, list):
                    result.ipv6_addresses = [str(a) for a in ipv6 if isinstance(a, str)]
        except Exception as exc:
            # OSINT failure must never break the recon pipeline.
            result.warnings.append(f"OSINT failed for {result.target_ip}: {exc}")
        return result

    # -----------------------------------------------------------------------
    # Phase: extended depth enumerators (each gated by its own ReconConfig flag,
    # default OFF). All network I/O is injectable via ``fetch_fn`` (HTTP) /
    # ``run_fn`` (subprocess) so tests need no live network. Each writes its
    # key into ``result.extended`` and never raises out of the enumerator.
    # -----------------------------------------------------------------------

    @staticmethod
    def _stdlib_fetch(url: str, *, timeout: int = 15, method: str = "GET",
                      headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
        """Default HTTP fetch (urllib). Returns (status, headers, body)."""
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(200000).decode(errors="replace")
                return resp.status, dict(resp.headers.items()), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()) if e.headers else {}, (e.read(2000).decode(errors="replace") if e.fp else "")
        except Exception:
            return 0, {}, ""

    @staticmethod
    def _domain_of(hostname: str) -> str:
        """Best-effort registrable domain from a hostname (last 2 labels)."""
        if not hostname:
            return ""
        parts = [p for p in hostname.strip(".").split(".") if p]
        if len(parts) < 2:
            return ""
        return ".".join(parts[-2:])

    async def _enumerate_subdomains(self, result: HostReconResult, services: list, *, fetch_fn=None) -> HostReconResult:
        """Passive subdomain expansion via crt.sh (+ optional subfinder)."""
        try:
            domain = self._domain_of(result.hostname or "")
            if not domain:
                result.extended["subdomains"] = {"enabled": False, "note": "no hostname/domain to expand"}
                return result
            fetch = fetch_fn or self._stdlib_fetch
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            status, _hdr, body = fetch(url, timeout=20)
            subs: set[str] = set()
            if status == 200 and body:
                try:
                    for row in json.loads(body):
                        for nv in str(row.get("name_value", "")).splitlines():
                            for s in nv.split(","):
                                s = s.strip().lstrip("*.").strip()
                                if s and s.endswith(domain):
                                    subs.add(s)
                except Exception:
                    pass
            result.extended["subdomains"] = {"enabled": True, "domain": domain, "count": len(subs), "subdomains": sorted(subs)[:500]}
            result.evidence_refs.append(f"crt.sh:{domain}")
        except Exception as exc:
            result.warnings.append(f"subdomain_enum failed for {result.target_ip}: {exc}")
        return result

    async def _enumerate_vhosts(self, result: HostReconResult, services: list, *, fetch_fn=None) -> HostReconResult:
        """Host-header rotation against web ports to discover virtual hosts."""
        try:
            domain = self._domain_of(result.hostname or "")
            if not domain or not services:
                result.extended["vhosts"] = {"enabled": False, "note": "no web service or hostname"}
                return result
            fetch = fetch_fn or self._stdlib_fetch
            words = ["www", "mail", "admin", "api", "dev", "staging", "test", "vpn", "portal", "git", "jenkins", "jira", "internal"]
            found = []
            for svc in services:
                scheme = "https" if svc.port in (443, 8443) else "http"
                base = f"{scheme}://{result.target_ip}:{svc.port}/"
                _s, _h, base_body = fetch(base, timeout=10)
                for w in words:
                    host = f"{w}.{domain}"
                    s, _h, body = fetch(base, timeout=10, headers={"Host": host})
                    if s and (s not in (404,) and (len(body) != len(base_body))):
                        found.append({"vhost": host, "port": svc.port, "status": s, "length": len(body)})
            result.extended["vhosts"] = {"enabled": True, "count": len(found), "vhosts": found}
            result.evidence_refs.append(f"vhosts:{domain}")
        except Exception as exc:
            result.warnings.append(f"vhost_discovery failed for {result.target_ip}: {exc}")
        return result

    async def _enumerate_waf(self, result: HostReconResult, services: list, *, fetch_fn=None) -> HostReconResult:
        """WAF/CDN fingerprinting via header + cookie heuristics (+ wafw00f)."""
        try:
            if not services:
                result.extended["waf"] = {"enabled": False, "note": "no web service"}
                return result
            fetch = fetch_fn or self._stdlib_fetch
            _SIGS = {
                "Cloudflare": (lambda h: "cf-ray" in h or h.get("server", "").lower() == "cloudflare"),
                "Akamai": (lambda h: "x-akamai" in h or "akamai" in h.get("server", "").lower()),
                "AWS CloudFront": (lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("server", "").lower()),
                "Sucuri": (lambda h: "sucuri" in h.get("server", "").lower() or "x-sucuri-id" in h),
                "Imperva Incapsula": (lambda h: "incap" in h.get("x-iinfo", "").lower() or "incapsula" in h.get("server", "").lower()),
                "F5 BIG-IP": (lambda h: "bigipserver" in str(h.get("set-cookie", "")).lower()),
            }
            detected = []
            for svc in services:
                scheme = "https" if svc.port in (443, 8443) else "http"
                url = f"{scheme}://{result.target_ip}:{svc.port}/"
                _s, hdrs, _b = fetch(url, timeout=10)
                low = {k.lower(): str(v) for k, v in hdrs.items()}
                for name, test in _SIGS.items():
                    try:
                        if test(low):
                            detected.append({"waf": name, "port": svc.port})
                    except Exception:
                        pass
            result.extended["waf"] = {"enabled": True, "detected": detected}
            result.evidence_refs.append("waf:fingerprint")
        except Exception as exc:
            result.warnings.append(f"waf_fingerprint failed for {result.target_ip}: {exc}")
        return result

    async def _enumerate_asn_whois(self, result: HostReconResult, services: list, *, fetch_fn=None) -> HostReconResult:
        """ASN / WHOIS via RDAP (arin.net) HTTPS lookup of the target IP."""
        try:
            fetch = fetch_fn or self._stdlib_fetch
            url = f"https://rdap.arin.net/registry/ip/{result.target_ip}"
            status, _h, body = fetch(url, timeout=15)
            info: dict[str, Any] = {"enabled": True, "ip": result.target_ip}
            if status == 200 and body:
                try:
                    data = json.loads(body)
                    info["network_name"] = data.get("name", "")
                    info["cidr"] = (data.get("cidr0_cidrs") or [{}])[0].get("v4prefix", "")
                    ents = data.get("entities", [])
                    if ents:
                        vcard = ents[0].get("vcardArray", [])
                        if vcard and len(vcard) > 1:
                            for entry in vcard[1]:
                                if entry and entry[0] == "fn":
                                    info["org"] = entry[3]
                    info["raw_keys"] = list(data.keys())
                except Exception:
                    info["parse_error"] = "RDAP JSON parse failed"
            else:
                info["error"] = f"RDAP returned status {status}"
            result.extended["asn"] = info
            result.evidence_refs.append(f"rdap:{result.target_ip}")
        except Exception as exc:
            result.warnings.append(f"asn_whois failed for {result.target_ip}: {exc}")
        return result

    async def _enumerate_cloud_metadata(self, result: HostReconResult, services: list, *, fetch_fn=None) -> HostReconResult:
        """Probe the link-local cloud metadata endpoint (169.254.169.254).

        NOTE: this queries the *operator* box's IMDS from the operator's
        vantage point (recon runs pre-foothold). It records whether IMDS is
        reachable at all -- an OPSEC signal that the operator box itself is
        cloud-hosted and its metadata is exposed. Re-run from the target after
        a foothold to probe the *target's* IMDS via lateral_exec.
        """
        try:
            fetch = fetch_fn or self._stdlib_fetch
            base = "http://169.254.169.254/latest/meta-data/"
            # IMDSv1
            s1, _h, body1 = fetch(base, timeout=4)
            info: dict[str, Any] = {"enabled": True, "imdsv1_reachable": s1 == 200}
            # IMDSv2 (PUT a session token, then GET with it)
            try:
                s2, _h2, token = fetch("http://169.254.169.254/latest/api/token", timeout=4, method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
                info["imdsv2_reachable"] = False
                if s2 == 200 and token:
                    s3, _h3, _b3 = fetch(base, timeout=4, headers={"X-aws-ec2-metadata-token": token.strip()})
                    info["imdsv2_reachable"] = s3 == 200
            except Exception:
                info["imdsv2_reachable"] = False
            if s1 == 200 and body1:
                info["instance_id_hint"] = body1.strip().splitlines()[0][:80]
            info["note"] = ("operator-box IMDS reachable -- your own metadata is exposed; re-run from the target after a foothold for target IMDS")
            result.extended["cloud_metadata"] = info
            result.evidence_refs.append("imds:probe")
        except Exception as exc:
            result.warnings.append(f"cloud_metadata_probe failed: {exc}")
        return result

    async def _enumerate_snmp(self, result: HostReconResult, services: list, *, run_fn=None) -> HostReconResult:
        """SNMP enumeration via snmpwalk -v2c -c public <target> (community 'public')."""
        try:
            run = run_fn or subprocess.run
            bin_ = shutil.which("snmpwalk") or "snmpwalk"
            proc = run([bin_, "-v2c", "-c", "public", result.target_ip], capture_output=True, text=True, timeout=30)
            out = getattr(proc, "stdout", "") or ""
            info: dict[str, Any] = {"enabled": True, "tool": bin_}
            info["returncode"] = getattr(proc, "returncode", None)
            sysdescr = ""
            for line in out.splitlines():
                if "sysDescr" in line:
                    sysdescr = line.split(":", 2)[-1].strip() if ":" in line else line
                    break
            info["sysDescr"] = sysdescr
            info["output_head"] = out[:1500]
            result.extended["snmp"] = info
            if sysdescr and not result.os_name:
                low = sysdescr.lower()
                if "linux" in low:
                    result.os_family = "linux"
                elif "windows" in low:
                    result.os_family = "windows"
                result.os_name = sysdescr[:120]
            result.evidence_refs.append("snmpwalk:public")
        except Exception as exc:
            result.warnings.append(f"snmp_enum failed for {result.target_ip}: {exc}")
        return result

    async def _enumerate_dns_zone_transfer(self, result: HostReconResult, services: list, *, run_fn=None) -> HostReconResult:
        """DNS AXFR via `dig axfr @<target_ip> <zone>` (zone inferred from hostname)."""
        try:
            domain = self._domain_of(result.hostname or "")
            zone = domain or "localhost"
            run = run_fn or subprocess.run
            bin_ = shutil.which("dig") or "dig"
            proc = run([bin_, "axfr", f"@{result.target_ip}", zone], capture_output=True, text=True, timeout=30)
            out = getattr(proc, "stdout", "") or ""
            info: dict[str, Any] = {"enabled": True, "tool": bin_, "zone": zone, "returncode": getattr(proc, "returncode", None)}
            records = []
            for line in out.splitlines():
                if line and not line.startswith(";") and "\t" in line:
                    records.append(line.strip())
            info["record_count"] = len(records)
            info["records"] = records[:500]
            if not records:
                info["note"] = "no zone records (AXFR refused or no matching zone)"
            result.extended["dns_zone"] = info
            result.evidence_refs.append(f"dns_axfr:{zone}")
        except Exception as exc:
            result.warnings.append(f"dns_zone_transfer failed for {result.target_ip}: {exc}")
        return result

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_technologies(headers: str) -> list[str]:
        """Extract server technologies from HTTP headers."""
        techs: list[str] = []
        patterns = {
            "Server": r"Server:\s*(.+)",
            "X-Powered-By": r"X-Powered-By:\s*(.+)",
            "X-AspNet-Version": r"X-AspNet-Version:\s*(.+)",
            "X-Generator": r"X-Generator:\s*(.+)",
        }
        for name, pattern in patterns.items():
            match = re.search(pattern, headers, re.IGNORECASE)
            if match:
                techs.append(f"{name}: {match.group(1).strip()}")
        return techs

    @staticmethod
    def _extract_smb_shares(output: str) -> list[str]:
        """Extract SMB share names from smbclient output."""
        shares: list[str] = []
        for line in output.split("\n"):
            if line.strip().startswith("|") or line.strip().startswith("  "):
                parts = line.strip().strip("|").strip().split()
                if parts and parts[0] not in ("Sharename", "--------", "", "IPC$"):
                    shares.append(parts[0])
        return shares

    @staticmethod
    def _map_openssh_cves(version: str) -> list[str]:
        """Map OpenSSH version string to known critical CVEs."""
        cves: list[str] = []
        if not version:
            return cves

        # Extract version number
        ver_match = re.search(r"openssh[/_\-\s]?(\d+\.\d+(?:p\d+)?)", version, re.IGNORECASE)
        if not ver_match:
            return cves

        ver_str = ver_match.group(1)
        try:
            major, minor_patch = ver_str.split(".", 1)
            major = int(major)
            if "p" in minor_patch:
                minor, patch = minor_patch.split("p", 1)
                minor = int(minor)
                patch = int(patch)
            else:
                minor = int(minor_patch)
                patch = 0
        except ValueError:
            return cves

        # CVE-2024-6387 (regreSSHion) - OpenSSH < 4.4p1 (if not patched for CVE-2006-5051)
        # and 8.5p1 <= version < 9.8p1
        if (major < 4 or (major == 4 and minor < 4) or
            (major == 8 and minor >= 5) or
            (major == 9 and minor < 8)):
            cves.append("CVE-2024-6387 (regreSSHion)")

        # CVE-2023-38408 - OpenSSH < 9.3p2
        if major < 9 or (major == 9 and minor < 3) or (major == 9 and minor == 3 and patch < 2):
            cves.append("CVE-2023-38408")

        # CVE-2023-28531 - OpenSSH < 9.3p1
        if major < 9 or (major == 9 and minor < 3):
            cves.append("CVE-2023-28531")

        # CVE-2021-41617 - OpenSSH 6.2 - 8.8
        if 6 <= major < 8 or (major == 8 and minor <= 8):
            cves.append("CVE-2021-41617")

        # CVE-2020-15778 - OpenSSH 8.3 and earlier (scp vulnerability)
        if major < 8 or (major == 8 and minor <= 3):
            cves.append("CVE-2020-15778")

        return cves


# ---------------------------------------------------------------------------
# Main reconnaissance orchestrator
# ---------------------------------------------------------------------------

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
                attack_surface["high_value_targets"].append({
                    "port": svc.port,
                    "service": svc.service,
                    "version": svc.version,
                    "cves": svc.scripts.get("openssh_cves", []),
                })
                attack_surface["credential_targets"].append({
                    "port": svc.port,
                    "service": svc.service,
                    "version": svc.version,
                })

            # Web targets
            if name in ("http", "https", "http-proxy"):
                attack_surface["web_targets"].append({
                    "port": svc.port,
                    "service": svc.service,
                    "technologies": svc.scripts.get("http_headers", ""),
                    "directories": svc.scripts.get("feroxbuster", ""),
                    "vulns": svc.scripts.get("nuclei", ""),
                })

            # Lateral movement
            if name in ("smb", "microsoft-ds", "ldap", "ldaps"):
                attack_surface["lateral_movement_targets"].append({
                    "port": svc.port,
                    "service": svc.service,
                    "version": svc.version,
                })

            # Privilege escalation hints
            if "docker" in name or svc.port in (2375, 2376, 10250):
                attack_surface["privilege_escalation_hints"].append({
                    "port": svc.port,
                    "service": svc.service,
                    "hint": "Container/Docker access may allow privilege escalation",
                })

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
            {"name": mod.name, "score": score, "description": mod.description}
            for score, mod in scored_modules[:10]
        ]

        return attack_surface
