"""Recon secondary enumeration — extracted from tools.recon_pipeline.

Canonical source for ``SecondaryEnumerator``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from typing import Any, Coroutine

from tools.logging_setup import get_logger
from tools.recon.config import HostReconResult, ReconConfig, ServiceInfo, ToolAvailability
from tools.recon.scanner import _kill_process, run_command
from tools.validation_utils import is_fqdn, is_subdomain_of, validate_ipv4

logger = get_logger()

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
        smb_services = [
            s for s in result.services if s.service.lower() in ("microsoft-ds", "smb", "netbios-ssn", "netbios-ns")
        ]
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
                s
                for s in result.services
                if s.port in _TLS_LIKELY_PORTS
                or s.service.lower() in ("https", "imaps", "pop3s", "smtps", "ldaps", "ftps")
            ]
            if tls_services:
                coros.append(self._enumerate_tls(result, tls_services))

            # SMTP banner / capability enumeration.
            smtp_services = [
                s for s in result.services if s.service.lower() in ("smtp", "smtps") or s.port in (25, 465, 587)
            ]
            if smtp_services:
                coros.append(self._enumerate_smtp(result, smtp_services))

            # Database banner enumeration.
            _DB_PORTS = {3306, 5432, 1433, 27017, 6379, 1521}
            _DB_SERVICE_NAMES = {
                "mysql",
                "postgresql",
                "mssql",
                "mongod",
                "mongodb",
                "redis",
                "oracle",
                "oracle-tns",
                "ms-sql-s",
            }
            db_services = [s for s in result.services if s.port in _DB_PORTS or s.service.lower() in _DB_SERVICE_NAMES]
            if db_services:
                coros.append(self._enumerate_db(result, db_services))

            # Bounded web spider on http/https services.
            web_spider_services = [s for s in result.services if s.service.lower() in ("http", "https", "http-proxy")]
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

        # ponytail: per-service fan-out + intra-service tool fan-out. Nikto /
        # feroxbuster / nuclei / curl are independent read-only probes; running
        # them serially costs up to 300s x 3 per service. Mutations touch
        # distinct svc.scripts keys; evidence/warning appends are
        # single-threaded asyncio appends (no true races).
        await asyncio.gather(*(self._enumerate_http_service(result, svc) for svc in services))
        return result

    async def _enumerate_http_service(self, result: HostReconResult, svc: ServiceInfo) -> None:
        port = svc.port
        scheme = "https" if svc.service.lower() == "https" or port in (443, 8443) else "http"
        base_url = f"{scheme}://{result.target_ip}:{port}"

        async def _nikto() -> None:
            # 1. Nikto scan
            if ToolAvailability.check(self._config.nikto_path):
                cmd = [
                    self._config.nikto_path,
                    "-h",
                    base_url,
                    "-C",
                    "all",
                    "-o",
                    "-",  # Output to stdout
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

        async def _dirbuster() -> None:
            # 2. Feroxbuster directory enumeration
            if ToolAvailability.check(self._config.feroxbuster_path):
                cmd = [
                    self._config.feroxbuster_path,
                    "-u",
                    base_url,
                    "-w",
                    self._config.wordlist_path,
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
                    "-u",
                    base_url,
                    "-w",
                    self._config.wordlist_path,
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

        async def _nuclei() -> None:
            # 4. Nuclei scan
            if ToolAvailability.check(self._config.nuclei_path):
                cmd = [
                    self._config.nuclei_path,
                    "-u",
                    base_url,
                    "-s",
                    "critical,high,medium",
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

        async def _headers() -> None:
            # 5. Technology fingerprinting with curl
            if ToolAvailability.check(self._config.curl_path):
                cmd = [
                    self._config.curl_path,
                    "-sI",
                    "-L",
                    "--max-time",
                    "10",
                    "--connect-timeout",
                    "5",
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

        await asyncio.gather(_nikto(), _dirbuster(), _nuclei(), _headers())

    async def _enumerate_ssh(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate SSH services: version, weak ciphers, CVE checks."""
        logger.info(f"Starting SSH enumeration on {result.target_ip}")

        # ponytail: per-service fan-out; the nmap probe is the only slow
        # subprocess here, the rest is local computation.
        await asyncio.gather(*(self._enumerate_ssh_service(result, svc) for svc in services))
        return result

    async def _enumerate_ssh_service(self, result: HostReconResult, svc: ServiceInfo) -> None:
        port = svc.port

        # 1. SSH version and cipher enumeration
        if ToolAvailability.check(self._config.nmap_path):
            cmd = [
                self._config.nmap_path,
                "-p",
                str(port),
                "--script",
                "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
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

    async def _enumerate_smb(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate SMB services: shares, users, null sessions."""
        logger.info(f"Starting SMB enumeration on {result.target_ip}")

        # ponytail: per-service fan-out + intra-service tool fan-out
        # (enum4linux 120s + smbclient 30s + nmap 120s serial -> ~max).
        await asyncio.gather(*(self._enumerate_smb_service(result, svc) for svc in services))
        return result

    async def _enumerate_smb_service(self, result: HostReconResult, svc: ServiceInfo) -> None:
        port = svc.port

        async def _enum4linux() -> None:
            # 1. enum4linux
            if ToolAvailability.check(self._config.enum4linux_path):
                cmd = [
                    self._config.enum4linux_path,
                    "-a",
                    result.target_ip,
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

        async def _shares() -> None:
            # 2. smbclient share enumeration
            if ToolAvailability.check(self._config.smbclient_path):
                cmd = [
                    self._config.smbclient_path,
                    "-L",
                    f"//{result.target_ip}/",
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
                            result.warnings.append(
                                f"Accessible SMB shares on {result.target_ip}:{port}: {', '.join(shares[:5])}"
                            )

        async def _nmap_smb() -> None:
            # 3. Nmap SMB scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p",
                    str(port),
                    "--script",
                    "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-*",
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

        await asyncio.gather(_enum4linux(), _shares(), _nmap_smb())

    async def _enumerate_ldap(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate LDAP services: anonymous bind, directory extraction."""
        logger.info(f"Starting LDAP enumeration on {result.target_ip}")

        # ponytail: per-service fan-out + intra-service tool fan-out.
        await asyncio.gather(*(self._enumerate_ldap_service(result, svc) for svc in services))
        return result

    async def _enumerate_ldap_service(self, result: HostReconResult, svc: ServiceInfo) -> None:
        port = svc.port
        protocol = "ldaps" if port == 636 or svc.service.lower() == "ldaps" else "ldap"

        async def _anon_bind() -> None:
            if ToolAvailability.check(self._config.ldapsearch_path):
                cmd = [
                    self._config.ldapsearch_path,
                    "-x",  # Simple authentication
                    "-H",
                    f"{protocol}://{result.target_ip}:{port}",
                    "-b",
                    "dc=example,dc=com",  # Base DN guess
                    "-s",
                    "base",
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

        async def _nmap_ldap() -> None:
            # 2. Nmap LDAP scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p",
                    str(port),
                    "--script",
                    "ldap-search,ldap-rootdse",
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

        await asyncio.gather(_anon_bind(), _nmap_ldap())

    async def _enumerate_ftp(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
        """Enumerate FTP services: anonymous login, version checks."""
        logger.info(f"Starting FTP enumeration on {result.target_ip}")

        # ponytail: per-service fan-out + intra-service tool fan-out.
        await asyncio.gather(*(self._enumerate_ftp_service(result, svc) for svc in services))
        return result

    async def _enumerate_ftp_service(self, result: HostReconResult, svc: ServiceInfo) -> None:
        port = svc.port

        async def _anon_login() -> None:
            # Test anonymous login with curl
            if ToolAvailability.check(self._config.curl_path):
                cmd = [
                    self._config.curl_path,
                    "-v",
                    f"ftp://anonymous:anonymous@{result.target_ip}:{port}/",
                    "--max-time",
                    "10",
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

        async def _nmap_ftp() -> None:
            # Nmap FTP scripts
            if ToolAvailability.check(self._config.nmap_path):
                cmd = [
                    self._config.nmap_path,
                    "-p",
                    str(port),
                    "--script",
                    "ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie",
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

        await asyncio.gather(_anon_login(), _nmap_ftp())

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
            logger.warning(f"Skipping Redis enumeration: invalid target {result.target_ip!r}")
            return result

        for svc in services:
            port = svc.port

            try:
                proc = await asyncio.create_subprocess_exec(
                    "nc",
                    "-w",
                    "3",
                    result.target_ip,
                    str(port),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                logger.warning(f"nc not available for Redis enumeration on port {port}: {exc}")
                continue

            try:
                stdout_bytes, _ = await asyncio.wait_for(proc.communicate(input=b"INFO\n"), timeout=10)
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
                    "-s",
                    f"{base_url}/_cluster/health",
                    "--max-time",
                    "10",
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
                    "-s",
                    f"{base_url}/_cat/indices?v",
                    "--max-time",
                    "10",
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
                        "-s",
                        f"{scheme}://{result.target_ip}:{port}/version",
                        "--max-time",
                        "10",
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
                        "-s",
                        "-k",
                        f"https://{result.target_ip}:{port}/api",
                        "--max-time",
                        "10",
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
                        "-s",
                        "-k",
                        f"https://{result.target_ip}:{port}/pods",
                        "--max-time",
                        "10",
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
                    "-p",
                    str(port),
                    "--script",
                    "rdp-enum-encryption,rdp-vuln-ms12-020",
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

    async def _enumerate_tls(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
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
                "-p",
                str(port),
                "--script",
                "ssl-cert,ssl-enum",
                "-Pn",
                result.target_ip,
            ]
            try:
                success, stdout, stderr, _ = await run_command(
                    cmd,
                    timeout=60,
                    max_retries=1,
                )
            except Exception as exc:
                result.warnings.append(f"TLS enum failed on port {port}: {exc}")
                continue
            if success and stdout:
                svc.ssl_info = parse_tls_info(stdout)
                svc.scripts["ssl_cert"] = stdout[:3000]
                result.evidence_refs.append(f"ssl_cert:{port}")
        return result

    async def _enumerate_smtp(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
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
                    "-p",
                    str(port),
                    "--script",
                    "smtp-commands,smtp-open-relay",
                    "-Pn",
                    result.target_ip,
                ]
                try:
                    success, stdout, stderr, _ = await run_command(
                        cmd,
                        timeout=60,
                        max_retries=1,
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

    async def _enumerate_db(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
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
                    "-p",
                    str(port),
                    "--script",
                    "banner,default",
                    "-Pn",
                    result.target_ip,
                ]
                try:
                    success, stdout, stderr, _ = await run_command(
                        cmd,
                        timeout=60,
                        max_retries=1,
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

    async def _enumerate_web_spider(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
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
            scheme = "https" if svc.service.lower() == "https" or port in (443, 8443) else "http"
            try:
                spider = http_spider(result.target_ip, port, scheme=scheme, max_pages=20)
            except Exception as exc:
                result.warnings.append(f"Web spider failed on port {port}: {exc}")
                continue
            if isinstance(spider, dict):
                result.spider_results.append(spider)
                result.evidence_refs.append(f"spider:{port}")
        return result

    async def _enumerate_osint(self, result: HostReconResult, services: list[ServiceInfo]) -> HostReconResult:
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
    def _stdlib_fetch(
        url: str, *, timeout: int = 15, method: str = "GET", headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], str]:
        """Default HTTP fetch (urllib). Returns (status, headers, body)."""
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(200000).decode(errors="replace")
                return resp.status, dict(resp.headers.items()), body
        except urllib.error.HTTPError as e:
            return (
                e.code,
                dict(e.headers.items()) if e.headers else {},
                (e.read(2000).decode(errors="replace") if e.fp else ""),
            )
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
                                if s and is_subdomain_of(s, domain):
                                    subs.add(s)
                except Exception:
                    pass
            result.extended["subdomains"] = {
                "enabled": True,
                "domain": domain,
                "count": len(subs),
                "subdomains": sorted(subs)[:500],
            }
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
            words = [
                "www",
                "mail",
                "admin",
                "api",
                "dev",
                "staging",
                "test",
                "vpn",
                "portal",
                "git",
                "jenkins",
                "jira",
                "internal",
            ]
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
                "Imperva Incapsula": (
                    lambda h: "incap" in h.get("x-iinfo", "").lower() or "incapsula" in h.get("server", "").lower()
                ),
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

    async def _enumerate_cloud_metadata(
        self, result: HostReconResult, services: list, *, fetch_fn=None
    ) -> HostReconResult:
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
                s2, _h2, token = fetch(
                    "http://169.254.169.254/latest/api/token",
                    timeout=4,
                    method="PUT",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                )
                info["imdsv2_reachable"] = False
                if s2 == 200 and token:
                    s3, _h3, _b3 = fetch(base, timeout=4, headers={"X-aws-ec2-metadata-token": token.strip()})
                    info["imdsv2_reachable"] = s3 == 200
            except Exception:
                info["imdsv2_reachable"] = False
            if s1 == 200 and body1:
                info["instance_id_hint"] = body1.strip().splitlines()[0][:80]
            info["note"] = (
                "operator-box IMDS reachable -- your own metadata is exposed; re-run from the target after a foothold for target IMDS"
            )
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

    async def _enumerate_dns_zone_transfer(
        self, result: HostReconResult, services: list, *, run_fn=None
    ) -> HostReconResult:
        """DNS AXFR via `dig axfr @<target_ip> <zone>` (zone inferred from hostname)."""
        try:
            domain = self._domain_of(result.hostname or "")
            zone = domain or "localhost"
            run = run_fn or subprocess.run
            bin_ = shutil.which("dig") or "dig"
            proc = run([bin_, "axfr", f"@{result.target_ip}", zone], capture_output=True, text=True, timeout=30)
            out = getattr(proc, "stdout", "") or ""
            info: dict[str, Any] = {
                "enabled": True,
                "tool": bin_,
                "zone": zone,
                "returncode": getattr(proc, "returncode", None),
            }
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
        if major < 4 or (major == 4 and minor < 4) or (major == 8 and minor >= 5) or (major == 9 and minor < 8):
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
