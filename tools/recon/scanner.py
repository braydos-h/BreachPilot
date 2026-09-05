"""Recon primary scanner — extracted from tools.recon_pipeline.

Canonical source for ``run_command`` helpers and ``PrimaryReconScanner``.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import signal
import time
from pathlib import Path
from typing import Any

from tools.logging_setup import get_logger
from tools.nmap_priv import apply_nmap_privilege, is_privilege_error
from tools.recon.config import HostReconResult, ReconConfig, ServiceInfo, ToolAvailability

logger = get_logger()

# ---------------------------------------------------------------------------
# Async command runner with retries
# ---------------------------------------------------------------------------

# Exit codes that are deterministic, not transient -- retrying a command that
# died this way just burns the retry budget (the log showed nmap on Windows
# retried 2x with 5s/7.5s sleeps after a 0xC0000005 access violation). Like
# ``is_privilege_error``, these short-circuit before the retry sleep so the
# caller can fall through to the next argv in the fallback chain.
_NON_RETRYABLE_EXIT_CODES = frozenset(
    {
        127,  # POSIX: command not found
        126,  # POSIX: found but not executable
        9009,  # Windows CMD: command not recognized
        3221225477,  # 0xC0000005 NTSTATUS_ACCESS_VIOLATION (nmap crash)
        3221225786,  # 0xC0000135 DLL not found
        3221225776,  # 0xC0000142 DLL initialization failed
    }
)


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
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed = max(time.monotonic() - start, 0.0001)
            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            if proc.returncode == 0:
                logger.debug(f"Command succeeded: {' '.join(cmd[:5])}... ({elapsed:.1f}s)")
                return True, stdout, stderr, elapsed
            else:
                last_error = f"Exit code {proc.returncode}: {stderr[:500]}"
                logger.warning(f"Command failed (attempt {attempt + 1}): {last_error}")
                # A raw-socket scan that fails for lack of root fails
                # identically on every retry. Don't burn the retry budget --
                # return now so the caller can downgrade the argv (``-sS`` ->
                # ``-sT``) and retry once with the corrected command.
                if is_privilege_error(stderr):
                    logger.warning(f"Privilege-related failure, not retrying: {last_error}")
                    return False, stdout, stderr, elapsed
                if proc.returncode in _NON_RETRYABLE_EXIT_CODES:
                    logger.warning(f"Non-retryable exit code {proc.returncode}, not retrying: {last_error}")
                    return False, stdout, stderr, elapsed

        except asyncio.TimeoutError:
            last_error = f"Timeout after {timeout}s"
            logger.warning(f"Command timeout (attempt {attempt + 1}): {' '.join(cmd[:5])}...")
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
            logger.warning(f"Command exception (attempt {attempt + 1}): {last_error}")

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
                    logger.info(f"Socket scan complete: {len(result.open_ports)} ports on {target}")
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
            "-sS",
            "-sV",
            "-O",
            "-Pn",
            "-T4",
            "--script=vuln,default",
            "-p-",
            "-oX",
            "-",  # XML output to stdout
            target,
        ]

        if self._config.aggression_level == "stealth":
            cmd = [
                self._config.nmap_path,
                "-sS",
                "-Pn",
                "--data-length",
                "50",
                "--randomize-hosts",
                "-T2",
                "-p-",
                "-oX",
                "-",
                target,
            ]
        elif self._config.aggression_level == "aggressive":
            cmd = [
                self._config.nmap_path,
                "-sS",
                "-sV",
                "-O",
                "-Pn",
                "-T5",
                "--script=vuln,default",
                "-p-",
                "-oX",
                "-",
                target,
            ]

        # Apply sudo-prefix / unprivileged downgrade (``-sS``/``-O`` -> ``-sT``)
        # up front so a non-root operator box does not fail on raw-packet scans.
        cmd, note = apply_nmap_privilege(cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback)
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
            cmd2, note2 = apply_nmap_privilege(cmd, sudo=self._config.sudo, priv_fallback=True)
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

    async def _run_nmap_udp(self, target: str, top_ports: int = 100) -> HostReconResult | None:
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
            "-sU",
            "-sV",
            "-Pn",
            "--top-ports",
            str(top_ports),
            "--script=default,vuln",
            "-oX",
            "-",
            target,
        ]

        cmd, note = apply_nmap_privilege(cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback)
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
                "-sU",
                "-sV",
                "-Pn",
                "--top-ports",
                str(reduced),
                "--script=default",
                "-oX",
                "-",
                target,
            ]
            cmd2, note2 = apply_nmap_privilege(cmd2, sudo=self._config.sudo, priv_fallback=True)
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
            "-a",
            target,
            "-t",
            "2000",
            "-b",
            "1000",
            "--range",
            "1-65535",
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
            "-sS",
            "-sV",
            "-Pn",
            "-T4",
            "--script=default,vuln",
            "-p",
            port_str,
            "-oX",
            "-",
            target,
        ]
        nmap_cmd, _ = apply_nmap_privilege(nmap_cmd, sudo=self._config.sudo, priv_fallback=self._config.priv_fallback)

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
            "--rate",
            "1000",
            "--wait",
            "5",
            "-oJ",
            "-",  # JSON output to stdout
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
                "-sS",
                "-sV",
                "-Pn",
                "-T4",
                "-p",
                port_str,
                "-oX",
                "-",
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

                # ponytail: membership guard, not blind append -- follow-up
                # scans (rustscan/masscan + nmap) pre-seed open_ports, and a
                # re-parse must never duplicate entries.
                if state == "open":
                    if port_id not in result.open_ports:
                        result.open_ports.append(port_id)
                elif state == "filtered":
                    if port_id not in result.filtered_ports:
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

            # Host scripts are host-level findings, not per-service ones --
            # copying every hostscript onto every service duplicated them N x M
            # times. Store once under result.extended instead.
            host_scripts: dict[str, str] = {}
            for script in host.findall("hostscript/script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                if script_id and script_id not in host_scripts:
                    host_scripts[script_id] = script_output
            if host_scripts:
                result.extended.setdefault("hostscripts", {}).update(host_scripts)

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
