"""Recon MCP tool registration."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import threading
import time
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.kernel.allowlist import _explicit_ip_allowlist_targets
from tools.kernel.target_network import (
    embedded_ipv4_address,
    is_metadata_destination,
    is_public_destination,
)
from tools.kernel.workspace import write_workspace_file
from tools.mcp_shared import _attempt_dir
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox, sandbox_error_block
from tools.recon.config import HostReconResult, ServiceInfo
from tools.recon.scanner import PrimaryReconScanner
from tools.sandbox.exceptions import SandboxError, SandboxUnsupportedError
from tools.validation_utils import is_fqdn, is_target_in_allowlist, resolve_target_bounded, validate_target_or_ip

# ponytail: short-TTL cache for get_service_fingerprint results. A planning
# loop re-fingerprints the same (ip, port) every cycle at ~8s socket+TLS per
# call; banners don't change minute-to-minute. 300s matches the FastRecon
# disk-cache precedent (tools/fast_recon.py).
_FINGERPRINT_TTL_S = 300.0
_FINGERPRINT_CACHE: dict[tuple[str, str, int], tuple[float, str]] = {}
_fingerprint_lock = threading.Lock()
_OSINT_TIMEOUT_S = 45.0
_OSINT_CALL_SLOTS = threading.BoundedSemaphore(value=4)


def _resolve_recon_target(
    target: str,
    config: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Resolve a scoped recon target once and return its pinned IP.

    The allowlist decorator authorizes the supplied hostname or IP. The
    returned address is pinned into worker argv; the original authorized name
    is separately passed to the sandbox scope gate so its firewall can enforce
    the same hostname-tied grant. Non-public DNS answers require an independent
    IP/CIDR grant, and metadata/link-local destinations are always denied.
    """
    if not isinstance(target, str) or not target.strip():
        return None, "target is required"
    target = target.strip()
    if not validate_target_or_ip(target):
        return None, "Invalid target (IP or domain)"

    runtime_domain = os.environ.get("EXPLOIT_TARGET_DOMAIN", "").strip()
    runtime_ip = os.environ.get("EXPLOIT_TARGET_IP", "").strip()
    domain_origin = target if is_fqdn(target) else ""
    resolved_ip: str | None
    if (
        runtime_domain
        and runtime_ip
        and (
            (is_fqdn(target) and runtime_domain.lower().rstrip(".") == target.lower().rstrip("."))
            or _same_target_address(target, runtime_ip)
        )
    ):
        # The recon-first service passes the pinned IP to IP-oriented tools
        # while retaining the original FQDN separately.
        # Keep that provenance so the IP literal cannot bypass the separate
        # private-address grant required for a domain-originated destination.
        domain_origin = runtime_domain
        resolved_ip = runtime_ip
    else:
        try:
            resolved_ip, _resolved_domain = resolve_target_bounded(target)
        except (OSError, TimeoutError, ValueError) as exc:
            return None, f"target resolution failed: {exc}"
    if not resolved_ip:
        return None, "target did not resolve to an IP address"

    try:
        address = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return None, "target resolution returned an invalid IP address"

    policy_address = embedded_ipv4_address(address) or address

    if is_metadata_destination(address):
        return None, "target resolves to a blocked metadata or link-local address"

    # A hostname grants scope to that name, not to an arbitrary private or
    # special-use address that DNS may return. Operators can intentionally
    # scan internal lab targets by listing the concrete IP or containing CIDR.
    if domain_origin and not is_public_destination(address):
        allowed_ips = _explicit_ip_allowlist_targets(config)
        if not is_target_in_allowlist(str(policy_address), allowed_ips):
            return None, f"domain resolves to non-public address {policy_address}, which is not separately allowlisted"

    # Reject scoped IPv6 literals: these are interface-relative and cannot be
    # represented as a stable target for the worker firewall.
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        return None, "scoped IPv6 targets are not supported by sandbox recon"

    return str(address), None


def _same_target_address(left: str, right: str) -> bool:
    """Compare IP spellings by address value, including IPv4-mapped forms.

    Runtime-pinned hostnames are re-entered as IP literals by IP-oriented
    tools. Text equality loses the original hostname provenance for equivalent
    IPv6 spellings, which could bypass the separate private-IP scope check.
    Comparing embedded IPv4 forms as well is conservative for transition
    addresses: aliases retain the pinned domain's stricter provenance.
    """
    try:
        left_address = ipaddress.ip_address(left)
        right_address = ipaddress.ip_address(right)
    except ValueError:
        return False
    left_embedded = embedded_ipv4_address(left_address)
    right_embedded = embedded_ipv4_address(right_address)
    return (left_embedded or left_address) == (right_embedded or right_address)


def _recon_target_error(message: str) -> str:
    """Render target validation failures consistently for MCP callers."""
    if message == "Invalid target (IP or domain)":
        return f"ERROR: {message}."
    return f"BLOCKED: {message}."


def _nmap_timeout(config: dict[str, Any] | None) -> int:
    """Return a bounded per-scan timeout for worker Nmap operations."""
    raw = ((config or {}).get("recon") or {}).get("timeout_seconds", 300)
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        seconds = 300
    return min(max(seconds, 5), 1800)


def _run_nmap_in_worker(
    ctx: ToolContext,
    *,
    scope_target: str,
    resolved_ip: str,
    args: list[str],
    timeout: int,
    tool_name: str,
) -> tuple[Any | None, str | None]:
    """Run fixed Nmap argv against one resolved address inside the worker.

    ``scope_target`` preserves hostname authorization for the manager and
    firewall. ``resolved_ip`` is the literal placed in argv, avoiding a second
    target lookup by Nmap. The result never falls back to host sockets or
    subprocesses.
    """
    try:
        address = ipaddress.ip_address(resolved_ip)
        argv = ["nmap"]
        if isinstance(address, ipaddress.IPv6Address):
            argv.append("-6")
        argv.extend(["-n", "-Pn", *args, "-oX", "-", str(address)])
        _ran, result = run_argv_in_sandbox(
            ctx,
            argv,
            target_ip=scope_target,
            targets=[scope_target],
            timeout=timeout,
            tool_name=tool_name,
        )
        if result.timed_out:
            return None, f"ERROR: {tool_name} timed out in the sandbox; no host fallback was attempted."
        if result.exit_code != 0:
            detail = (result.stderr or result.stdout or "Nmap exited unsuccessfully").strip()[-1200:]
            return None, f"ERROR: {tool_name} failed in the sandbox (exit {result.exit_code}): {detail}"
        if "<nmaprun" not in (result.stdout or ""):
            return None, f"ERROR: {tool_name} returned no Nmap XML from the sandbox; results are unavailable."
        return result, None
    except _EXC_GROUP_CATCH as exc:
        _log_nested_exceptions(exc)
        if isinstance(exc, SandboxError):
            return None, sandbox_error_block(exc, tool_name=tool_name)
        detail = str(exc) or type(exc).__name__
        return None, sandbox_error_block(SandboxError(f"sandbox execution failed: {detail}"), tool_name=tool_name)


def _parse_nmap_result(target: str, worker_result: Any, *, scan_tool: str) -> HostReconResult:
    """Parse a successful worker Nmap XML result without host execution."""
    result = HostReconResult(
        target_ip=target,
        scan_tool=scan_tool,
        scan_duration=float(getattr(worker_result, "duration_seconds", 0.0) or 0.0),
    )
    PrimaryReconScanner._parse_nmap_xml(worker_result.stdout or "", result)
    return result


async def sandbox_recon_host(
    ctx: ToolContext,
    target: str,
    config: dict[str, Any] | None = None,
    *,
    aggression: str = "normal",
) -> tuple[HostReconResult | None, str | None]:
    """Run one full TCP recon scan through the scoped sandbox worker.

    This adapter is shared by the MCP recon tool, autonomous campaigns, and
    swarm recon agents so those entrypoints use the same DNS pinning, target
    checks, worker firewall, timeout, and no-host-fallback behavior.
    """
    resolved_ip, target_error = _resolve_recon_target(target, config)
    if target_error:
        return None, _recon_target_error(target_error)
    assert resolved_ip is not None

    profile = str(aggression or "normal").strip().lower()
    if profile == "maximum":
        profile = "aggressive"
    if profile not in {"stealth", "normal", "aggressive"}:
        profile = "normal"
    timing = {"stealth": "-T2", "normal": "-T3", "aggressive": "-T4"}[profile]
    scan_args = ["-sT", "-sV", timing]
    if profile == "stealth":
        scan_args.extend(["--top-ports", "1000"])
    else:
        scan_args.append("-p-")
    scan_args.append("--script=default,vuln" if profile == "aggressive" else "--script=default")

    worker_result, error = await asyncio.to_thread(
        _run_nmap_in_worker,
        ctx,
        scope_target=target.strip(),
        resolved_ip=resolved_ip,
        args=scan_args,
        timeout=_nmap_timeout(config),
        tool_name="run_full_recon",
    )
    if error:
        return None, error
    assert worker_result is not None
    result = _parse_nmap_result(resolved_ip, worker_result, scan_tool="nmap-worker")
    if result.errors:
        return None, f"ERROR: run_full_recon could not parse Nmap results: {'; '.join(result.errors[:3])}"
    result.warnings.append("Nmap worker results only; secondary service-specific enumeration was not run.")
    return result, None


def _service_details(service: ServiceInfo) -> str:
    details = " ".join(part for part in (service.version, service.banner) if part).strip()
    return details[:240] if details else "(no version details)"


def _os_heuristic(result: HostReconResult) -> tuple[str, list[str], int, int]:
    """Infer a cautious OS hint from Nmap service metadata, never TTL claims."""
    windows_score = 0
    linux_score = 0
    hints: list[str] = []
    windows_words = ("windows", "win32", "microsoft", "iis", "winrm")
    linux_words = ("ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "suse", "alpine", "linux", "openssh")
    for service in result.services:
        evidence = f"{service.service} {service.version} {service.banner}".lower()
        if service.port in (135, 139, 445, 3389, 5985):
            windows_score += 1
            hints.append(f"Port {service.port}/tcp is a Windows-associated service port")
        if service.port in (111, 2049):
            linux_score += 1
            hints.append(f"Port {service.port}/tcp is a Unix/Linux-associated service port")
        if any(word in evidence for word in windows_words):
            windows_score += 2
            hints.append(f"Nmap service metadata on port {service.port} contains a Windows indicator")
        if any(word in evidence for word in linux_words):
            linux_score += 2
            hints.append(f"Nmap service metadata on port {service.port} contains a Unix/Linux indicator")
    if windows_score and not linux_score:
        verdict = "WINDOWS"
    elif linux_score and not windows_score:
        verdict = "LINUX"
    elif windows_score and linux_score:
        verdict = (
            "MIXED/DETECTED_BOTH"
            if windows_score == linux_score
            else ("WINDOWS" if windows_score > linux_score else "LINUX")
        )
    else:
        verdict = "UNKNOWN"
    return verdict, hints, windows_score, linux_score


def _run_passive_osint_bounded(run_osint: Any, ip: str, hostname: str) -> dict[str, Any]:
    """Run passive OSINT with a wall-time bound and capped resolver threads.

    The OS-level PTR/AAAA resolver calls may stall despite HTTP timeouts. A
    fixed number of daemon workers prevents repeated timeouts from creating an
    unbounded thread pool. Provider HTTP itself is pinned to crt.sh/Shodan,
    uses a 15-second request timeout, and caps response bodies at 2 MiB.
    """
    if not _OSINT_CALL_SLOTS.acquire(blocking=False):
        return {"error": "passive OSINT workers are busy; this request failed closed"}
    finished = threading.Event()
    payload: dict[str, Any] = {}

    def collect() -> None:
        try:
            result = run_osint(ip, hostname=hostname)
            if isinstance(result, dict):
                payload.update(result)
        except Exception as exc:  # noqa: BLE001 -- passive lookup errors are surfaced as bounded result data
            payload["error"] = f"passive OSINT lookup failed: {type(exc).__name__}"
        finally:
            _OSINT_CALL_SLOTS.release()
            finished.set()

    worker = threading.Thread(target=collect, name="breachpilot-passive-osint", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _OSINT_CALL_SLOTS.release()
        return {"error": "passive OSINT worker could not start"}
    if not finished.wait(_OSINT_TIMEOUT_S):
        return {"error": f"passive OSINT exceeded its {_OSINT_TIMEOUT_S:.0f}-second time limit"}
    return payload


def register_recon_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def check_os(target_ip: str) -> str:
        """Return a cautious OS hint from Nmap service metadata in the sandbox.

        This is a heuristic, not an OS fingerprint: the worker has no raw
        socket capability, so the tool does not use TTL or privileged Nmap OS
        probes. It scans only the listed common TCP ports.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        resolved_ip, target_error = _resolve_recon_target(target_ip, config)
        if target_error:
            return _recon_target_error(target_error)
        assert resolved_ip is not None
        common_ports = [
            21,
            22,
            80,
            111,
            135,
            139,
            443,
            445,
            2049,
            2121,
            2222,
            2323,
            3000,
            3306,
            3389,
            4455,
            5900,
            5985,
            8080,
            8081,
            8082,
            8083,
        ]
        worker_result, error = _run_nmap_in_worker(
            ctx,
            scope_target=target_ip.strip(),
            resolved_ip=resolved_ip,
            args=["-sT", "-sV", "--version-light", "-T3", "-p", ",".join(map(str, common_ports))],
            timeout=120,
            tool_name="check_os",
        )
        if error:
            return error
        assert worker_result is not None
        result = _parse_nmap_result(resolved_ip, worker_result, scan_tool="nmap-worker")
        if result.errors:
            return f"ERROR: check_os could not parse Nmap results: {'; '.join(result.errors[:3])}"
        verdict, hints, windows_score, linux_score = _os_heuristic(result)
        lines = [
            "OS_CHECK_RESULTS:",
            f"TARGET: {target_ip.strip()}",
            f"RESOLVED_IP: {resolved_ip}",
            "METHOD: Nmap service metadata heuristic; no TTL or privileged OS probe was used.",
            "TTL: N/A (not collected)",
            "",
        ]
        for service in result.services:
            lines.append(f"  Port {service.port}/tcp: open - {service.service} {_service_details(service)}")
        lines.extend(
            [
                "",
                f"OS_VERDICT: {verdict}",
                f"CONFIDENCE: heuristic scores Windows={windows_score}, Unix/Linux={linux_score}; not an OS fingerprint",
                f"HINTS: {'; '.join(hints) if hints else 'No OS-specific service metadata found.'}",
                "GUIDANCE: Treat this as an initial hint; verify the operating system through a scoped service-specific check.",
            ]
        )
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def quick_scan(
        target_ip: str,
        ports: str = "22,80,135,139,443,445,3389,3000,8080,8081,8082,8083,2222,2121,2323,4455,3306",
    ) -> str:
        """Run a bounded Nmap TCP connect scan in the sandbox worker.

        Provide a comma-separated list of ports. Service/version details come
        from Nmap's light version probes; this tool does not open host sockets.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not isinstance(ports, str):
            return "BLOCKED: ports must be a comma-separated string of TCP port numbers."
        tokens = [part.strip() for part in ports.split(",")]
        if not tokens or any(not token.isdecimal() for token in tokens):
            return "BLOCKED: ports must contain only decimal TCP port numbers."
        port_list = list(dict.fromkeys(int(token) for token in tokens))
        if any(port < 1 or port > 65535 for port in port_list):
            return "BLOCKED: TCP ports must be between 1 and 65535."
        if len(port_list) > 1000:
            return "BLOCKED: quick_scan accepts at most 1000 distinct ports."
        resolved_ip, target_error = _resolve_recon_target(target_ip, config)
        if target_error:
            return _recon_target_error(target_error)
        assert resolved_ip is not None
        worker_result, error = _run_nmap_in_worker(
            ctx,
            scope_target=target_ip.strip(),
            resolved_ip=resolved_ip,
            args=["-sT", "-sV", "--version-light", "-T3", "-p", ",".join(map(str, port_list))],
            timeout=90,
            tool_name="quick_scan",
        )
        if error:
            return error
        assert worker_result is not None
        result = _parse_nmap_result(resolved_ip, worker_result, scan_tool="nmap-worker")
        if result.errors:
            return f"ERROR: quick_scan could not parse Nmap results: {'; '.join(result.errors[:3])}"
        services = {service.port: service for service in result.services if service.protocol == "tcp"}
        lines = [f"QUICK_SCAN_RESULTS: {target_ip.strip()}", f"RESOLVED_IP: {resolved_ip}", ""]
        for port in port_list:
            service = services.get(port)
            if service:
                lines.append(f"  Port {port}/tcp OPEN ({service.service}) - {_service_details(service)}")
        open_count = len(services)
        lines.extend(["", f"SUMMARY: {open_count}/{len(port_list)} ports open (Nmap TCP connect scan; sandbox worker)"])
        if not open_count:
            lines.append("NOTE: Nmap reported no open ports in the requested set; filtered ports may be inconclusive.")
        else:
            lines.append(
                "NEXT STEPS: Verify service versions and research relevant exposures before any exploit attempt."
            )
        return "\n".join(lines)

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 1. Reconnaissance & Intelligence (tools.recon_pipeline)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @require_allowlist()
    async def run_full_recon(target_ip: str, aggression: str = "normal") -> str:
        """Run a TCP Nmap scan inside the sandbox worker and save its results.

        No host-side scanner or secondary enumerator fallback is used. The
        stealth profile scans common ports; normal/aggressive scan the full TCP
        range, with the aggressive profile also enabling Nmap's ``vuln`` NSE
        category. Raw-socket OS detection is unavailable in the hardened worker.

        Args:
            target_ip: Authorized IP address or domain.
            aggression: Scan aggression level Ã¢â‚¬â€ 'stealth', 'normal', 'aggressive', or 'maximum'.
                        Stealth uses slower timing and common ports; aggressive enables
                        the Nmap ``vuln`` script category and faster timing.

        Returns:
            Structured summary of Nmap TCP ports/services and the saved JSON path.

        Example:
            run_full_recon("192.168.1.100", "aggressive")
        """
        result, error = await sandbox_recon_host(ctx, target_ip, config, aggression=aggression)
        if error:
            return error
        assert result is not None
        resolved_ip = result.target_ip
        profile = str(aggression or "normal").strip().lower()
        if profile == "maximum":
            profile = "aggressive"
        if profile not in {"stealth", "normal", "aggressive"}:
            profile = "normal"

        try:
            _, attempt_id = _attempt_dir(workspace)
            json_path = write_workspace_file(
                workspace,
                f"{attempt_id}/recon_result.json",
                json.dumps(result.to_dict(), indent=2, default=str).encode("utf-8"),
            )
        except (OSError, ValueError) as exc:
            return f"ERROR: Nmap scan completed but recon results could not be saved: {exc}"

        lines = [
            "RECON_RESULT: completed",
            f"ATTEMPT_ID: {attempt_id}",
            f"TARGET: {target_ip.strip()}",
            f"RESOLVED_IP: {resolved_ip}",
            "OS: Unknown (raw-socket OS fingerprinting is unavailable in the worker)",
            "TTL: N/A (not collected)",
            f"SCAN_DURATION: {result.scan_duration:.1f}s",
            f"SCAN_TOOL: {result.scan_tool}",
            f"PROFILE: {profile}",
            f"OPEN_PORTS: {len(result.open_ports)} ports — {result.open_ports}",
            f"FILTERED_PORTS: {len(result.filtered_ports)} ports",
            f"SAVED_JSON: {json_path}",
            "",
            "SERVICES:",
        ]
        for service in result.services:
            lines.append(f"  {service.port}/{service.protocol} — {service.service} {_service_details(service)}")
        lines.append(f"\nNOTE: {result.warnings[0]}")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def get_service_fingerprint(target_ip: str, port: int) -> str:
        """Fingerprint one TCP service using Nmap inside the sandbox worker.

        Nmap service/version details are returned when the port responds. TLS
        ports also run the worker's ``ssl-cert`` script. No operator-host
        sockets or TLS handshakes are used.

        Args:
            target_ip: Authorized IP address or domain.
            port: TCP port number to fingerprint.

        Returns:
            Structured output with Nmap service/version metadata and TLS script output.

        Example:
            get_service_fingerprint("192.168.1.100", 443)
        """
        if isinstance(port, str) and port.strip().isdecimal():
            port = int(port.strip())
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return "ERROR: Port must be an integer between 1 and 65535."
        resolved_ip, target_error = _resolve_recon_target(target_ip, config)
        if target_error:
            return _recon_target_error(target_error)
        assert resolved_ip is not None

        _fp_key = (target_ip.strip(), resolved_ip, port)
        with _fingerprint_lock:
            _fp_hit = _FINGERPRINT_CACHE.get(_fp_key)
            if _fp_hit is not None and time.monotonic() - _fp_hit[0] < _FINGERPRINT_TTL_S:
                return _fp_hit[1]

        is_tls = port in (443, 8443, 636, 993, 995, 465, 989, 990)
        scan_args = ["-sT", "-sV", "--version-light", "-T3", "-p", str(port)]
        if is_tls:
            scan_args.append("--script=ssl-cert")
        worker_result, error = _run_nmap_in_worker(
            ctx,
            scope_target=target_ip.strip(),
            resolved_ip=resolved_ip,
            args=scan_args,
            timeout=45,
            tool_name="get_service_fingerprint",
        )
        if error:
            return error
        assert worker_result is not None
        result = _parse_nmap_result(resolved_ip, worker_result, scan_tool="nmap-worker")
        if result.errors:
            return f"ERROR: fingerprint results could not be parsed: {'; '.join(result.errors[:3])}"
        service = next((item for item in result.services if item.port == port and item.protocol == "tcp"), None)
        lines = [
            f"SERVICE_FINGERPRINT: {target_ip.strip()}:{port}",
            f"RESOLVED_IP: {resolved_ip}",
            f"PORT: {port}/tcp",
            f"STATE: {'open' if service else 'not reported open'}",
            f"SERVICE_GUESS: {service.service if service else 'unknown'}",
            f"NMAP_DETAILS: {_service_details(service) if service else '(no service version returned)'}",
        ]
        if service and service.scripts.get("ssl-cert"):
            lines.extend(["", "SSL_CERT_SCRIPT:", service.scripts["ssl-cert"][:2000]])
        rendered = "\n".join(lines)
        with _fingerprint_lock:
            _FINGERPRINT_CACHE[_fp_key] = (time.monotonic(), rendered)
        return rendered

    # ======================================================================
    # 1b. Reconnaissance & Intelligence (Phase 3 Round 2: UDP / OSINT / diff)
    # ======================================================================

    @mcp.tool()
    @require_allowlist()
    async def run_udp_recon(target_ip: str, top_ports: int = 100) -> str:
        """Report that UDP scanning is unavailable under the worker policy.

        The sandbox worker drops NET_RAW, which Nmap UDP scanning needs for
        reliable open/closed/filtered semantics. This tool fails closed rather
        than running an unprivileged or operator-host fallback that could
        misreport results.

        Args:
            target_ip: Authorized IP address or domain.
            top_ports: Retained for API compatibility; no UDP scan is started.

        Returns:
            A ``SANDBOX_UNSUPPORTED`` result until a sandbox-safe UDP scanner
            can preserve reliable scan semantics without NET_RAW.
        """
        resolved_ip, target_error = _resolve_recon_target(target_ip, config)
        if target_error:
            return _recon_target_error(target_error)
        assert resolved_ip is not None
        del top_ports
        unsupported = SandboxUnsupportedError(
            "Nmap UDP scanning requires NET_RAW, which the hardened worker intentionally drops; "
            "no host execution or lower-confidence UDP fallback is available"
        )
        return f"UDP_PORTS: blocked\n{sandbox_error_block(unsupported, tool_name='run_udp_recon')}"

    @mcp.tool()
    @require_allowlist()
    def run_osint_recon(target_ip: str) -> str:
        """Run bounded passive OSINT lookups about the authorized target.

        PASSIVE ONLY: queries PUBLIC data sources (reverse DNS, DNS AAAA for
        IPv6, crt.sh certificate transparency, optional Shodan) about the single
        target. No active scanning, no third-party submissions. IPv6 is PASSIVE
        ONLY (DNS AAAA lookup; no active IPv6 scan). Host DNS resolver calls
        are capped by a bounded daemon-worker pool and the full request has a
        45-second wall-time limit. Provider fetches are pinned to crt.sh and
        Shodan, with 15-second request and 2 MiB response limits.

        Args:
            target_ip: Authorized IP address or domain.

        Returns:
            OSINT summary: ipv6 addresses, reverse dns, cert-transparency count,
            shodan enabled/disabled.
        """
        resolved_ip, target_error = _resolve_recon_target(target_ip, config)
        if target_error:
            return _recon_target_error(target_error)
        assert resolved_ip is not None
        from tools.recon_osint import run_osint

        try:
            target_domain = target_ip.strip() if is_fqdn(target_ip.strip()) else ""
            osint = _run_passive_osint_bounded(run_osint, resolved_ip, target_domain)
            if not isinstance(osint, dict):
                return "OSINT: no result"
            ipv6 = osint.get("ipv6_addresses") or []
            rev = osint.get("reverse_dns") or ""
            ct = osint.get("cert_transparency") or {}
            ct_count = ct.get("count", 0) if isinstance(ct, dict) else 0
            shodan = osint.get("shodan") or {}
            shodan_enabled = bool(shodan.get("enabled", False)) if isinstance(shodan, dict) else False
            hostname = osint.get("hostname") or ""
            lines = [
                f"OSINT: {'partial' if osint.get('error') else 'completed'}",
                f"TARGET: {target_ip.strip()}",
                f"RESOLVED_IP: {resolved_ip}",
                f"HOSTNAME: {hostname or '(none)'}",
                f"REVERSE_DNS: {rev or '(none)'}",
                f"IPV6_ADDRESSES: {ipv6 if ipv6 else '(none)'}",
                f"CERT_TRANSPARENCY: {ct_count} certs",
                f"SHODAN: {'enabled' if shodan_enabled else 'disabled'}",
            ]
            if isinstance(shodan, dict) and shodan.get("error"):
                lines.append(f"SHODAN_ERROR: {shodan['error']}")
            if osint.get("error"):
                lines.append(f"OSINT_ERROR: {osint['error']}")
            return "\n".join(lines)
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"ERROR: OSINT recon failed - {exc}"

    @mcp.tool()
    @require_allowlist()
    def diff_recon_runs(old_path: str, new_path: str) -> str:
        """Compare two persisted recon_result.json snapshots.

        This tool does NOT scan; it loads two JSON files produced by prior
        run_full_recon runs and reports added/removed ports, changed services,
        new/lost CVEs, and OS changes. require_allowlist is applied for
        audit-trail consistency even though no target is touched.

        Args:
            old_path: Filesystem path to the older recon_result.json.
            new_path: Filesystem path to the newer recon_result.json.

        Returns:
            RECON_DIFF summary of the changes between the two snapshots.
        """
        from tools.recon_diff import diff_recon_files

        if not old_path or not new_path:
            return "ERROR: both old_path and new_path are required."
        try:
            diff = diff_recon_files(old_path, new_path)
            if not isinstance(diff, dict):
                return "RECON_DIFF: no result"
            if diff.get("error"):
                return f"RECON_DIFF: error - {diff['error']}"
            target = diff.get("target_ip") or "(unknown)"
            added = diff.get("added_ports") or []
            removed = diff.get("removed_ports") or []
            changed = diff.get("changed_services") or []
            new_cves = diff.get("new_cves") or []
            lost_cves = diff.get("lost_cves") or []
            os_changed = diff.get("os_changed")
            summary = diff.get("summary") or "no changes"
            lines = [
                "RECON_DIFF: completed",
                f"TARGET: {target}",
                f"SUMMARY: {summary}",
                f"ADDED_PORTS: {added}",
                f"REMOVED_PORTS: {removed}",
                f"CHANGED_SERVICES: {len(changed)}",
                f"NEW_CVES: {new_cves}",
                f"LOST_CVES: {lost_cves}",
                f"OS_CHANGED: {os_changed}",
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: recon diff failed - {exc}"
