"""Recon MCP tool registration."""

from __future__ import annotations

import subprocess

from tools.mcp_tools.registry import *


def register_recon_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def check_os(target_ip: str) -> str:
        """Probe the target to determine its operating system. Uses ping TTL analysis, banner grabs, and HTTP header probes on common ports. Returns the detected OS and guidance for exploitation tools."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket

        result_lines = ["OS_CHECK_RESULTS:", f"TARGET: {target_ip}", ""]
        hints: list[str] = []
        windows_score = 0
        linux_score = 0

        # --- Ping TTL analysis ---
        if _platform_system() == "Windows":
            ping_cmd = ["ping", "-n", "1"]
            ttl_re = re.compile(r"TTL=(\d+)", re.IGNORECASE)
        else:
            ping_cmd = ["ping", "-c", "1"]
            ttl_re = re.compile(r"ttl=(\d+)", re.IGNORECASE)

        try:
            proc = subprocess.run(
                ping_cmd + [target_ip],
                capture_output=True, text=True, timeout=10,
            )
            match = ttl_re.search(proc.stdout)
            if match:
                ttl = int(match.group(1))
                result_lines.append(f"  TTL: {ttl}")
                if 0 < ttl <= 64:
                    hints.append(f"TTL {ttl} - likely Linux/Unix")
                    linux_score += 2
                elif 64 < ttl <= 128:
                    hints.append(f"TTL {ttl} - likely Windows")
                    windows_score += 2
                elif 128 < ttl <= 255:
                    hints.append(f"TTL {ttl} - likely Cisco/Network device")
                else:
                    hints.append(f"TTL {ttl} - unclear OS")
        except (subprocess.TimeoutExpired, Exception):
            result_lines.append("  Ping: no response")

        # --- Port scans with banner grabs ---
        common_ports = [21, 22, 80, 111, 135, 139, 443, 445, 2049, 3389, 5900, 5985, 8080]
        banner_texts: dict[int, str] = {}

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    if s.connect_ex((target_ip, port)) == 0:
                        banner = ""
                        if port in (80, 443, 8080):
                            try:
                                s.settimeout(2)
                                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                                banner = s.recv(512).decode("utf-8", errors="replace").strip()[:200]
                            except Exception:
                                pass
                        else:
                            try:
                                s.settimeout(2)
                                banner = s.recv(256).decode("utf-8", errors="replace").strip()[:120]
                            except Exception:
                                pass
                        banner_texts[port] = banner
                        result_lines.append(f"  Port {port}/tcp: open - {banner if banner else '(no banner)'}")

                        if port == 22:
                            hints.append("Port 22/tcp open - likely Linux/Unix (SSH)")
                            linux_score += 1
                        elif port in (135, 139, 445, 3389, 5985):
                            hints.append(f"Port {port}/tcp open - likely Windows")
                            windows_score += 1
                        elif port in (111, 2049):
                            hints.append(f"Port {port}/tcp open - likely Linux/Unix")
                            linux_score += 1
            except Exception:
                pass

        # --- Banner text heuristics ---
        windows_banner_keywords = ["windows", "win32", "microsoft", "iis", "winrm"]
        linux_banner_keywords = [
            "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
            "suse", "alpine", "linux", "apache", "nginx/", "openssh", "ssh-2.0-openssh",
        ]

        for port, text in banner_texts.items():
            low = text.lower()
            for kw in windows_banner_keywords:
                if kw in low:
                    windows_score += 1
                    hints.append(f"Banner on port {port} contains '{kw}' - Windows indicator")
                    break
            for kw in linux_banner_keywords:
                if kw in low:
                    linux_score += 1
                    hints.append(f"Banner on port {port} contains '{kw}' - Linux indicator")
                    break

        # --- Verdict ---
        result_lines.append("")
        if windows_score > 0 and linux_score > 0:
            if windows_score > linux_score:
                os_verdict = "WINDOWS"
                confidence = f"{windows_score}:{linux_score}"
            elif linux_score > windows_score:
                os_verdict = "LINUX"
                confidence = f"{linux_score}:{windows_score}"
            else:
                os_verdict = "MIXED/DETECTED_BOTH"
                confidence = "tied"
        elif windows_score > 0:
            os_verdict = "WINDOWS"
            confidence = str(windows_score)
        elif linux_score > 0:
            os_verdict = "LINUX"
            confidence = str(linux_score)
        else:
            os_verdict = "UNKNOWN"
            confidence = "0"

        result_lines.append(f"OS_VERDICT: {os_verdict}")
        result_lines.append(f"CONFIDENCE: {confidence}")
        result_lines.append(f"HINTS: {'; '.join(hints) if hints else 'No definitive OS hints found.'}")
        result_lines.append("")

        if os_verdict == "WINDOWS":
            result_lines.append(
                "WINDOWS_GUIDANCE: Target appears to be Windows. Most Kali Linux tools "
                "(searchsploit -m/--examine, msfconsole modules, bash scripts) will NOT work "
                "directly on your scanner host if it is Windows. For exploitation you can "
                "write custom Python scripts using write_python_file and run_python_file tools. "
                "Python is cross-platform. Use socket, ssl, http.client, urllib, struct, and json "
                "libraries to build exploits. Common Windows targets: SMB (445), RDP (3389), "
                "WinRM (5985), NetBIOS (139), HTTP/IIS (80/443/8080)."
            )
        elif os_verdict == "LINUX":
            result_lines.append(
                "LINUX_GUIDANCE: Target appears to be Linux. Kali tools are available if your "
                "scanner is Linux. Use search_exploit_db to find exploits, search_web_exploit for PoCs, "
                "run_exploit_terminal for any Kali command (nmap scripts, hydra, netcat, "
                "curl-based exploits, etc.), and run_msf_module for Metasploit modules. "
                "write_python_file + run_python_file are also available for custom scripts."
            )
        elif os_verdict == "MIXED/DETECTED_BOTH":
            result_lines.append(
                "MIXED_GUIDANCE: Both Windows and Linux indicators were detected. The target may be "
                "a dual-boot system, a VM host running mixed guests, or a bastion with forwarded ports. "
                "Write Python scripts that work on both platforms, or enumerate further to determine "
                "which service belongs to which host."
            )
        else:
            result_lines.append(
                "UNKNOWN_GUIDANCE: OS could not be determined. Write custom Python exploit "
                "scripts using write_python_file and run_python_file (they work everywhere). "
                "If you detect services via terminal tools, adapt your approach."
            )

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def quick_scan(target_ip: str, ports: str = "22,80,135,139,443,445,3389,8080") -> str:
        """Fast multi-port TCP scanner with banner grabbing. MUCH faster than nmap for quick recon. Provide a comma-separated list of ports (default: common ports). Returns which ports are open and any banners received. Use this FIRST before running slow nmap scans."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        if not port_list:
            return "BLOCKED: no valid ports provided."

        # Delegate to the shared native socket scanner (also used by the recon
        # pipeline's no-privilege fallback tier) so there is one implementation
        # of the TCP-connect + banner-grab logic.
        from tools.socket_scan import format_socket_scan_results, socket_scan_sync

        results = socket_scan_sync(target_ip, port_list)
        return format_socket_scan_results(target_ip, results)

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 1. Reconnaissance & Intelligence (tools.recon_pipeline)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @require_allowlist()
    async def run_full_recon(target_ip: str, aggression: str = "normal") -> str:
        """Run a comprehensive reconnaissance pipeline against a target IP.

        Performs primary scanning (Nmap with fallback to RustScan/Masscan) followed by
        service-aware secondary enumeration (HTTP, SSH, SMB, LDAP, FTP, Redis, etc.).
        Results are saved as structured JSON for downstream attack modules.

        Args:
            target_ip: IPv4 address of the target host.
            aggression: Scan aggression level Ã¢â‚¬â€ 'stealth', 'normal', 'aggressive', or 'maximum'.
                        Stealth uses slower timing and minimal probes; aggressive enables
                        exploit scripts and faster timing.

        Returns:
            Structured summary: target IP, open ports with services, OS guess, scan duration,
            and path to the saved recon_result.json file.

        Example:
            run_full_recon("192.168.1.100", "aggressive")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        aggression_map = {
            "stealth": "stealth",
            "normal": "normal",
            "aggressive": "aggressive",
            "maximum": "aggressive",
        }
        agg_level = aggression_map.get(aggression.lower(), "normal")

        try:
            recon_config = ReconConfig.from_config(config, aggression_level=agg_level)
            pipeline = ReconPipeline(recon_config)
            result: HostReconResult = await pipeline.recon_host(target_ip)

            attempt_dir, attempt_id = _attempt_dir(workspace)
            json_path = attempt_dir / "recon_result.json"
            json_path.write_text(
                json.dumps(result.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )

            lines = [
                f"RECON_RESULT: completed",
                f"ATTEMPT_ID: {attempt_id}",
                f"TARGET: {target_ip}",
                f"OS: {result.os_name or 'Unknown'} (family: {result.os_family}, accuracy: {result.os_accuracy}%)",
                f"TTL: {result.ttl if result.ttl is not None else 'N/A'}",
                f"SCAN_DURATION: {result.scan_duration:.1f}s",
                f"SCAN_TOOL: {result.scan_tool}",
                f"OPEN_PORTS: {len(result.open_ports)} ports Ã¢â‚¬â€ {result.open_ports}",
                f"FILTERED_PORTS: {len(result.filtered_ports)} ports",
                f"SAVED_JSON: {json_path}",
                "",
                "SERVICES:",
            ]
            for svc in result.services:
                lines.append(
                    f"  {svc.port}/{svc.protocol} Ã¢â‚¬â€ {svc.service} {svc.version}"
                    f"{' (' + svc.banner[:60] + '...)' if svc.banner else ''}"
                )
            if result.warnings:
                lines.append(f"\nWARNINGS: {'; '.join(result.warnings[:5])}")
            if result.errors:
                lines.append(f"ERRORS: {'; '.join(result.errors[:5])}")
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Reconnaissance failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @require_allowlist()
    def get_service_fingerprint(target_ip: str, port: int) -> str:
        """Perform a deep service fingerprint on a specific port.

        Connects via TCP, grabs the banner, and for TLS ports (443, 8443) extracts
        SSL/TLS certificate details including issuer and Subject Alternative Names.

        Args:
            target_ip: IPv4 address of the target host.
            port: TCP port number to fingerprint.

        Returns:
            Structured output: port, protocol, banner text, SSL issuer/SAN if applicable,
            and a best-guess service identification.

        Example:
            get_service_fingerprint("192.168.1.100", 443)
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not isinstance(port, int) or port < 1 or port > 65535:
            return "ERROR: Port must be an integer between 1 and 65535."

        try:
            lines = [f"SERVICE_FINGERPRINT: {target_ip}:{port}", ""]
            banner = ""
            ssl_info: dict[str, Any] = {}

            banner = ""
            ssl_info: dict[str, Any] = {}

            # Check if this is a TLS port Ã¢â‚¬â€ try SSL handshake
            is_tls = port in (443, 8443, 636, 993, 995, 465, 989, 990)
            if is_tls:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(8)
                        sock.connect((target_ip, port))
                        ctx = _ssl_module.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl_module.CERT_NONE
                        with ctx.wrap_socket(sock, server_hostname=target_ip) as tls_sock:
                            cert = tls_sock.getpeercert()
                            if cert:
                                ssl_info["issuer"] = ", ".join(
                                    f"{k}={v}" for item in cert.get("issuer", [])
                                    for k, v in item if k == "commonName"
                                )
                                ssl_info["subject"] = ", ".join(
                                    f"{k}={v}" for item in cert.get("subject", [])
                                    for k, v in item if k == "commonName"
                                )
                                san = cert.get("subjectAltName", [])
                                ssl_info["san"] = [s[1] for s in san if s[0] == "DNS"]
                                ssl_info["not_after"] = cert.get("notAfter", "")
                            banner = tls_sock.recv(512).decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    # Not actually TLS or handshake failed Ã¢â‚¬â€ fall back to plain
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(8)
                        sock.connect((target_ip, port))
                        try:
                            banner = sock.recv(512).decode("utf-8", errors="replace").strip()[:200]
                        except Exception:
                            pass
            else:
                # Plain TCP banner grab
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(8)
                    sock.connect((target_ip, port))
                    try:
                        # Send a probe for HTTP-like services
                        if port in (80, 8080, 8000, 3000, 5000):
                            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode())
                        banner = sock.recv(512).decode("utf-8", errors="replace").strip()[:200]
                    except Exception:
                        pass

            # Service guess
            service_guess = "unknown"
            banner_lower = banner.lower()
            if "ssh" in banner_lower or port == 22:
                service_guess = "SSH"
            elif "smtp" in banner_lower or port == 25:
                service_guess = "SMTP"
            elif "http" in banner_lower or "html" in banner_lower or port in (80, 8080):
                service_guess = "HTTP"
            elif "ftp" in banner_lower or port == 21:
                service_guess = "FTP"
            elif "mysql" in banner_lower or port == 3306:
                service_guess = "MySQL"
            elif "postgresql" in banner_lower or port == 5432:
                service_guess = "PostgreSQL"
            elif "redis" in banner_lower or port == 6379:
                service_guess = "Redis"
            elif "mongodb" in banner_lower or port == 27017:
                service_guess = "MongoDB"
            elif "ldap" in banner_lower or port in (389, 636):
                service_guess = "LDAP"
            elif "rdp" in banner_lower or port == 3389:
                service_guess = "RDP"
            elif "smb" in banner_lower or "samba" in banner_lower or port in (445, 139):
                service_guess = "SMB"
            elif is_tls and ssl_info:
                service_guess = "HTTPS/TLS"

            lines.append(f"PORT: {port}/tcp")
            lines.append(f"SERVICE_GUESS: {service_guess}")
            lines.append(f"BANNER: {banner if banner else '(no banner)'}")

            if ssl_info:
                lines.append("")
                lines.append("SSL/TLS INFO:")
                if ssl_info.get("issuer"):
                    lines.append(f"  Issuer: {ssl_info['issuer']}")
                if ssl_info.get("subject"):
                    lines.append(f"  Subject: {ssl_info['subject']}")
                if ssl_info.get("san"):
                    lines.append(f"  SAN: {', '.join(ssl_info['san'][:10])}")
                if ssl_info.get("not_after"):
                    lines.append(f"  Valid Until: {ssl_info['not_after']}")

            return "\n".join(lines)
        except socket.timeout:
            return f"ERROR: Connection to {target_ip}:{port} timed out."
        except ConnectionRefusedError:
            return f"ERROR: Connection refused on {target_ip}:{port}."
        except Exception as exc:
            return f"ERROR: Fingerprint failed Ã¢â‚¬â€ {exc}"




    # ======================================================================
    # 1b. Reconnaissance & Intelligence (Phase 3 Round 2: UDP / OSINT / diff)
    # ======================================================================

    @mcp.tool()
    @require_allowlist()
    async def run_udp_recon(target_ip: str, top_ports: int = 100) -> str:
        """Run a UDP port scan against the single target.

        Uses nmap -sU --top-ports <N> -sV (UDP requires root/sudo; the pipeline
        auto-downgrades on privilege errors). Targets ONLY the single authorized
        target_ip. Results are returned inline (UDP ports + udp services); this
        is additive to the TCP run_full_recon path.

        Args:
            target_ip: IPv4 address of the single authorized target.
            top_ports: Number of most-common UDP ports to scan (default 100).

        Returns:
            UDP_PORTS summary listing the discovered UDP ports and services.
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not isinstance(top_ports, int) or top_ports <= 0:
            top_ports = 100
        try:
            recon_config = ReconConfig.from_config(config)
            pipeline = ReconPipeline(recon_config)
            result: HostReconResult = await pipeline.recon_udp(target_ip, top_ports=top_ports)

            udp_services = [s for s in result.services if s.protocol == "udp"]
            lines = [
                "UDP_PORTS: completed",
                f"TARGET: {target_ip}",
                f"SCAN_TOOL: {result.scan_tool}",
                f"UDP_PORT_COUNT: {len(result.udp_ports)}",
                f"UDP_PORTS: {result.udp_ports}",
                "",
                "UDP_SERVICES:",
            ]
            for svc in udp_services:
                lines.append(
                    f"  {svc.port}/udp - {svc.service}"
                    f"{' (' + svc.banner[:60] + '...)' if svc.banner else ''}"
                )
            if result.warnings:
                lines.append(f"\nWARNINGS: {'; '.join(result.warnings[:5])}")
            if result.errors:
                lines.append(f"ERRORS: {'; '.join(result.errors[:5])}")
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: UDP recon failed - {exc}"

    @mcp.tool()
    @require_allowlist()
    def run_osint_recon(target_ip: str) -> str:
        """Run passive OSINT aggregation against the single target.

        PASSIVE ONLY: queries PUBLIC data sources (reverse DNS, DNS AAAA for
        IPv6, crt.sh certificate transparency, optional Shodan) about the single
        target. No active scanning, no third-party submissions. IPv6 is PASSIVE
        ONLY (DNS AAAA lookup; no active IPv6 scan).

        Args:
            target_ip: IPv4 address of the single authorized target.

        Returns:
            OSINT summary: ipv6 addresses, reverse dns, cert-transparency count,
            shodan enabled/disabled.
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        from tools.recon_osint import run_osint

        try:
            osint = run_osint(target_ip)
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
                "OSINT: completed",
                f"TARGET: {target_ip}",
                f"HOSTNAME: {hostname or '(none)'}",
                f"REVERSE_DNS: {rev or '(none)'}",
                f"IPV6_ADDRESSES: {ipv6 if ipv6 else '(none)'}",
                f"CERT_TRANSPARENCY: {ct_count} certs",
                f"SHODAN: {'enabled' if shodan_enabled else 'disabled'}",
            ]
            if isinstance(shodan, dict) and shodan.get("error"):
                lines.append(f"SHODAN_ERROR: {shodan['error']}")
            return "\n".join(lines)
        except Exception as exc:
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
        except Exception as exc:
            return f"ERROR: recon diff failed - {exc}"
