"""Native Python TCP port scanner — the no-privilege fallback tier.

Extracted from ``tools/mcp_tools/recon.py:quick_scan`` so the recon pipeline
(``tools/recon_pipeline.py``) can fall back to it when nmap/rustscan/masscan
are unavailable or fail for lack of root, and so the MCP ``quick_scan`` tool
delegates to the same implementation instead of holding its own copy.

Socket connects require no special privileges, so this works on a non-root
operator box where SYN/OS scans would fail.
"""

from __future__ import annotations

import asyncio
import socket

# A conservative common-ports list used by the recon pipeline's final
# fallback tier (``PrimaryReconScanner.scan_host``).
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
    6379, 8080, 9200, 27017,
]

_SERVICE_GUESS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-proxy",
    9200: "elasticsearch", 27017: "mongodb",
}


def _probe_port(target: str, port: int, timeout: float = 3.0) -> dict:
    """Synchronous single-port TCP connect probe with banner grab."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((target, port)) == 0:
            banner = ""
            try:
                sock.settimeout(2.0)
                banner = sock.recv(512).decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
            return {
                "port": port,
                "open": True,
                "banner": banner,
                "service_guess": _SERVICE_GUESS.get(port, ""),
            }
        return {"port": port, "open": False, "banner": "", "service_guess": ""}
    except Exception:
        return {"port": port, "open": False, "banner": "", "service_guess": ""}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def socket_scan_sync(target: str, ports: list[int], timeout: float = 3.0) -> list[dict]:
    """Synchronous multi-port scan (used by the sync ``quick_scan`` MCP tool)."""
    return [_probe_port(target, p, timeout) for p in ports]


async def socket_scan(target: str, ports: list[int], timeout: float = 3.0) -> list[dict]:
    """Async multi-port scan — runs probes concurrently in a thread pool so
    the event loop is not blocked on N blocking ``connect_ex`` calls."""
    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(None, _probe_port, target, p, timeout)
        for p in ports
    ]
    return await asyncio.gather(*tasks)


def format_socket_scan_results(target: str, results: list[dict]) -> str:
    """Render scan results in the ``QUICK_SCAN_RESULTS:`` text format the
    MCP ``quick_scan`` tool has always returned."""
    open_results = [r for r in results if r["open"]]
    lines = [f"QUICK_SCAN_RESULTS: {target}", ""]
    for r in results:
        if r["open"]:
            banner = r["banner"] if r["banner"] else "(no banner)"
            lines.append(f"  Port {r['port']}/tcp OPEN ({r['service_guess']}) - {banner}")
    lines += ["", f"SUMMARY: {len(open_results)}/{len(results)} ports open"]
    if not open_results:
        lines.append("NOTE: No ports responded. Target may be down, firewalled, or blocking scans.")
    else:
        lines.append(
            "NEXT STEPS: Research CVEs for discovered services, then write "
            "Python exploits with write_python_file."
        )
    return "\n".join(lines)