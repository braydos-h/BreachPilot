"""Validation utilities for security testing commands and targets.

Provides strict IPv4 validation, command sanitization, target allowlist
enforcement, tool preflight checks, and service banner parsing.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
from typing import Any

# Strict IPv4 regex: four octets 0-255 separated by dots, anchored.
_STRICT_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Regex to find an IP-like substring that may have trailing garbage.
_LOOSE_IPV4_RE = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^0-9\.].*)?$"
)

# Token that is a valid IPv4 optionally followed by a CIDR suffix (/NN) and/or
# a port suffix (:NNNN). Such tokens are legitimate and must NOT be "corrected"
# by stripping the /CIDR or :port portion (M18).
_IP_WITH_SUFFIX_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?(:\d+)?$")

# Regex to find IP addresses embedded in a larger command string.
_EMBEDDED_IPV4_RE = re.compile(
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)


def validate_ipv4(ip: str) -> bool:
    """Validate an IPv4 address with a strict regex and ipaddress module."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not _STRICT_IPV4_RE.match(ip):
        return False
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def sanitize_ipv4(ip: str) -> str | None:
    """Return a clean IPv4 if possible, or None if unrecoverable.

    Strips trailing non-digit/non-dot garbage (e.g., '43.229.61.92oos'
    becomes '43.229.61.92').
    """
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()
    if validate_ipv4(ip):
        return ip
    m = _LOOSE_IPV4_RE.match(ip)
    if m:
        candidate = m.group(1)
        if validate_ipv4(candidate):
            return candidate
    return None


def extract_ips_from_command(command: str) -> list[str]:
    """Extract all potential IPv4 addresses from a command string."""
    if not command:
        return []
    found: list[str] = []
    for m in _EMBEDDED_IPV4_RE.finditer(command):
        candidate = m.group(0)
        if validate_ipv4(candidate):
            found.append(candidate)
    return found


def sanitize_target_in_command(command: str) -> tuple[str, list[dict[str, Any]]]:
    """Sanitize a shell command by fixing malformed IP targets.

    Returns:
        (sanitized_command, corrections) where corrections is a list of
        dicts with keys: original, sanitized, valid.
    """
    if not command or not isinstance(command, str):
        return command, []

    corrections: list[dict[str, Any]] = []
    sanitized = command

    # Strategy: find any token that looks like an IP with trailing garbage.
    # We tokenize loosely by whitespace and common separators.
    tokens = re.split(r"(\s+|=[= ]*)", sanitized)
    new_tokens: list[str] = []
    for token in tokens:
        # M18: A token that is a valid IPv4 with an optional CIDR suffix and/or
        # port suffix (e.g. "10.0.0.5/24", "10.0.0.5:80", "10.0.0.5/24:80" not
        # matched here) is legitimate -- keep it verbatim. Only the octet portion
        # (before / or :) needs to validate as an IPv4.
        if _IP_WITH_SUFFIX_RE.match(token):
            octet_part = re.split(r"[/:]", token, 1)[0]
            if validate_ipv4(octet_part):
                new_tokens.append(token)
                continue
        # If token contains an IP-like sequence
        m = _LOOSE_IPV4_RE.match(token)
        if m:
            # Check whether the *entire* token is already a valid IP
            if validate_ipv4(token):
                new_tokens.append(token)
                continue
            # Otherwise try to sanitize trailing garbage
            fixed = sanitize_ipv4(token)
            if fixed:
                corrections.append({
                    "original": token,
                    "sanitized": fixed,
                    "valid": True,
                })
                new_tokens.append(fixed)
                continue
        new_tokens.append(token)

    sanitized = "".join(new_tokens)
    return sanitized, corrections


def is_local_target(target_ip: str) -> bool:
    """True when the target is the operator's own host (loopback or a local IF IP).

    When the target is local, filesystem reads and local enumeration are cheaper
    and safer than network brute-force -- the agent already has the box. This
    drives the LOCAL TARGET PLAYBOOK injected by ``build_exploit_system_prompt``:
    it tells the model to read ``/etc/shadow``, ``~/.ssh/``, SUID binaries, etc.
    BEFORE spraying its own SSH listener.

    Returns True for:
      - ``localhost`` (case-insensitive)
      - any loopback IP (127.0.0.0/8, ::1) per ``ipaddress.is_loopback``
      - any IP bound on a local interface (``socket.getaddrinfo`` of the
        hostname) -- e.g. the box's own 192.168.x.x / 10.x.x.x address
    Best-effort: any parse error returns False (treat as remote, the safe
    default for the network playbook).
    """
    if not target_ip or not isinstance(target_ip, str):
        return False
    s = target_ip.strip()
    if not s:
        return False
    if s.lower() == "localhost":
        return True
    # Loopback (127.0.0.0/8, ::1)
    try:
        if ipaddress.ip_address(s).is_loopback:
            return True
    except ValueError:
        pass
    # Matches a non-loopback IP bound on a local interface (e.g. 192.168.1.5).
    try:
        local_ips: set[str] = set()
        host = socket.gethostname()
        try:
            local_ips.add(socket.gethostbyname(host).split("%")[0])
        except OSError:
            pass
        for info in socket.getaddrinfo(host, None):
            try:
                local_ips.add(info[4][0].split("%")[0])
            except (IndexError, TypeError):
                continue
        if s in local_ips:
            return True
    except OSError:
        pass
    return False


def is_tool_installed(tool_name: str) -> bool:
    """Check whether a common tool binary is available on PATH."""
    return shutil.which(tool_name) is not None


def preflight_command_check(command: str) -> dict[str, Any]:
    """Run pre-flight checks on a terminal command before execution.

    Returns a dict with:
        - valid: bool
        - original_command: str
        - sanitized_command: str
        - corrections: list of dicts
        - missing_tools: list of tool names not found on PATH
        - blocked_reason: str or None
    """
    if not command or not command.strip():
        return {
            "valid": False,
            "original_command": command,
            "sanitized_command": command,
            "corrections": [],
            "missing_tools": [],
            "blocked_reason": "Empty command.",
        }

    sanitized, corrections = sanitize_target_in_command(command)

    # Detect tools used in the command for preflight warnings.
    common_tools = ["nmap", "rustscan", "masscan", "curl", "nc", "ncat", "python", "python3"]
    missing_tools = []
    cmd_lower = sanitized.lower()
    for tool in common_tools:
        # Heuristic: tool appears at start of command or after pipe/semicolon/&&
        if re.search(rf"(?:^|[;|&]|\s){re.escape(tool)}(?:\s|$)", cmd_lower):
            if not is_tool_installed(tool):
                missing_tools.append(tool)

    return {
        "valid": True,
        "original_command": command,
        "sanitized_command": sanitized,
        "corrections": corrections,
        "missing_tools": missing_tools,
        "blocked_reason": None,
    }


def is_target_in_allowlist(target: str, allowed_assets: list[str]) -> bool:
    """Check whether a target is explicitly present in an allowlist.

    Supports exact IPs, CIDR ranges, domains, and wildcard domains.
    """
    if not target or not allowed_assets:
        return False

    target_clean = target.strip().lower()
    for asset in allowed_assets:
        asset_clean = asset.strip().lower()
        if not asset_clean:
            continue

        # Exact match
        if target_clean == asset_clean:
            return True

        # Wildcard domain
        if asset_clean.startswith("*."):
            suffix = asset_clean[1:]  # e.g. ".example.com"
            if target_clean.endswith(suffix):
                return True

        # CIDR match
        try:
            network = ipaddress.ip_network(asset_clean, strict=False)
            addr = ipaddress.ip_address(target_clean)
            if addr in network:
                return True
        except ValueError:
            pass

        # IP exact match via ipaddress
        try:
            if str(ipaddress.ip_address(target_clean)) == str(ipaddress.ip_address(asset_clean)):
                return True
        except ValueError:
            pass

    return False


def parse_service_banners(text: str) -> list[dict[str, Any]]:
    """Parse check_os / nmap style output into structured service records.

    Extracts:
        - host
        - port
        - protocol
        - service
        - product
        - version
        - os_guess
    """
    records: list[dict[str, Any]] = []
    host = ""

    # Try to extract TARGET or host from lines like "TARGET: 10.0.0.1"
    host_match = re.search(r"TARGET[:\s]+(\S+)", text)
    if host_match:
        host = host_match.group(1)

    # Extract OS verdict
    os_guess = ""
    os_match = re.search(r"OS_VERDICT[:\s]+(\S+)", text)
    if os_match:
        os_guess = os_match.group(1)
    else:
        # Fallback heuristic for OS hints
        if "WINDOWS" in text.upper():
            os_guess = "WINDOWS"
        elif "LINUX" in text.upper():
            os_guess = "LINUX"

    # Pattern: "Port 22/tcp: open - OpenSSH_8.5p1"
    port_re = re.compile(
        r"Port\s+(\d+)/(tcp|udp):\s+open\s+-\s+(.*?)$",
        re.IGNORECASE | re.MULTILINE,
    )

    for m in port_re.finditer(text):
        port = int(m.group(1))
        protocol = m.group(2).lower()
        banner = m.group(3).strip()

        product = ""
        version = ""
        service = ""

        # Infer service from port
        common_ports = {
            22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            445: "smb", 3389: "rdp", 8080: "http-proxy",
        }
        service = common_ports.get(port, "unknown")

        # Extract product and version from banner heuristics
        # Example: "OpenSSH_8.5p1" or "Apache/2.4.41"
        prod_ver_match = re.match(r"([A-Za-z0-9\-_]+)[_/\s]+([\d\.\-p]+[a-z0-9]*)", banner)
        if prod_ver_match:
            product = prod_ver_match.group(1)
            version = prod_ver_match.group(2)
        elif banner and banner != "(no banner)":
            product = banner

        # Override service from product name hints
        if "ssh" in product.lower() or "openssh" in product.lower():
            service = "ssh"
        elif "apache" in product.lower() or "nginx" in product.lower() or "iis" in product.lower():
            service = "http"
        elif "microsoft-ds" in banner.lower() or "smb" in banner.lower():
            service = "smb"
        elif "rdp" in product.lower() or "ms-wbt-server" in banner.lower():
            service = "rdp"

        records.append({
            "host": host,
            "port": port,
            "protocol": protocol,
            "service": service,
            "product": product,
            "version": version,
            "os_guess": os_guess,
            "raw_banner": banner,
        })

    return records
