"""Validation utilities for security testing commands and targets.

Provides strict IPv4 validation, command sanitization, target allowlist
enforcement, tool preflight checks, and service banner parsing. Also
provides domain-aware target validation and resolution helpers so the
agent can be pointed at a DNS name (``example.com``) as well as an IP.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
from typing import Any, Sequence

# Strict IPv4 regex: four octets 0-255 separated by dots, anchored.
_STRICT_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# FQDN regex: a dot-separated sequence of labels, the last label being at
# least two alphabetic characters (the TLD). A leading wildcard ``*.`` is
# permitted because operators may add ``*.example.com`` to the allowlist
# by hand and the matcher already supports it. Length bounds follow RFC1035.
_FQDN_RE = re.compile(
    r"^(?:\*\.)?"
    r"(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}$"
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


def is_fqdn(s: str) -> bool:
    """True when ``s`` looks like a fully-qualified domain name.

    Accepts an optional leading ``*.`` wildcard (used by operators when
    they add ``*.example.com`` to the allowlist). Does NOT resolve -- a
    syntactic check only. An IPv4/IPv6 literal returns False.
    """
    if not s or not isinstance(s, str):
        return False
    s = s.strip().lower()
    if not s:
        return False
    # An IP literal is not a domain.
    try:
        ipaddress.ip_address(s)
        return False
    except ValueError:
        pass
    return bool(_FQDN_RE.match(s))


def validate_target(s: str) -> bool:
    """True when ``s`` is a valid IPv4, IPv6, or FQDN target.

    Pure syntax check -- does NOT resolve a domain. Use
    :func:`resolve_target_to_ip` when you need an address.
    """
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if not s:
        return False
    if validate_ipv4(s):
        return True
    try:
        ipaddress.ip_address(s)  # IPv6
        return True
    except ValueError:
        pass
    return is_fqdn(s)


def validate_target_or_ip(s: str) -> bool:
    """Alias for :func:`validate_target` -- the per-MCP-tool gate.

    The per-tool ``validate_ipv4`` pre-gates were replaced with this so
    the exploit MCP tools accept a resolvable domain alongside an IP.
    Pure syntax check; the allowlist gate (``is_target_in_allowlist``)
    is the actual authorization.
    """
    return validate_target(s)


def resolve_target_to_ip(
    host: str,
    *,
    resolver_fn: Any = None,
    family: int = socket.AF_INET,
) -> str | None:
    """Resolve a hostname to a single primary IP string.

    ``resolver_fn(host) -> list[str]`` may be injected for testing (the
    same injectable-resolver pattern used by ``tools.recon_osint``). When
    ``resolver_fn`` is ``None`` the system resolver is used via
    ``socket.getaddrinfo``. ``family`` selects the address family
    (``AF_INET`` for IPv4 by default, ``AF_INET6`` for IPv6). Returns
    ``None`` on any error -- never raises -- so callers can fall back to
    the hostname. If ``host`` is already an IP literal it is returned as-is.
    """
    if not host or not isinstance(host, str):
        return None
    host = host.strip()
    if not host:
        return None
    # Already an IP literal -- return verbatim.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not is_fqdn(host):
        return None
    try:
        if resolver_fn is not None:
            addrs = resolver_fn(host)
            if addrs:
                return str(addrs[0])
            return None
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        for info in infos:
            try:
                return info[4][0].split("%")[0]
            except (IndexError, TypeError):
                continue
        return None
    except (OSError, socket.gaierror, ValueError):
        return None


def resolve_target(host: str, *, resolver_fn: Any = None) -> tuple[str | None, str | None]:
    """Classify and (if needed) resolve a target string.

    Returns ``(ip, domain)``:
      - ``host`` is an IP literal  -> ``(host, None)``
      - ``host`` is a domain       -> ``(resolved_ip_or_None, host)``
      - ``host`` is invalid        -> ``(None, None)``

    The domain is always returned verbatim when ``host`` is a domain, even
    if resolution fails, so callers can still use the domain for HTTP Host
    headers / TLS SNI while falling back to it when no IP is available.
    """
    if not host or not isinstance(host, str):
        return None, None
    host = host.strip()
    if not host:
        return None, None
    try:
        ipaddress.ip_address(host)
        return host, None
    except ValueError:
        pass
    if not is_fqdn(host):
        return None, None
    ip = resolve_target_to_ip(host, resolver_fn=resolver_fn)
    return ip, host


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
      - a domain that resolves to any of the above (best-effort DNS)
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
    # If the target is a domain, resolve it and classify the resolved IP.
    if is_fqdn(s):
        resolved = resolve_target_to_ip(s)
        if resolved is None:
            return False
        return is_local_target(resolved)
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


def is_private_or_local_target(
    target_ip: str, extra_local_cidrs: Sequence[str] | None = None
) -> bool:
    """True when ``target_ip`` is a private / local-network address (not public-routable).

    This is the "local vs public" classifier used by the target-aware OPSEC
    policy: when the operator points the agent at their own lab box or a
    private RFC1918 network, OPSEC hardening (pacing, UA rotation, quiet
    commands) is turned OFF -- the operator already owns the box and wants the
    AI to move freely. For a public Internet-routable target, OPSEC stays ON.

    Distinct from :func:`is_local_target`, which means specifically "the
    operator's own host" (loopback / an IP bound on a local interface) and is
    locked by ``tests/test_local_target.py`` (it returns False for
    ``10.0.0.50``). This function returns True for all RFC1918 / loopback /
    link-local / reserved / ULA space, not just the operator's own box.

    Returns True when ``target_ip`` parses as an IP and any of
    ``ipaddress``'s ``is_private`` / ``is_loopback`` / ``is_link_local`` /
    ``is_reserved`` / ``is_multicast`` / ``is_unspecified`` flags hold, OR when
    it falls inside any operator-configured ``extra_local_cidrs`` entry (CIDR
    or exact IP, matched via :func:`is_target_in_allowlist`). A domain name is
    resolved (best-effort DNS) and the resolved IP is classified; a domain that
    fails to resolve returns False (treat as public, so OPSEC stays on -- the
    safe default for an unknown target).
    """
    if not target_ip or not isinstance(target_ip, str):
        return False
    s = target_ip.strip().lower()
    if not s:
        return False
    if s in {"localhost", "localhost.localdomain", "0.0.0.0"}:
        return True
    # A domain: resolve and classify the resolved IP. DNS failure -> False
    # (public), so OPSEC stays on -- the safe default.
    if is_fqdn(s):
        resolved = resolve_target_to_ip(s)
        if resolved is None:
            return False
        return is_private_or_local_target(resolved, extra_local_cidrs)
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    # Operator-configured local ranges (e.g. a lab CIDR that is technically
    # public space but the operator treats as local). Reuse the allowlist
    # matcher so CIDR containment + exact-IP normalization come for free.
    if extra_local_cidrs and is_target_in_allowlist(s, list(extra_local_cidrs)):
        return True
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
