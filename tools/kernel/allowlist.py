"""Target-IP allowlist helpers — the ONE attack-mode safety gate.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). The allowlist union
(``exploit.allowed_targets`` + ``EXPLOIT_TARGET`` / ``_IP`` / ``_DOMAIN`` /
``DISCOVERED_TARGETS`` env vars) IS the target-IP lock
(``safety-model.md`` §Exploit Permission Modes). Both flows and every
target-touching MCP tool import from here; ``tools.mcp_shared`` re-exports
for backwards compat.

Ponytail: pure functions + env-var union + ``is_target_in_allowlist``
matcher (supports domains, ``*.wildcard``, CIDR).
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from typing import Any

from tools.validation_utils import is_fqdn, is_target_in_allowlist, validate_target

_MSF_RHOSTS_RE = re.compile(
    r"\bset(?:g)?\s+(?:RHOSTS|RHOST)\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
_MSF_PIVOT_RE = re.compile(
    r"(?i:\bportfwd\b)[^\n]*?(?:\s-r\s+)(\S+)"
    r"|(?i:\broute\s+add\s+)(\S+)"
    r"|(?i:\bautoroute)(?:\s+add|\s+-s)?\s+(\S+)"
)


def _allowed_target_list(config: dict[str, Any] | None) -> list[str]:
    """The effective allowlist = config ``exploit.allowed_targets`` UNION env vars.

    See ``tools.mcp_shared._allowed_target_list`` docstring (verbatim move).
    """
    exploit_cfg = (config or {}).get("exploit", {})
    allowed = list(exploit_cfg.get("allowed_targets", []))
    for env_key in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN"):
        val = os.environ.get(env_key, "").strip()
        if val and val not in allowed:
            allowed.append(val)
    discovered = os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "").strip()
    if discovered:
        for tok in discovered.split(","):
            tok = tok.strip()
            if tok and tok not in allowed:
                allowed.append(tok)
    return allowed


def add_discovered_target(host: str, ip: str | None = None) -> None:
    """Runtime-extend the allowlist with a discovered subdomain (verbatim move)."""
    if not host:
        return
    vals = [t.strip() for t in os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "").split(",") if t.strip()]
    if host not in vals:
        vals.append(host)
    if ip and ip not in vals and ip != host:
        vals.append(ip)
    os.environ["EXPLOIT_DISCOVERED_TARGETS"] = ",".join(vals)


def _check_allowlist(target_ip: str, config: dict[str, Any] | None) -> tuple[bool, str]:
    """Return (allowed, reason) for target_ip against config allowlist (verbatim move)."""
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return True, "allowlist not required"
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return False, "require_explicit_allowlist is True but allowed_targets is empty"
    if is_target_in_allowlist(target_ip, allowed_targets):
        return True, "target in allowlist"
    return False, (
        f"Target IP {target_ip} is not in the explicit allowlist. "
        f"Add it to config.yaml exploit.allowed_targets to authorize."
    )


def _extract_msf_rhosts(text: str) -> list[str]:
    """Extract RHOSTS/RHOST + pivot hosts from msfconsole text (verbatim move)."""
    if not text:
        return []
    out: list[str] = []
    for m in _MSF_RHOSTS_RE.findall(text):
        tok = next((g for g in m if g), "").strip().strip("\"';")
        if tok and tok not in out:
            out.append(tok)
    for m in _MSF_PIVOT_RE.finditer(text):
        for g in m.groups():
            if g:
                tok = g.strip().strip("\"';")
                if tok and tok not in out:
                    out.append(tok)
    return out


def check_targets_allowlist(
    targets: list[str], config: dict[str, Any] | None
) -> tuple[bool, str]:
    """Return (allowed, reason) for a list of hosts (verbatim move)."""
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return True, "allowlist not required"
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return False, "require_explicit_allowlist is True but allowed_targets is empty"
    for t in targets:
        if not t:
            continue
        if not is_target_in_allowlist(t, list(allowed_targets)):
            return False, (
                f"Host {t} is not in the explicit allowlist. "
                f"Add it to config.yaml exploit.allowed_targets to authorize."
            )
    return True, "all named hosts in allowlist"


# H4: scanner verbs whose positional arguments are the scan targets.
# ``command_analyzer._NETVERB_HOST_RE`` covers ssh/nc/curl/... but omits scanners
# (nmap/masscan/rustscan/...), so a bare hostname/CIDR/FQDN target after a
# scanner would slip past the allowlist gate. The old single-regex approach
# treated every ``-flag`` as value-less, so a space-separated value flag like
# nmap ``-p 445,139,135,389`` had its *port list* captured as the "target" and
# the whole command was blocked even when the real target was authorized. The
# argv-walk below fixes that.
_SCANNER_VERBS = {
    "nmap",
    "masscan",
    "rustscan",
    "nikto",
    "nuclei",
    "gobuster",
    "feroxbuster",
    "sqlmap",
    "smbclient",
    "enum4linux",
    "hydra",
    "whatweb",
    "wpscan",
    "dirb",
    "dirbuster",
    "amass",
    "sublist3r",
}

# Flags whose space-separated value is a dotted/host-shaped token that is NOT
# the scan target -- output files (-oN scan.txt), wordlists (-w rockyou.txt),
# exclude/include files (-iL/--excludefile), request/config files, the source
# IP (-S), and the proxy. Skipping their value prevents a dotted filename or a
# source IP from being mistaken for the target.
_SCANNER_VALUE_FLAGS = {
    "-o",
    "--output",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "-oS",
    "-oM",
    "--output-file",
    "-w",
    "--wordlist",
    "-iL",
    "--excludefile",
    "--includefile",
    "-r",
    "--request-file",
    "-c",
    "--config-file",
    "--config",
    "-L",
    "-P",
    "--proxy",
    "--proxy-file",
    "--auth-file",
    "-S",
    "--source-ip",
}

_SHELL_SEPARATORS = {"|", ";", "&&", "||", ">", "<", ">>", "2>", "&"}


def _scanner_token_is_host(token: str) -> bool:
    """True if ``token`` is host-shaped and thus a plausible scan target."""
    if not token:
        return False
    if validate_target(token):
        return True
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        pass
    if token.startswith("*."):
        rest = token[2:]
        return bool(rest) and is_fqdn(rest)
    return False


def _is_scanner_verb_token(token: str) -> bool:
    """True if ``token`` invokes a scanner (basename-aware)."""
    base = token.replace("\\", "/").split("/")[-1]
    return base.lower() in _SCANNER_VERBS


def _extract_scanner_targets(command: str) -> list[str]:
    """Extract host-shaped scan-target tokens from a scanner command (Phase 3 move).

    Verbatim from ``tools.mcp_tools.registry._extract_scanner_targets``.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    targets: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        if _is_scanner_verb_token(tokens[i]):
            i += 1
            while i < n:
                t = tokens[i]
                if t in _SHELL_SEPARATORS or _is_scanner_verb_token(t):
                    break
                if t.startswith("-"):
                    if t in _SCANNER_VALUE_FLAGS and i + 1 < n:
                        i += 2
                        continue
                    i += 1
                    continue
                if _scanner_token_is_host(t) and t not in targets:
                    targets.append(t)
                i += 1
            continue
        i += 1
    return targets
