"""Defensive MCP server — exposes scope-enforced, scope-gated scan tools.

Phase 0.4 of the plan: this file was referenced by the README and the
architecture diagram but did not exist. It mirrors the structure of
`mcp_exploit_server.py` but only exposes the *defensive* surface:

    run_nmap_ping_sweep      (discovery)
    run_nmap_triage_scan     (top-port triage on discovered hosts)
    run_nmap_basic_scan      (per-host service/version detection)
    run_nmap_service_scan    (per-host service/script/OS scan)
    run_nmap_vuln_scan       (NSE vuln scripts on a single host)
    run_limited_terminal     (allowlisted Nmap commands only)
    search_vulnerability_intel (sanitized public vuln/advisory search)
    search_cve_intel         (NVD CVE lookup, rate-limited and cached)

All tools require the caller to provide an asset that has been
approved in the mission scope. Out-of-scope requests are rejected.
"""
# NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Tools used by this server
try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - import guard
    raise RuntimeError(
        "The MCP Python SDK is not installed. Run: "
        "python -m pip install -r requirements.txt"
    ) from exc

from tools.api_key_store import (
    DEFAULT_API_KEY_FILE,
    disabled_research_tools_message,
    load_api_keys_into_env,
    research_api_keys_available,
)
from tools.cve_lookup import format_cve_results
from tools.mcp_shared import build_cve_search, build_researcher, load_config, run_mcp_http_server
from tools.validation_utils import (
    is_target_in_allowlist,
    preflight_command_check,
    sanitize_target_in_command,
    validate_ipv4,
)

# ── Scope helpers ───────────────────────────────────────────────────


def _normalize_allowlist(allow: list[str] | None) -> list[str]:
    """Normalize the allowlist: strip comments, expand CIDRs, dedupe."""
    if not allow:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in allow:
        if not entry:
            continue
        e = entry.strip()
        if e.startswith("#"):
            continue
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _is_in_allowlist(asset: str, allow: list[str]) -> bool:
    """Scope check for a defensive-server target (IP, hostname, or CIDR subnet).

    Tier 4: delegates the IP / wildcard / IP-in-CIDR cases to
    ``tools.validation_utils.is_target_in_allowlist`` (deduping one of the
    three allowlist implementations in this repo) AND adds the CIDR-subset-of-
    CIDR case the old hand-rolled matcher missed: a ``/24`` *asset* against a
    ``/16`` *allow* entry was previously rejected because ``ipaddress.ip_address``
    raises on a CIDR, skipping the containment loop entirely. Now a CIDR asset
    is accepted when it is ``subnet_of`` an allowed CIDR (or exact-equal).
    """
    if not allow:
        return False
    if is_target_in_allowlist(asset, allow):
        return True
    # CIDR asset subset of an allowed CIDR (e.g. allow 10.0.0.0/16, asset
    # 10.0.0.0/24). is_target_in_allowlist only does single-IP containment, so
    # handle network-subset here.
    try:
        asset_net = ipaddress.ip_network(asset.strip(), strict=False)
    except ValueError:
        return False
    for entry in allow:
        try:
            allow_net = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            continue
        if asset_net == allow_net or asset_net.subnet_of(allow_net):
            return True
    return False


# ── Nmap runner ─────────────────────────────────────────────────────

# Runtime nmap config, set by ``create_mcp_server`` from ``config["nmap"]``.
# Defaults keep the legacy behavior (binary "nmap" on PATH, no sudo, and an
# unprivileged fallback that downgrades root-requiring flags instead of
# failing on a non-root Linux host).
_NMAP_BINARY: str = "nmap"
_NMAP_USE_SUDO: bool = False
_NMAP_PRIV_FALLBACK: bool = True

# The privilege/downgrade helpers live in the shared ``tools.nmap_priv`` module
# so the defensive server and the exploit recon pipeline apply the SAME
# behaviour. Re-exported here so existing ``from mcp_server import ...`` imports
# (see tests/test_linux_support.py) keep working.
from tools.nmap_priv import (  # noqa: E402,F401  (re-exported for back-comat)
    _NMAP_ROOT_FLAGS,
    _downgrade_unprivileged_args,
    _is_privileged,
    apply_nmap_privilege,
    is_privilege_error,
)


async def _run_nmap(args: list[str], timeout: int = 300) -> dict[str, Any]:
    """Run an nmap command and return parsed output.

    Returns a dict with keys: ok, stdout, stderr, exit_code, duration_s.
    Offloads to a thread so the event loop is not blocked under HTTP transport.

    Linux privilege handling: ``-O`` / ``-sS`` and friends require root. When
    unprivileged and ``nmap.sudo`` is off, the root-requiring flags are
    downgraded (see ``_downgrade_unprivileged_args``) so the scan still
    produces results instead of failing. When ``nmap.sudo`` is on and the host
    is unprivileged, nmap is run via ``sudo -n`` (non-interactive -- fails fast
    instead of hanging on a password prompt).
    """
    start = time.time()
    argv, downgrade_note = apply_nmap_privilege(
        [_NMAP_BINARY, *args], sudo=_NMAP_USE_SUDO, priv_fallback=_NMAP_PRIV_FALLBACK
    )

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stderr = proc.stderr or ""
        if downgrade_note:
            stderr = (stderr + "\n" + downgrade_note).strip()
        return {
            "ok": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": stderr,
            "exit_code": proc.returncode,
            "duration_s": round(time.time() - start, 2),
        }
    except FileNotFoundError:
        path_hint = _NMAP_BINARY
        return {
            "ok": False,
            "stdout": "",
            "stderr": (
                f"nmap binary '{path_hint}' not found. Install nmap or set "
                f"nmap.path in config.yaml to its full path."
            ),
            "exit_code": -1,
            "duration_s": round(time.time() - start, 2),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "stdout": "",
            "stderr": f"nmap timed out after {timeout}s",
            "exit_code": -1,
            "duration_s": round(time.time() - start, 2),
        }


# ── Server factory ──────────────────────────────────────────────────


def create_mcp_server(
    *,
    nvd: NVDClient,
    researcher: WebResearcher,
    config: dict[str, Any] | None = None,
    allow: list[str] | None = None,
) -> FastMCP:
    """Create the defensive MCP server.

    Args:
        nvd: shared NVD client
        researcher: shared web researcher
        config: full loaded config (used for timeouts/limits)
        allow: scope allowlist (loaded from config.research.allowed_assets
               if not provided)
    """
    config = config or {}
    research_cfg = config.get("research", {}) or {}
    allowlist = _normalize_allowlist(
        allow or research_cfg.get("allowed_assets", [])
    )

    default_timeout = int(research_cfg.get("nmap_timeout_seconds", 300))

    # Thread the nmap runtime config (path / sudo / priv_fallback) into the
    # module-level globals read by ``_run_nmap``. Falls back to the safe
    # defaults when the optional ``nmap`` section is absent.
    global _NMAP_BINARY, _NMAP_USE_SUDO, _NMAP_PRIV_FALLBACK
    nmap_cfg = config.get("nmap", {}) or {}
    _NMAP_BINARY = nmap_cfg.get("path") or "nmap"
    _NMAP_USE_SUDO = bool(nmap_cfg.get("sudo", False))
    _NMAP_PRIV_FALLBACK = bool(nmap_cfg.get("priv_fallback", True))

    mcp = FastMCP("ai-nmap-defensive")

    # ── run_nmap_ping_sweep ──────────────────────────────────────
    @mcp.tool()
    async def run_nmap_ping_sweep(subnet: str) -> dict[str, Any]:
        """Run `nmap -sn` against an approved subnet. Returns live hosts.

        Args:
            subnet: CIDR subnet (e.g. '10.0.0.0/24')
        """
        if not _is_in_allowlist(subnet, allowlist):
            return {"ok": False, "error": f"subnet {subnet!r} is not in scope"}
        return await _run_nmap(["-sn", "-T4", subnet], timeout=default_timeout)

    # ── run_nmap_triage_scan ─────────────────────────────────────
    @mcp.tool()
    async def run_nmap_triage_scan(subnet: str, top_ports: int = 100) -> dict[str, Any]:
        """Top-port triage scan against an approved subnet."""
        if not _is_in_allowlist(subnet, allowlist):
            return {"ok": False, "error": f"subnet {subnet!r} is not in scope"}
        return await _run_nmap(
            ["-sS", "--top-ports", str(top_ports), "-T4", subnet],
            timeout=default_timeout,
        )

    # ── run_nmap_basic_scan ──────────────────────────────────────
    @mcp.tool()
    async def run_nmap_basic_scan(ip: str) -> dict[str, Any]:
        """Service/version detection on a single approved host."""
        if not validate_ipv4(ip) or not _is_in_allowlist(ip, allowlist):
            return {"ok": False, "error": f"host {ip!r} is not in scope"}
        return await _run_nmap(["-sV", "-T4", ip], timeout=default_timeout)

    # ── run_nmap_service_scan ────────────────────────────────────
    @mcp.tool()
    async def run_nmap_service_scan(ip: str) -> dict[str, Any]:
        """Service + scripts + OS detection on a single approved host.

        Equivalent to `nmap -sV -sC -O -T4 <ip>`.
        """
        if not validate_ipv4(ip) or not _is_in_allowlist(ip, allowlist):
            return {"ok": False, "error": f"host {ip!r} is not in scope"}
        return await _run_nmap(["-sV", "-sC", "-O", "-T4", ip], timeout=default_timeout)

    # ── run_nmap_vuln_scan ───────────────────────────────────────
    @mcp.tool()
    async def run_nmap_vuln_scan(ip: str) -> dict[str, Any]:
        """Run the Nmap NSE `vuln` category on a single approved host."""
        if not validate_ipv4(ip) or not _is_in_allowlist(ip, allowlist):
            return {"ok": False, "error": f"host {ip!r} is not in scope"}
        return await _run_nmap(["-sV", "--script", "vuln", "-T4", ip], timeout=default_timeout)

    # ── run_limited_terminal ─────────────────────────────────────
    @mcp.tool()
    async def run_limited_terminal(command: str) -> dict[str, Any]:
        """Run a command if it is an allowlisted Nmap command and the
        target is in scope. Anything else is rejected.

        The allowlist is intentionally tiny: nmap, nmap -sn, nmap -sV,
        nmap -sC, nmap -O, nmap --script, nmap -A, and the -sS/-sT
        forms. Shell metacharacters are rejected outright.
        """
        decision = preflight_command_check(command)
        if not decision.get("valid", False):
            return {"ok": False, "error": decision.get("blocked_reason", "rejected")}
        # Whitelist of approved nmap command shapes
        nmap_patterns = [
            r"^nmap\s+-sn\b",
            r"^nmap\s+-sV\b",
            r"^nmap\s+-sC\b",
            r"^nmap\s+-O\b",
            r"^nmap\s+-sS\b",
            r"^nmap\s+-sT\b",
            r"^nmap\s+-A\b",
            r"^nmap\s+--script\s+\S+",
        ]
        if not any(re.match(p, command.strip()) for p in nmap_patterns):
            return {"ok": False, "error": f"command shape {command!r} not in allowlist"}
        # Every IP/CIDR argument must be in scope
        sanitized, _corrections = sanitize_target_in_command(command)
        for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", command):
            if not _is_in_allowlist(token, allowlist):
                return {"ok": False, "error": f"target {token!r} in command is not in scope"}
        return await _run_nmap(sanitized.split()[1:], timeout=default_timeout)

    # ── search_vulnerability_intel ───────────────────────────────
    @mcp.tool()
    def search_vulnerability_intel(query: str) -> str:
        """Defensive public vulnerability/advisory search. The query is
        sanitized: shell metacharacters, private IPs, hostnames, and
        offensive terms are rejected.
        """
        if not research_api_keys_available(config):
            return disabled_research_tools_message(config)
        return researcher.search(query)

    # ── search_cve_intel ─────────────────────────────────────────
    @mcp.tool()
    def search_cve_intel(query: str) -> str:
        """NVD CVE lookup for a known product/version string.

        Args:
            query: search string (e.g. 'apache 2.4.49')
        """
        entries = nvd.search_sync(query)
        return format_cve_results(entries, query)

    return mcp


# ── CLI entrypoint ──────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Defensive MCP server for the NetAttackAI agent."
    )
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--allow-public-bind",
        action="store_true",
        help="Allow binding a non-loopback interface (requires MCP_ALLOW_PUBLIC_BIND=1 too).",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    load_api_keys_into_env(DEFAULT_API_KEY_FILE)
    nvd = build_cve_search(config)
    researcher = build_researcher(config)
    server = create_mcp_server(nvd=nvd, researcher=researcher, config=config)

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        # HTTP transport is loopback-only by default; a non-loopback bind
        # requires --allow-public-bind AND MCP_ALLOW_PUBLIC_BIND=1, and an
        # optional MCP_HTTP_TOKEN bearer secret is honored when set. See
        # tools.mcp_shared.run_mcp_http_server (shared with mcp_exploit_server).
        run_mcp_http_server(server, args.host, args.port, allow_public_bind=args.allow_public_bind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
