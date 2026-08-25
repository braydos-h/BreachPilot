"""Recon data structures and config — extracted from tools.recon_pipeline.

This module is the canonical source for ``ServiceInfo``, ``HostReconResult``,
``ReconConfig`` and ``ToolAvailability``. ``tools.recon_pipeline`` re-exports
these for the 1-release shim window.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any


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
        services = [ServiceInfo.from_dict(s) for s in (data.get("services", []) or []) if isinstance(s, dict)]
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
    # Pre-flight reachability probe (Phase 5). When True, ``recon_host`` runs
    # a couple of bare TCP connects *before* the full Nmap -p- scan and bails
    # to ``no_attack_surface`` when every probe port is definitively refused --
    # a host that answers nothing on the probe set would only confirm the same
    # thing after a 65535-port scan. Ambiguous (timeout/filtered) results fall
    # through to the normal scan so a firewalled-but-live host is never skipped.
    # Default OFF: the full scan is the existing, more thorough reachability
    # test, and this is purely additive (it can only skip work, never add it).
    preflight_probe: bool = False
    preflight_ports: list[int] = field(default_factory=lambda: [80, 443])
    preflight_timeout_ms: int = 1000

    @classmethod
    def from_config(cls, config: dict | None, **overrides: Any) -> "ReconConfig":
        """Build a ReconConfig from a config dict, reading the ``nmap`` section
        for path/sudo/priv_fallback. Extra keyword overrides (e.g.
        ``aggression_level``) are applied on top so callers don't lose fields
        they used to pass positionally."""
        nmap = (config or {}).get("nmap") or {}
        recon_cfg = (config or {}).get("recon") or {}
        import os as _os

        shodan_key = recon_cfg.get("shodan_api_key") or _os.environ.get("SHODAN_API_KEY", "") or ""
        fields: dict[str, Any] = dict(
            nmap_path=nmap.get("path") or "nmap",
            sudo=bool(nmap.get("sudo", False)),
            priv_fallback=bool(nmap.get("priv_fallback", True)),
            # ponytail: make retry budget configurable so operators can set
            # ``recon.max_retries: 0`` to skip straight to the native socket
            # fallback on Windows where nmap -sS/-O hangs on Npcap issues
            # (3 retries × 5-7.5s backoff = ~45s wasted before fallback).
            # Defaults preserve existing behavior.
            max_retries=int(recon_cfg.get("max_retries", 2)),
            retry_delay=float(recon_cfg.get("retry_delay", 5.0)),
            timeout_seconds=int(recon_cfg.get("timeout_seconds", 300)),
            # Production opts into the Phase 3 additive enumerators by
            # default; ``recon.extended_enumerators: false`` disables them.
            extended_enumerators=bool(recon_cfg.get("extended_enumerators", True)),
            shodan_api_key=shodan_key,
        )
        # Phase: extended depth enumerators (all default False / opt-in).
        for flag in (
            "subdomain_enum",
            "vhost_discovery",
            "waf_fingerprint",
            "asn_whois",
            "cloud_metadata_probe",
            "snmp_enum",
            "dns_zone_transfer",
        ):
            fields[flag] = bool(recon_cfg.get(flag, False))
        # Pre-flight reachability probe (Phase 5). All opt-in / default-off so
        # existing tests and single-IP campaigns are byte-identical.
        fields["preflight_probe"] = bool(recon_cfg.get("preflight_probe", False))
        _pp = recon_cfg.get("preflight_ports") or [80, 443]
        fields["preflight_ports"] = [int(p) for p in _pp]
        fields["preflight_timeout_ms"] = int(recon_cfg.get("preflight_timeout_ms", 1000))
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
