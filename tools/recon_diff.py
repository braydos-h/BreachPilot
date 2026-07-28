"""Pure recon-diff: compare two HostReconResult.to_dict() snapshots.

This is detection/reporting only — no network, no scanning, no imports from
tools.recon_pipeline (avoids import cycles; operates on plain dicts).

Public API (imported by the MCP tool layer and Round 2):
    diff_recon(old: dict, new: dict) -> dict
    diff_recon_files(old_path: str, new_path: str) -> dict

CVE extraction mirrors the pipeline regex at mcp_tools/attack_modules.py:1187
(CVE-\\d{4}-\\d{4,}).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

__all__ = ["diff_recon", "diff_recon_files"]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _coerce(value):
    """Treat None as an empty dict; pass dicts through; anything else as {}."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _as_int(value):
    """Best-effort port normalization to int; returns None if not coercible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_cves(snap: dict) -> set:
    """Aggregate CVE ids found in any service script output of a snapshot."""
    cves: set = set()
    services = snap.get("services") or []
    if not isinstance(services, list):
        return cves
    for svc in services:
        if not isinstance(svc, dict):
            continue
        scripts = svc.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for value in scripts.values():
            if value is None:
                continue
            if not isinstance(value, str):
                # Some pipelines store lists of strings; handle defensively.
                if isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, str):
                            cves.update(_CVE_RE.findall(item))
                continue
            cves.update(_CVE_RE.findall(value))
    return cves


def _services_by_port(snap: dict) -> dict:
    """Index a snapshot's services by port (int) -> service dict."""
    out: dict = {}
    services = snap.get("services") or []
    if not isinstance(services, list):
        return out
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = _as_int(svc.get("port"))
        if port is None:
            continue
        out[port] = svc
    return out


def _changed_service_entry(port, field, old_val, new_val) -> dict:
    return {
        "port": port,
        "service": None,
        "field": field,
        "old": old_val,
        "new": new_val,
    }


def diff_recon(old: dict, new: dict) -> dict:
    """Compare two HostReconResult.to_dict() snapshots.

    Returns a dict with:
      target_ip, added_ports (list[int]), removed_ports (list[int]),
      changed_services (list[dict] with port, service, field, old, new for
      version/banner/ssl_info/service changes),
      new_cves (list[str]), lost_cves (list[str]),
      os_changed (bool, old_os, new_os),
      summary (short human-readable string).

    Tolerant: missing keys / empty dicts / None degrade to empty results,
    never raise.
    """
    old = _coerce(old)
    new = _coerce(new)

    # --- target_ip (prefer new, fall back to old) ---
    target_ip = new.get("target_ip")
    if target_ip is None:
        target_ip = old.get("target_ip")

    # --- ports (open + filtered, normalized to int) ---
    def _port_set(snap: dict) -> set:
        ports: set = set()
        for key in ("open_ports", "filtered_ports"):
            val = snap.get(key)
            if not isinstance(val, list):
                continue
            for p in val:
                pi = _as_int(p)
                if pi is None:
                    continue
                ports.add(pi)
        return ports

    old_ports = _port_set(old)
    new_ports = _port_set(new)
    added_ports = sorted(new_ports - old_ports)
    removed_ports = sorted(old_ports - new_ports)

    # --- changed services (compare fields on ports present in both) ---
    old_svcs = _services_by_port(old)
    new_svcs = _services_by_port(new)
    common_ports = sorted(set(old_svcs.keys()) & set(new_svcs.keys()))
    changed_services: list = []
    for port in common_ports:
        o = old_svcs[port]
        n = new_svcs[port]
        for field in ("service", "version", "banner", "ssl_info"):
            o_val = o.get(field)
            n_val = n.get(field)
            # For ssl_info, treat presence (truthiness) so an empty dict and
            # missing key both read as "no ssl_info"; otherwise compare equality.
            if field == "ssl_info":
                o_present = bool(o_val)
                n_present = bool(n_val)
                if o_present != n_present:
                    entry = _changed_service_entry(port, field, o_val, n_val)
                    entry["service"] = o.get("service") or n.get("service")
                    changed_services.append(entry)
            else:
                if o_val != n_val:
                    entry = _changed_service_entry(port, field, o_val, n_val)
                    entry["service"] = o.get("service") or n.get("service")
                    changed_services.append(entry)

    # --- CVEs ---
    old_cves = _extract_cves(old)
    new_cves = _extract_cves(new)
    new_cves_list = sorted(new_cves - old_cves)
    lost_cves_list = sorted(old_cves - new_cves)

    # --- OS ---
    old_os = old.get("os_family")
    new_os = new.get("os_family")
    os_changed = bool(old_os != new_os)

    # --- summary ---
    bits = []
    if added_ports:
        bits.append(f"+{len(added_ports)} ports")
    if removed_ports:
        bits.append(f"-{len(removed_ports)} ports")
    if changed_services:
        bits.append(f"{len(changed_services)} service changes")
    if new_cves_list:
        bits.append(f"+{len(new_cves_list)} CVEs")
    if lost_cves_list:
        bits.append(f"-{len(lost_cves_list)} CVEs")
    if os_changed:
        bits.append("OS changed")
    summary = ", ".join(bits) if bits else "no changes"

    return {
        "target_ip": target_ip,
        "added_ports": added_ports,
        "removed_ports": removed_ports,
        "changed_services": changed_services,
        "new_cves": new_cves_list,
        "lost_cves": lost_cves_list,
        "os_changed": os_changed,
        "old_os": old_os,
        "new_os": new_os,
        "summary": summary,
    }


def diff_recon_files(old_path: str, new_path: str) -> dict:
    """Load two recon_result.json files, call diff_recon, return its dict.

    On any IO/JSON error return {"error": "<message>"} (never raise).
    """
    try:
        with open(Path(old_path), "r", encoding="utf-8") as f:
            old = json.load(f)
        with open(Path(new_path), "r", encoding="utf-8") as f:
            new = json.load(f)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return diff_recon(old, new)