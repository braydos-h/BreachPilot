"""Detection-coverage planning + audit-footprint summary helpers (READ-ONLY).

This module is pure-stdlib and performs NO network, time, or random behavior at
import time. It exists to support the read-only detection/planning attack
modules in ``tools/attack_modules/modules/detection.py``:

- ``canary_command`` / ``detection_probe_plan`` build a PLAN of canary actions
  the operator deploys against their OWN authorized target to validate that
  their SIEM/IDS/FIM detection coverage fires on attacker-like behavior. Nothing
  here executes anything; it only produces plan dicts.
- ``footprint_summary`` reduces an audit-record list (e.g. from
  ``exploit_audit.jsonl``) into a small summary dict used by the OPSEC posture
  report. The audit trail is append-only/tamper-evident and is NEVER mutated by
  this module -- it is read for reporting only.

No Flow B imports. No target-IP allowlist interaction. All functions are
side-effect free and deterministic.
"""

from __future__ import annotations

import re
from typing import Any

# Noisy-command patterns for the OPSEC footprint (mirrors tools/opsec.py
# _NOISY_PATTERNS). A record counts as noisy when its ``noisy`` flag is set OR
# its command string matches one of these (case-insensitive substring).
_NOISY_PATTERNS: tuple[str, ...] = (
    "-t5",
    "--script=vuln",
    "masscan",
    "hydra",
    "nuclei",
    "ffuf",
    "gobuster",
    "dirb",
    "crackmapexec",
    "nmap -su",
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_HOST_RE = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)


def _extract_egress(record: dict[str, Any], sink: set[str]) -> None:
    """Scan a record's string values for IPv4 tokens and URL authorities.

    Used to summarize the egress footprint (which hosts/IPs the run touched)
    without mutating the record. Tolerant of any nested structure.
    """

    def walk(obj: Any) -> None:
        if isinstance(obj, str):
            for m in _IPV4_RE.findall(obj):
                sink.add(m)
            for m in _URL_HOST_RE.findall(obj):
                sink.add(m)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)

    try:
        walk(record)
    except Exception:  # noqa: BLE001 -- never let a malformed record raise
        pass


def canary_command(
    category: str,
    description: str,
    command: str,
    detection_hint: str,
    *,
    target_ip: str = "",
) -> dict[str, Any]:
    """Build a single canary-action plan entry (read-only planning artifact).

    ``target_ip`` is recorded so the operator can confirm the canary is scoped
    to the authorized target. No execution happens here.
    """
    return {
        "category": category,
        "description": description,
        "command": command,
        "detection_hint": detection_hint,
        "target_ip": target_ip,
        "read_only": True,
    }


def detection_probe_plan(target_ip: str) -> list[dict[str, Any]]:
    """Return a 4-item canary plan to test authorized-target detection coverage.

    Each entry describes an attacker-like action the operator may deploy against
    their OWN target, plus the detection surface it should trip (SIEM/IDS/FIM/EDR).
    This is PLANNING ONLY -- nothing is executed. The plan is target-locked to
    ``target_ip``.
    """
    return [
        canary_command(
            category="auth",
            description="Failed SSH login from a synthetic source IP",
            command=f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes operator_canary@{target_ip} true",
            detection_hint="SIEM / auth logs: failed SSH login from a new source IP",
            target_ip=target_ip,
        ),
        canary_command(
            category="file",
            description="Canary file creation in a sensitive directory",
            command=f"echo breachpilot-canary > /tmp/.breachpilot_canary_{target_ip}",
            detection_hint="FIM: new file written under a monitored directory",
            target_ip=target_ip,
        ),
        canary_command(
            category="exec",
            description="Suspicious recon command execution on the target",
            command="whoami /priv && systeminfo",
            detection_hint="EDR: suspicious recon command (privilege enumeration)",
            target_ip=target_ip,
        ),
        canary_command(
            category="network",
            description="Outbound connection to a known-bad / C2-like port",
            command=f"curl -sS -o /dev/null http://{target_ip}:4444/",
            detection_hint="IDS / NSM: outbound connection to a C2-like port (4444)",
            target_ip=target_ip,
        ),
    ]


def footprint_summary(audit_records: list[Any] | None) -> dict[str, Any]:
    """Reduce an audit-record list into a small summary dict (read-only).

    Accepts a list of dicts (the shape ``exploit_audit.jsonl`` lines decode to)
    and returns counts. Tolerant of ``None`` (treated as ``[]``) and of
    non-dict entries (skipped). Does NOT mutate the input list or the records.
    """
    records = audit_records or []
    total = 0
    noisy = 0
    commands = 0
    targets: set[str] = set()
    tools: set[str] = set()
    egress: set[str] = set()
    noisy_examples: list[str] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        total += 1
        cmd_str = str(rec.get("command") or "")
        is_noisy = bool(rec.get("noisy")) or any(p in cmd_str.lower() for p in _NOISY_PATTERNS)
        if is_noisy:
            noisy += 1
            if cmd_str and len(noisy_examples) < 5:
                noisy_examples.append(cmd_str)
        tool = rec.get("tool") or rec.get("action")
        if tool:
            tools.add(str(tool))
            if tool in ("run_exploit_terminal", "run_python_file", "lateral_exec"):
                commands += 1
        if rec.get("command"):
            commands += 1
        t = rec.get("target") or rec.get("target_ip") or rec.get("asset")
        if t:
            targets.add(str(t))
        _extract_egress(rec, egress)
    return {
        "total_actions": total,
        "noisy_actions": noisy,
        "commands_executed": commands,
        "unique_targets": len(targets),
        "unique_tools": len(tools),
        # Phase 6.2 enrichment (additive; the OPSEC posture report + planning
        # tools consume these). Existing keys above are preserved for backward
        # compatibility with the detection modules' own assertions.
        "commands": commands,
        "distinct_tools": sorted(tools),
        "target_ips": sorted(targets),
        "egress_endpoints": sorted(egress),
        "noisy_examples": noisy_examples,
    }
