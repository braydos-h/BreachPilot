"""Attack modules: detection coverage + OPSEC posture (READ-ONLY / planning).

Three AttackModule subclasses that NEVER execute anything against the target
and NEVER set ``shell_type`` / ``privilege_level`` (so ``access_achieved`` is
never flipped). They are target-locked to ``ctx.target_ip`` and produce only
planning / reporting output:

- ``DetectionCoverageProbe`` -- plans canary actions the operator deploys
  against their OWN authorized target to validate SIEM/IDS/FIM detection.
- ``LogSourceEnum`` -- lists candidate log/audit sources for the target OS
  (does not read them).
- ``OPSECPostureReport`` -- reports the active OPSEC posture + audit-footprint
  summary with heuristic recommendations.

These modules HARDEN the agent (pacing/jitter/UA-rotation/DoH/quiet-commands)
and test DETECTION COVERAGE. They do NOT actively evade target defenses: no log
clearing, no timestomping, no EDR/SIEM defeat. The audit trail
(``exploit_audit.jsonl``) is append-only/tamper-evident and is never mutated.

No Flow B imports. No weakening of the target-IP allowlist lock.
"""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


def _ctx_get(ctx: ModuleContext, key: str, default: Any = None) -> Any:
    """Tolerantly read a key from the context.

    Real ``ModuleContext`` is a dataclass with no ``get``, but the detection
    modules may be driven by a richer dict-like context at runtime. Try a
    ``get`` method first (dict-like), then fall back to an attribute, then to
    ``default``. Returns ``default`` when the value is ``None``/missing.
    """
    getter = getattr(ctx, "get", None)
    if callable(getter):
        try:
            val = getter(key, default)
        except TypeError:
            # getter may be dict.get which accepts a default; a single-arg
            # getter would raise TypeError -- handle that gracefully.
            val = getter(key)
        if val is not None:
            return val
    return getattr(ctx, key, default)


class DetectionCoverageProbe(AttackModule):
    name = "detection_coverage_probe"
    description = (
        "Plan canary actions to test the authorized target detection coverage "
        "(read-only planning)."
    )
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}
    # Capability metadata: read-only detection coverage planning.
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "recon"

    def applicability(self, ctx: ModuleContext) -> int:
        # Always selectable but low-priority vs real exploit modules.
        return 15

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Lazy import to avoid import cycles with the detection coverage helpers.
        from tools.detection_coverage import detection_probe_plan

        plan = detection_probe_plan(ctx.target_ip)
        return self._info_result(
            ctx,
            note=(
                "Operator deploys these canaries against the authorized target "
                "and correlates with their SIEM/IDS/FIM."
            ),
            evidence=[f"Planned {len(plan)} canaries across categories: {', '.join(c.get('category', '?') for c in plan)}"],
            references=[
                "https://attack.mitre.org/techniques/T1078/",
                "https://attack.mitre.org/techniques/T1105/",
            ],
            probe_plan=plan,
            target_ip=ctx.target_ip,
        )


class LogSourceEnum(AttackModule):
    name = "log_source_enum"
    description = "Enumerate likely log/audit sources on the target (read-only)."
    target_services = ["ssh", "msrpc", "netbios-ssn", "cifs"]
    target_ports = [22, 445, 139]
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}
    # Capability metadata: read-only log source enumeration.
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Phase 2: ModuleContext carries `target_os`, not `os_family` -- the
        # old getattr(ctx, "os_family", None) was ALWAYS None, so every target
        # (including Windows boxes) was classified as Linux and the Windows
        # log-source list was unreachable. Fall back to os_family for legacy
        # fakes that still expose the old field name.
        os_family = str(getattr(ctx, "target_os", None) or getattr(ctx, "os_family", None) or "").strip().lower()
        if os_family != "windows":
            os_family = "linux"

        if os_family == "windows":
            log_sources = [
                {"channel": "Security", "path": "EventLog:Security",
                 "note": "Login/logon events (4624/4625), privilege use"},
                {"channel": "System", "path": "EventLog:System",
                 "note": "Service/driver events, system errors"},
                {"channel": "Microsoft-Windows-Sysmon/Operational",
                 "path": "EventLog:Microsoft-Windows-Sysmon/Operational",
                 "note": "Process/network/file creation events (if Sysmon deployed)"},
                {"channel": "Application", "path": "EventLog:Application",
                 "note": "Application-level audit events"},
                {"channel": "Windows PowerShell", "path": "EventLog:Windows PowerShell",
                 "note": "PowerShell script block logging (4104) and execution (4103)"},
                {"channel": "TerminalServices-Gateway/Operational",
                 "path": "EventLog:TerminalServices-Gateway/Operational",
                 "note": "RDP session events"},
            ]
        else:
            log_sources = [
                {"path": "/var/log/auth.log",
                 "note": "SSH auth, su/sudo, privilege escalation attempts"},
                {"path": "/var/log/syslog", "note": "General system events"},
                {"path": "/var/log/audit/audit.log",
                 "note": "auditd syscall/SELinux events (if auditd deployed)"},
                {"path": "journald", "note": "systemd-journald binary journal"},
                {"path": "/var/log/messages",
                 "note": "Legacy syslog destination (RHEL-family)"},
                {"path": "/var/log/secure",
                 "note": "Legacy auth log (RHEL-family)"},
            ]

        return self._info_result(
            ctx,
            note=(
                "Candidate log/audit sources only. The executor reads these "
                "during authorized assessment; this module does not read them."
            ),
            evidence=[f"Enumerated {len(log_sources)} candidate log sources for {os_family} target {ctx.target_ip}"],
            references=[
                "https://attack.mitre.org/techniques/T1078/",
                "https://attack.mitre.org/techniques/T1110/",
            ],
            log_sources=log_sources,
            os_family=os_family,
            target_ip=ctx.target_ip,
        )


class OPSECPostureReport(AttackModule):
    name = "opsec_posture_report"
    description = (
        "Report the active OPSEC posture + audit footprint summary (read-only)."
    )
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}
    # Capability metadata: read-only OPSEC posture reporting.
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "recon"

    def applicability(self, ctx: ModuleContext) -> int:
        # Baseline low-priority; always selectable.
        return 10

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        from tools.detection_coverage import footprint_summary

        profile = _ctx_get(ctx, "opsec_profile", None)
        if not isinstance(profile, dict):
            profile = {}

        audit_records = _ctx_get(ctx, "audit_records", None)
        if not isinstance(audit_records, list):
            audit_records = []

        footprint = footprint_summary(audit_records)

        recommendations: list[str] = []
        ua_rotation = profile.get("ua_rotation")
        if ua_rotation is False:
            recommendations.append("UA rotation disabled")
        min_gap = profile.get("min_gap_seconds")
        if min_gap == 0:
            recommendations.append("Pacing disabled")
        doh = profile.get("doh")
        if doh is False:
            recommendations.append("DNS-over-HTTPS disabled")
        quiet = profile.get("quiet_commands")
        if quiet is False:
            recommendations.append("Quiet command rewriting disabled")

        noisy = footprint.get("noisy_actions", 0)
        if isinstance(noisy, int) and noisy > 0:
            recommendations.append(f"{noisy} noisy actions recorded")

        total = footprint.get("total_actions", 0)
        if isinstance(total, int) and total == 0:
            recommendations.append("No audit actions recorded yet")

        return self._info_result(
            ctx,
            note=(
                "Read-only OPSEC posture + audit footprint summary. The audit "
                "trail is append-only/tamper-evident and is never mutated."
            ),
            evidence=[f"OPSEC posture reported for {ctx.target_ip}: {len(recommendations)} recommendations"],
            references=[
                "https://attack.mitre.org/techniques/T1027/",
                "https://attack.mitre.org/techniques/T1070/",
            ],
            opsec_profile=profile,
            footprint=footprint,
            recommendations=recommendations,
            target_ip=ctx.target_ip,
        )
