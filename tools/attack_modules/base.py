"""Attack module base types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


@dataclass
class ModuleContext:
    target_ip: str
    target_os: str | None = None
    services: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    workspace: Path = Path("exploit_workspace")
    # Phase 1: thread recovered credentials + task parameters + config into
    # modules. The orchestrator builds ctx from recon_result only, so
    # post-exploit modules (LateralMovement, ValidateFinding) could not read
    # the recovered cred or the task's {exploit: ...} parameter. Optional
    # fields keep existing callers byte-identical.
    credentials: list[dict[str, str]] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] | None = None


# Status values a module's run() may legitimately return. Kept loose (str) on
# the dataclass so legacy modules that return ad-hoc strings ("exploited",
# "executed", ...) still round-trip through ``to_result`` without raising.
ModuleStatus = Literal["info", "script_generated", "success", "failed", "blocked"]


@dataclass
class ModuleResult:
    """Structured outcome of an attack module run (Phase 2.1).

    The legacy contract is ``dict[str, Any]`` (``AttackModule.run`` still
    returns that). ``ModuleResult`` is the typed shape the autonomous
    orchestrator and the MCP renderer want to read -- it carries the keys
    ``AttackState.record_success`` actually consumes (``shell_type``,
    ``privilege_level``, ``credentials``, ``loot``, ``pivot_targets``) plus
    evidence/references for the audit trail. Use ``to_result(d)`` to adapt a
    module's existing dict return into a ``ModuleResult`` so existing modules
    keep working unchanged.
    """

    status: str = "executed"
    module: str = ""
    script: str = ""
    note: str = ""
    suggested_command: str = ""
    suggested_msf: str = ""
    # Compromise signals -- only set when a real shell / foothold is achieved.
    shell_type: str = ""  # none|reverse|bind|webshell|meterpreter|sh|cmd
    privilege_level: str = ""  # ""|user|admin|system|root
    credentials_found: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # Extra keys a module may pass through that are not first-class fields
    # (e.g. ``techniques``, ``workflow``, ``prompt_template``). Preserved so the
    # MCP renderer's existing dict access (``result.get("suggested_command")``
    # etc.) and downstream consumers keep seeing them after adaptation.
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to the dict shape the legacy renderer / record_success expect.

        Drops empty optional fields (mirrors the renderer's ``if result.get(...)``
        guards) but always includes ``status`` and ``module``. Merges ``extra``
        so pass-through keys surface as top-level dict entries.
        """
        out: dict[str, Any] = {
            "status": self.status or "executed",
            "module": self.module,
        }
        if self.script:
            out["script"] = self.script
        if self.note:
            out["note"] = self.note
        if self.suggested_command:
            out["suggested_command"] = self.suggested_command
        if self.suggested_msf:
            out["suggested_msf"] = self.suggested_msf
        if self.shell_type:
            out["shell_type"] = self.shell_type
        if self.privilege_level:
            out["privilege_level"] = self.privilege_level
        if self.credentials_found:
            # record_success reads result["credentials"] as a list[dict[str,str]];
            # accept both str entries (this dataclass) and dict entries (legacy).
            out["credentials"] = list(self.credentials_found)
        if self.evidence:
            out["evidence"] = list(self.evidence)
        if self.references:
            out["references"] = list(self.references)
        # Pass-through extra keys win over the typed defaults only when the
        # module set them explicitly (modules that return dicts with extra
        # workflow/prompt_template data keep that data).
        for k, v in self.extra.items():
            if k not in out and v not in (None, "", [], {}):
                out[k] = v
        return out

    @classmethod
    def to_result(cls, d: dict[str, Any] | "ModuleResult") -> "ModuleResult":
        """Adapt a module's existing dict return (or a ModuleResult) into a
        ``ModuleResult``. Existing dict keys map 1:1; unknown keys are stashed
        in ``extra`` so they survive a round-trip via ``to_dict``.
        """
        if isinstance(d, ModuleResult):
            return d
        if not isinstance(d, dict):
            # Defensive: a misbehaving module returned a non-dict; degrade to
            # an info-stub so the caller never crashes.
            return cls(status="info", note=f"non-dict module return: {type(d).__name__}")

        known = {
            "status", "module", "script", "note", "suggested_command",
            "suggested_msf", "shell_type", "privilege_level",
            "credentials_found", "evidence", "references", "extra",
        }
        # Modules historically used "credentials" (list[dict]) not
        # "credentials_found" (list[str]); normalize both onto the dataclass.
        creds = d.get("credentials_found") or d.get("credentials") or []
        if isinstance(creds, dict):
            creds = [creds]
        creds_list: list[str] = []
        for c in creds:
            if isinstance(c, str):
                creds_list.append(c)
            elif isinstance(c, dict):
                # Flatten single-cred dicts to "user=... password=..." style.
                creds_list.append(" ".join(f"{k}={v}" for k, v in c.items()))
        extra = {k: v for k, v in d.items() if k not in known and k != "credentials"}
        return cls(
            status=str(d.get("status", "executed") or "executed"),
            module=str(d.get("module", "") or ""),
            script=str(d.get("script", "") or ""),
            note=str(d.get("note", "") or ""),
            suggested_command=str(d.get("suggested_command", "") or ""),
            suggested_msf=str(d.get("suggested_msf", "") or ""),
            shell_type=str(d.get("shell_type", "") or ""),
            privilege_level=str(d.get("privilege_level", "") or ""),
            credentials_found=creds_list,
            evidence=list(d.get("evidence", []) or []),
            references=list(d.get("references", []) or []),
            extra=extra,
        )


class AttackModule(ABC):
    """Base class for pre-packaged attack modules the AI can call via MCP.

    ``target_versions`` maps a lowercased service name to a list of
    version-substring patterns that are known-vulnerable for this module. The
    default (empty dict) means "no version constraint" -- the module's
    applicability is computed purely from service/port/CVE matching, so every
    existing module with ``target_versions={}`` behaves exactly as before.

    When a module declares ``target_versions`` and a service present in
    ``ctx.services`` both (a) has its lowercased name as a key and (b) reports a
    version string containing any of the declared patterns (case-insensitive
    substring match), ``applicability`` adds a single +25 bonus ONCE per module
    (not per pattern, not per service -- a flat +25 if any declared vulnerable
    version is observed). The bonus is applied AFTER the existing
    service/port/CVE scoring and BEFORE the ``min(score, 100)`` cap, so it can
    never push a module past 100.
    """

    name: str = ""
    description: str = ""
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}
    # Phase 1: OS-gated applicability path for post-foothold modules (privesc,
    # persistence, detection) that don't key on a network service. When
    # declared, applicability() adds +30 when ctx.target_os matches one of
    # the listed OS hints (case-insensitive). Empty list (default) means no
    # OS gating -- existing behavior unchanged.
    target_os_hint: list[str] = []
    # Phase 1: ICS destructive-write gate. When True, applicability() returns
    # 0 unless _ics_write_allowed() (ics.allow_write + ics.destructive_ics both
    # true in config) -- so the 4 write modules (ModbusWriteCoil,
    # ModbusWriteRegister, S7PlcStop, S7PlcStart) are invisible to find_modules
    # unless the operator has explicitly armed both flags. Default False
    # keeps all non-ICS modules unchanged.
    destructive_ics: bool = False

    def applicability(self, ctx: ModuleContext) -> int:
        """Return 0-100 score indicating how applicable this module is.
        Higher = more confident this module fits the target."""
        # Phase 1: ICS destructive-write hard gate. Done before any
        # service/port scoring so an unarmed write module never appears in
        # find_modules even if its target service/port match. The live
        # run() also re-checks via _ics_write_allowed() for defense in depth.
        if self.destructive_ics:
            try:
                from tools.attack_modules.modules.ics_iot import _ics_write_allowed
                if not _ics_write_allowed():
                    return 0
            except Exception:  # noqa: BLE001 -- best-effort gate
                return 0
        score = 0
        svc_names = {s.get("service", "").lower() for s in ctx.services}
        svc_ports = {int(s.get("port", 0).split("/")[0]) for s in ctx.services if "/" in s.get("port", "")}
        cve_upper = {c.upper() for c in ctx.cves}

        for svc in self.target_services:
            if svc.lower() in svc_names:
                score += 30
        for port in self.target_ports:
            if port in svc_ports:
                score += 20
        for cve in self.required_cves:
            if cve.upper() in cve_upper:
                score += 40

        # Version-aware bonus (Phase 4): if this module declares known-vulnerable
        # version patterns and ANY service present in ctx.services matches one of
        # them (case-insensitive substring), add a single flat +25. Empty
        # target_versions (the default) short-circuits and changes nothing.
        if self.target_versions:
            version_bonus = False
            for s in ctx.services:
                svc = s.get("service", "").lower()
                patterns = self.target_versions.get(svc)
                if not patterns:
                    continue
                version = (s.get("version", "") or "").lower()
                if any(p.lower() in version for p in patterns):
                    version_bonus = True
                    break
            if version_bonus:
                score += 25

        # Phase 1: OS-hint applicability for post-foothold modules. When a
        # module declares target_os_hint (e.g. ["linux"], ["windows"]) and
        # ctx.target_os matches, add +30 so privesc/persistence/detection
        # modules can score >0 without coupling to a network service. Empty
        # target_os_hint (default) short-circuits and changes nothing.
        if self.target_os_hint and ctx.target_os:
            ctx_os = ctx.target_os.lower()
            if any(h.lower() in ctx_os or ctx_os in h.lower() for h in self.target_os_hint):
                score += 30

        return min(score, 100)

    @abstractmethod
    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        """Execute the module. Returns a structured result dict."""
        ...

    def generate_python_script(self, ctx: ModuleContext) -> str:
        """Override to return a Python exploit script string."""
        return ""

    def generate_dynamic_script(self, ctx: ModuleContext, mutator: Any | None = None) -> str:
        """Generate or mutate an exploit script using the PayloadCrafter.

        Falls back to static generate_python_script() if no mutator is provided.
        """
        if mutator is None:
            return self.generate_python_script(ctx)

        # Extract service info from context. Use the shared picker so the
        # service+version recorded here (write side) agrees with what
        # find_modules queries via _module_target_signature (read side). This
        # matters for multi-service modules (e.g. SMBRelay: [microsoft-ds,
        # smb, netbios-ssn]) where recon may report a non-first-declared
        # service string -- previously this hardcoded target_services[0]
        # ('microsoft-ds'), found no matching service, and recorded an empty
        # version while the read side queried the present 'smb' with its
        # version, so the experience was silently never applied.
        from tools.attack_modules.registry import _module_primary_service

        if self.target_services:
            service_name, version = _module_primary_service(self, ctx)
        else:
            service_name, version = "unknown", ""
        os_hint = ctx.target_os or "unknown"

        payload = mutator.craft_initial(
            target_ip=ctx.target_ip,
            service_name=service_name,
            version=version,
            os_hint=os_hint,
            module_name=self.name,
        )
        return payload.script

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "target_services": self.target_services,
            "target_ports": self.target_ports,
            "required_cves": self.required_cves,
        }
