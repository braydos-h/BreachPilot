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
    # Capability-upgrade (all optional; existing construction sites unchanged):
    # compact assessment state so modules can reason about prerequisites
    # (foothold/privilege/sessions) and prior evidence without raw logs.
    sessions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    access_achieved: bool = False
    privilege_level: str = ""
    phase: str | None = None


# Status values a module's run() may legitimately return. Kept loose (str) on
# the dataclass so legacy modules that return ad-hoc strings ("exploited",
# "executed", ...) still round-trip through ``to_result`` without raising.
ModuleStatus = Literal["info", "script_generated", "success", "failed", "blocked"]


@dataclass
class ApplicabilityReport:
    """Structured explanation of a module's applicability score (§6)."""

    score: int
    reasons: list[str] = field(default_factory=list)
    penalties: list[str] = field(default_factory=list)


_ARTIFACT_KINDS_FOOTHOLD = {"foothold", "shell", "session"}
_ARTIFACT_KINDS_PRIV = {"admin_priv", "root_priv", "system_priv", "high_priv"}


def _artifact_present(kind: str, ctx: ModuleContext) -> bool:
    """Best-effort prerequisite check: is artifact ``kind`` available in ctx?"""
    kind = kind.lower()
    if kind in {"credentials", "creds", "password", "hash"}:
        return bool(ctx.credentials)
    if kind in _ARTIFACT_KINDS_FOOTHOLD:
        return bool(ctx.access_achieved or ctx.sessions)
    if kind in _ARTIFACT_KINDS_PRIV:
        return ctx.privilege_level.lower() in {"admin", "administrator", "system", "root"}
    if kind == "user_list":
        return any("user" in c for c in ctx.credentials)
    # Unknown artifact kinds cannot be verified from state; treat as present so
    # a typo in a module's requires list never hides the module from ranking.
    return True


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
    # Capability-upgrade fields (additive; empty/None defaults serialize away
    # so the flattened dict legacy consumers read is unchanged):
    failure_class: str = ""  # tools/failure_taxonomy.FailureClass value
    retryable: bool | None = None
    confidence: float | None = None
    produced_artifacts: list[str] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)
    unlocked_capabilities: list[str] = field(default_factory=list)
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
        # Capability-upgrade fields: emitted only when set, so legacy consumers
        # (record_success key set, the MCP renderer) see an unchanged shape for
        # modules that never populate them.
        if self.failure_class:
            out["failure_class"] = self.failure_class
        if self.retryable is not None:
            out["retryable"] = self.retryable
        if self.confidence is not None:
            out["confidence"] = self.confidence
        if self.produced_artifacts:
            out["produced_artifacts"] = list(self.produced_artifacts)
        if self.follow_ups:
            out["follow_ups"] = list(self.follow_ups)
        if self.unlocked_capabilities:
            out["unlocked_capabilities"] = list(self.unlocked_capabilities)
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
            "failure_class", "retryable", "confidence",
            "produced_artifacts", "follow_ups", "unlocked_capabilities",
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
            failure_class=str(d.get("failure_class", "") or ""),
            retryable=d.get("retryable") if isinstance(d.get("retryable"), bool) else None,
            confidence=d.get("confidence") if isinstance(d.get("confidence"), (int, float)) else None,
            produced_artifacts=list(d.get("produced_artifacts", []) or []),
            follow_ups=list(d.get("follow_ups", []) or []),
            unlocked_capabilities=list(d.get("unlocked_capabilities", []) or []),
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
    # Capability-upgrade metadata (all defaulted; machine-readable via
    # capability_record()). ``requires``/``produces`` name artifact kinds
    # ("credentials", "foothold", "admin_priv", "hash_artifact", "user_list",
    # ...) so the planner can discover module composition dynamically instead
    # of hard-coding chains. read_only = does not change target state.
    requires: list[str] = []
    produces: list[str] = []
    read_only: bool = False
    cost: str = "medium"  # low|medium|high -- planning hint only
    phase_hint: str = ""  # recon|enumerate|exploit|escalate|loot|pivot|... advisory

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

    def applicability_explain(self, ctx: ModuleContext) -> "ApplicabilityReport":
        """Structured explanation of the applicability score.

        The score itself delegates to ``applicability()`` so subclass overrides
        (e.g. the fixed-score detection modules, the ICS gate) stay the single
        source of truth; this method derives the human/AI-readable reasons and
        penalties from the same metadata conditionals. The planner and the
        capability MCP tools expose these so the model can see WHY a module
        ranks where it does instead of trusting a bare number.
        """
        score = self.applicability(ctx)
        reasons: list[str] = []
        penalties: list[str] = []

        svc_names = {s.get("service", "").lower() for s in ctx.services}
        svc_ports = {int(s.get("port", 0).split("/")[0]) for s in ctx.services if "/" in s.get("port", "")}
        cve_upper = {c.upper() for c in ctx.cves}

        # ponytail: descriptive labels mirror applicability()'s conditionals by
        # contract; the weights live only in applicability(). If a new scoring
        # input is added there, add its label here.
        matched_services = [s for s in self.target_services if s.lower() in svc_names]
        if matched_services:
            reasons.append(f"service matched: {', '.join(matched_services)}")
        matched_ports = [p for p in self.target_ports if p in svc_ports]
        if matched_ports:
            reasons.append(f"port matched: {', '.join(str(p) for p in matched_ports)}")
        matched_cves = [c for c in self.required_cves if c.upper() in cve_upper]
        if matched_cves:
            reasons.append(f"CVE matched: {', '.join(matched_cves)}")
        if self.target_versions:
            for s in ctx.services:
                patterns = self.target_versions.get(s.get("service", "").lower())
                version = (s.get("version", "") or "").lower()
                if patterns and any(p.lower() in version for p in patterns):
                    reasons.append(f"vulnerable version matched: {s.get('service')} {s.get('version')}")
                    break
        if self.target_os_hint and ctx.target_os:
            ctx_os = ctx.target_os.lower()
            if any(h.lower() in ctx_os or ctx_os in h.lower() for h in self.target_os_hint):
                reasons.append(f"target OS matched: {ctx.target_os}")
        # Prerequisite satisfaction (advisory signal — never changes the score).
        missing = [r for r in self.requires if not _artifact_present(r, ctx)]
        for r in self.requires:
            if r not in missing:
                reasons.append(f"prerequisite available: {r}")
        for r in missing:
            penalties.append(f"prerequisite missing: {r}")
        if self.destructive_ics and score == 0:
            penalties.append("ICS destructive-write gates not armed (ics.allow_write + ics.destructive_ics)")
        if score == 0 and not reasons and not penalties:
            penalties.append("no service/port/CVE/version/OS match")
        return ApplicabilityReport(score=score, reasons=reasons, penalties=penalties)

    def capability_record(self) -> dict[str, Any]:
        """Full machine-readable capability record for discovery tools.

        Superset of to_json() (which stays byte-identical for the WebUI/tests);
        this is the shape query_capabilities/get_capability_details expose.
        """
        return {
            "name": self.name,
            "description": self.description,
            "target_services": list(self.target_services),
            "target_ports": list(self.target_ports),
            "required_cves": list(self.required_cves),
            "target_versions": {k: list(v) for k, v in self.target_versions.items()},
            "target_os_hint": list(self.target_os_hint),
            "destructive_ics": bool(self.destructive_ics),
            "requires": list(self.requires),
            "produces": list(self.produces),
            "read_only": bool(self.read_only),
            "cost": self.cost,
            "phase_hint": self.phase_hint,
        }

    @abstractmethod
    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        """Execute the module. Returns a structured result dict."""
        ...

    def _info_result(
        self,
        ctx: ModuleContext,
        *,
        note: str,
        evidence: list[str] | None = None,
        references: list[str] | None = None,
        suggested_command: str = "",
        suggested_msf: str = "",
        **extra: Any,
    ) -> dict[str, Any]:
        """Phase 3: build a well-formed ``status="info"`` result dict.

        Info-stub modules previously returned bare ``{"status": "info",
        "module": self.name, "note": ...}`` with no evidence, references, or
        actionable command -- so the orchestrator's audit trail and the
        post-run report lost "what did this module actually find", and the
        module was recorded as a failure (Phase 1) with nothing to show for
        it. This helper pre-populates the fields ``ModuleResult`` /
        ``record_success`` consume so every info module leaves an actionable
        evidence trail. Extra kwargs pass through as top-level dict keys
        (e.g. ``techniques=...``, ``log_sources=...``).
        """
        result: dict[str, Any] = {
            "status": "info",
            "module": self.name,
            "note": note,
        }
        if evidence:
            result["evidence"] = list(evidence)
        if references:
            result["references"] = list(references)
        if suggested_command:
            result["suggested_command"] = suggested_command
        if suggested_msf:
            result["suggested_msf"] = suggested_msf
        result.update(extra)
        return result

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
