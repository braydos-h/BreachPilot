"""Attack module base types."""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

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


def port_of(svc: dict[str, Any]) -> int:
    """Normalize a service port value to an int (0 when unparseable).

    Recon paths store ports heterogeneously: ``445`` (int), ``"445"``,
    ``"445/tcp"``. The scorer previously required ``"/"`` in the string,
    silently awarding zero port points for int-port contexts.
    """
    raw = svc.get("port", 0)
    if isinstance(raw, int):
        return raw
    text = str(raw or "").split("/")[0].strip()
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def _artifact_present(kind: str, ctx: ModuleContext) -> bool:
    """Best-effort prerequisite check: is artifact ``kind`` available in ctx?

    Closed-world since the artifact-vocabulary freeze: unknown kinds are
    absent (fail closed) instead of present. Delegates to
    :mod:`tools.attack_modules.artifacts`; kept as the import site
    ``registry.missing_prerequisites`` and older callers use.
    """
    try:
        from tools.attack_modules.artifacts import is_satisfied
    except Exception:  # noqa: BLE001 -- artifacts module must never break scoring
        return True
    try:
        return bool(is_satisfied(kind, ctx))
    except Exception:  # noqa: BLE001
        return False


# Service-name equivalence classes for scoring. Names inside one set match
# each other (recon reports whichever string the scanner emitted:
# nmap says ``ms-wbt-server``, humans write ``rdp``). http/https/api are
# deliberately NOT aliased — scheme matters to web payloads; fix the
# module's target_services instead (cf. JWTTamper + api).
_SERVICE_ALIASES: tuple[frozenset[str], ...] = (
    frozenset({"ms-wbt-server", "rdp"}),
    frozenset({"microsoft-ds", "smb", "cifs", "netbios-ssn"}),
    frozenset({"ldap", "ldaps"}),
    frozenset({"ssh", "openssh"}),
)


def canonical_service(name: str) -> str:
    """Map a service name to its equivalence-class representative (lowercased)."""
    n = (name or "").strip().lower()
    for group in _SERVICE_ALIASES:
        if n in group:
            return sorted(group)[0]
    return n


@dataclass
class ApplicabilityEvidence:
    """Structured inputs to the applicability score (one source of truth).

    ``applicability()`` is a pure function of this object, and
    ``applicability_explain()`` renders from it — subclass overrides should
    extend :meth:`AttackModule.applicability_evidence`, never the integer.
    """

    matched_services: list[str] = field(default_factory=list)
    matched_ports: list[int] = field(default_factory=list)
    matched_cves: list[str] = field(default_factory=list)
    version_match: bool | None = None  # None = no version info to judge
    os_match: bool | None = None  # None = no OS hint / no ctx OS
    missing_prereqs: list[str] = field(default_factory=list)
    # Veto/penalty signals (negative evidence):
    # NOTE: a version-mismatch penalty is deliberately absent — the pinned
    # contract (tests/test_version_aware_ranking.py) requires a non-matching
    # version to score identically to an empty version. Negative version
    # evidence arrives via the CVE-absent cap + OS veto instead.
    os_contradicted: bool = False  # OS hint declared, ctx OS set, no match
    cve_unconfirmed: bool = False  # required_cves declared, none present


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
    # Verification verdict: "confirmed" only when post-conditions were
    # observed (not merely queued). "inconclusive" is the honest default
    # for recipe/info results; "disproven" when negative evidence rules out
    # the hypothesis.
    verdict: str = "inconclusive"  # confirmed|disproven|inconclusive
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
        if self.verdict and self.verdict != "inconclusive":
            out["verdict"] = self.verdict
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
            "status",
            "module",
            "script",
            "note",
            "suggested_command",
            "suggested_msf",
            "shell_type",
            "privilege_level",
            "credentials_found",
            "evidence",
            "references",
            "extra",
            "failure_class",
            "retryable",
            "confidence",
            "produced_artifacts",
            "follow_ups",
            "unlocked_capabilities",
            "verdict",
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
            verdict=str(d.get("verdict", "") or "inconclusive"),
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

    def _ics_gate_closed(self) -> bool:
        """True when the destructive-ICS gate hides this module."""
        if not self.destructive_ics:
            return False
        try:
            from tools.attack_modules.modules.ics_iot import _ics_write_allowed

            return not _ics_write_allowed()
        except Exception:  # noqa: BLE001 -- best-effort gate
            return True

    def applicability_evidence(self, ctx: ModuleContext) -> ApplicabilityEvidence:
        """Compute the structured evidence the score derives from.

        Override this (not :meth:`applicability`) to change what a module
        matches on. Service matching uses :func:`canonical_service` aliases;
        version lookup resolves declared keys through the same aliases.
        """
        svc_names = {canonical_service(s.get("service", "")) for s in ctx.services}
        svc_ports = {port_of(s) for s in ctx.services} - {0}
        cve_upper = {c.upper() for c in ctx.cves}

        matched_services = [s for s in self.target_services if canonical_service(s) in svc_names]
        matched_ports = [p for p in self.target_ports if p in svc_ports]
        matched_cves = [c for c in self.required_cves if c.upper() in cve_upper]

        version_match: bool | None = None
        if self.target_versions:
            # Bonus-only (pinned contract): a match adds +25 once; a
            # non-match scores exactly like an empty version (no penalty).
            hit = False
            for s in ctx.services:
                key = canonical_service(s.get("service", ""))
                patterns: list[str] | None = None
                for declared, pats in self.target_versions.items():
                    if canonical_service(declared) == key:
                        patterns = pats
                        break
                if not patterns:
                    continue
                version = (s.get("version", "") or "").strip()
                if not version:
                    continue
                if any(p.lower() in version.lower() for p in patterns):
                    hit = True
                    break
            # version_match stays None when no versioned service was judged
            # (indistinguishable from "no info" by design).
            version_match = True if hit else None

        os_match: bool | None = None
        os_contradicted = False
        if self.target_os_hint:
            if ctx.target_os:
                ctx_os = ctx.target_os.lower()
                hit = any(h.lower() in ctx_os or ctx_os in h.lower() for h in self.target_os_hint)
                os_match = hit
                os_contradicted = not hit
            # No ctx OS: None (no signal either way).

        missing = [r for r in self.requires if not _artifact_present(r, ctx)]
        return ApplicabilityEvidence(
            matched_services=matched_services,
            matched_ports=matched_ports,
            matched_cves=matched_cves,
            version_match=version_match,
            os_match=os_match,
            missing_prereqs=missing,
            os_contradicted=os_contradicted,
            cve_unconfirmed=bool(self.required_cves and not matched_cves),
        )

    @staticmethod
    def score_evidence(ev: ApplicabilityEvidence) -> int:
        """Pure score function: bonuses minus negative-evidence adjustments.

        Services count by DISTINCT canonical family (alias members like
        microsoft-ds/smb/netbios-ssn collapse to one +30 for a single
        observed service — otherwise multi-name modules triple-count).
        """
        distinct_services = {canonical_service(s) for s in ev.matched_services}
        score = (
            30 * len(distinct_services)
            + 20 * len(set(ev.matched_ports))
            + 40 * len({c.upper() for c in ev.matched_cves})
        )
        if ev.version_match:
            score += 25
        if ev.os_match:
            score += 30
        # Negative evidence (never below the floor logic in applicability()):
        if ev.cve_unconfirmed:
            score = min(score, 30)  # CVE-gated exploit without the CVE: probe at best
        if ev.missing_prereqs:
            score -= 15 * len(ev.missing_prereqs)
        return max(0, min(score, 100))

    def applicability(self, ctx: ModuleContext) -> int:
        """Return 0-100 score indicating how applicable this module is.
        Higher = more confident this module fits the target."""
        # ICS destructive-write hard gate (unchanged): unarmed write modules
        # never appear in find_modules. The live run() re-checks for defense
        # in depth.
        if self._ics_gate_closed():
            return 0
        ev = self.applicability_evidence(ctx)
        # OS contradiction is a hard veto: an OS-gated module never fits the
        # wrong OS, no matter which ports are open.
        if ev.os_contradicted:
            return 0
        score = self.score_evidence(ev)
        # Missing prerequisites demote but never fully hide a service-matched
        # module (floor 5 keeps the recovery path visible to the planner).
        if ev.missing_prereqs and score == 0 and (ev.matched_services or ev.matched_ports):
            score = 5
        return score

    def applicability_explain(self, ctx: ModuleContext) -> "ApplicabilityReport":
        """Structured explanation of the applicability score.

        Renders from the same :class:`ApplicabilityEvidence` the score
        derives from, so reasons/penalties can never drift from the number.
        Subclass ``applicability()`` overrides (fixed-score detection
        modules, the ICS gate) stay authoritative for their own score; their
        evidence still renders the underlying match signals.
        """
        try:
            ev = self.applicability_evidence(ctx)
            score = self.applicability(ctx)
        except Exception:  # noqa: BLE001 -- explain must never raise
            return ApplicabilityReport(score=0, reasons=[], penalties=["evidence computation failed"])
        reasons: list[str] = []
        penalties: list[str] = []
        if ev.matched_services:
            reasons.append(f"service matched: {', '.join(ev.matched_services)}")
        if ev.matched_ports:
            reasons.append(f"port matched: {', '.join(str(p) for p in ev.matched_ports)}")
        if ev.matched_cves:
            reasons.append(f"CVE matched: {', '.join(ev.matched_cves)}")
        if ev.version_match:
            reasons.append("vulnerable version matched")
        if ev.os_match:
            reasons.append(f"target OS matched: {ctx.target_os}")
        for r in self.requires:
            if r not in ev.missing_prereqs:
                reasons.append(f"prerequisite available: {r}")
        if ev.cve_unconfirmed:
            penalties.append("required CVE unconfirmed — capped at probe-level (30)")
        if ev.os_contradicted:
            penalties.append(f"target OS contradicts hint {self.target_os_hint} (veto)")
        for r in ev.missing_prereqs:
            penalties.append(f"prerequisite missing: {r} (-15)")
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
        confidence: float | None = None,
        verdict: str = "inconclusive",
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
        if confidence is not None:
            result["confidence"] = confidence
        if verdict and verdict != "inconclusive":
            result["verdict"] = verdict
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
