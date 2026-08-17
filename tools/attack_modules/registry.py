"""Module registry and ranking."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.modules import (
    ADCSEnum,
    ADLDAPEnum,
    APIFuzzer,
    ArtifactExposure,
    ASREPRoast,
    BACnetEnum,
    BasicAuthBuster,
    BloodHoundCollect,
    CICDMisconfig,
    CloudPrivesc,
    ContainerBreakout,
    CredentialSpray,
    CVEToExploit,
    DCSyncAttack,
    DependencyConfusion,
    DeserializeAttack,
    DetectionCoverageProbe,
    DiffPatchAnalysis,
    DNP3Enum,
    DockerSockEscape,
    DumpHashes,
    ElasticsearchExploit,
    EternalBlue,
    ExposedVCS,
    FTPAnonymous,
    FuzzToExploit,
    GoldenTicket,
    GraphQLIntrospect,
    HashCrack,
    HMIDefaultCred,
    IMDSExploit,
    IoTDefaultCred,
    JWTTamper,
    K8sPrivesc,
    Kerberoasting,
    KernelExploitCheck,
    LateralMovement,
    LDAPAnonymous,
    LFITraversal,
    LinuxPersistence,
    LinuxPrivescCheck,
    LocalExploitSuggester,
    Log4jRCE,
    LogSourceEnum,
    ModbusEnum,
    OpenSSHCVECheck,
    OPSECPostureReport,
    PassTheHash,
    PasswordSpray,
    RaceRequest,
    RDPBlueKeep,
    RDPExploit,
    RedisExploit,
    RegreSSHion,
    RequestSmuggling,
    ResponderRelay,
    S3BucketTakeover,
    S7Enum,
    ServiceMisconfiguration,
    SMBGhost,
    SMBNullSession,
    SMBRelay,
    SMBSigningCheck,
    SQLInjection,
    SSHBruteForce,
    SSRFProbe,
    SSTIProbe,
    SUIDEnumeration,
    SupplyChainRecon,
    TimingOracle,
    TokenImpersonation,
    ValidateFinding,
    WeaponizedExploit,
    WebShellPersistence,
    WebShellUpload,
    WindowsPersistence,
    WindowsPrivescCheck,
    XSSScanner,
    XXEProbe,
)

_MODULE_CLASSES: list[type[AttackModule]] = [
    Log4jRCE,
    SMBGhost,
    EternalBlue,
    BasicAuthBuster,
    APIFuzzer,
    RDPBlueKeep,
    SSHBruteForce,
    RegreSSHion,
    OpenSSHCVECheck,
    SMBRelay,
    SMBNullSession,
    WebShellUpload,
    SQLInjection,
    XSSScanner,
    CredentialSpray,
    LinuxPrivescCheck,
    WindowsPrivescCheck,
    SUIDEnumeration,
    KernelExploitCheck,
    ContainerBreakout,
    LinuxPersistence,
    WindowsPersistence,
    WebShellPersistence,
    FTPAnonymous,
    RedisExploit,
    ElasticsearchExploit,
    LDAPAnonymous,
    RDPExploit,
    # ── NEW: Advanced Web Exploitation ──
    JWTTamper,
    SSTIProbe,
    DeserializeAttack,
    GraphQLIntrospect,
    # ── NEW: Race Condition & Timing ──
    RaceRequest,
    TimingOracle,
    RequestSmuggling,
    # ── NEW: Credential Attack Amplifiers ──
    PasswordSpray,
    HashCrack,
    PassTheHash,
    DumpHashes,
    # ── NEW: AI-Assisted Exploit Synthesis ──
    CVEToExploit,
    DiffPatchAnalysis,
    FuzzToExploit,
    # ── NEW: SSRF / XXE / LFI ──
    SSRFProbe,
    XXEProbe,
    LFITraversal,
    # ── NEW: Active Directory / Kerberos ──
    ASREPRoast,
    Kerberoasting,
    DCSyncAttack,
    ADLDAPEnum,
    # ── NEW: Weaponized exploit synthesis ──
    WeaponizedExploit,
    # ── NEW: Cloud / Kubernetes privilege escalation ──
    CloudPrivesc,
    K8sPrivesc,
    # ── NEW (D3): Cloud exploitation modules (IMDS creds, docker.sock escape, S3 takeover) ──
    IMDSExploit,
    DockerSockEscape,
    S3BucketTakeover,
    # --- Phase 6.3: ICS/SCADA/IoT enumeration (read-only) ---
    ModbusEnum,
    DNP3Enum,
    S7Enum,
    BACnetEnum,
    HMIDefaultCred,
    IoTDefaultCred,
    # --- Phase 6.4: Supply-chain / CI-CD reconnaissance ---
    ExposedVCS,
    CICDMisconfig,
    DependencyConfusion,
    ArtifactExposure,
    SupplyChainRecon,
    # --- Phase 6.2: Detection-coverage / OPSEC posture (read-only) ---
    DetectionCoverageProbe,
    LogSourceEnum,
    OPSECPostureReport,
    # --- Orchestrator phase modules (back the privesc/lateral/validation phases;
    #     previously phantom names -> get_module None -> FAILED) ---
    TokenImpersonation,
    ServiceMisconfiguration,
    LateralMovement,
    ValidateFinding,
    LocalExploitSuggester,
    # --- Phase 1: AD/Kerberos post-exploit recipe modules (wrap ad.py MCP tools) ---
    ADCSEnum,
    BloodHoundCollect,
    ResponderRelay,
    GoldenTicket,
    SMBSigningCheck,
]


def _plugin_extra_module_classes() -> list[type]:
    """Return plugin-registered AttackModule subclasses, if any.

    Lazy import of ``tools.plugins`` wrapped so a plugins-module import
    failure never breaks the built-in registry -- the consult is additive.
    """
    try:
        from tools.plugins import PLUGIN_REGISTRY
        return list(PLUGIN_REGISTRY.extra_module_classes)
    except Exception:  # noqa: BLE001 -- best-effort plugin consult
        return []


def list_modules() -> list[AttackModule]:
    """Return instantiated copies of all registered modules."""
    modules = [cls() for cls in _MODULE_CLASSES]
    for cls in _plugin_extra_module_classes():
        try:
            modules.append(cls())
        except Exception:  # noqa: BLE001 -- one bad plugin module never breaks the rest
            pass
    return modules


def find_modules(
    ctx: ModuleContext, experience_store: Any | None = None
) -> list[tuple[float, AttackModule]]:
    """Return modules sorted by a composite of static applicability and
    (when an experience store is provided) Bayesian confidence.

    Without ``experience_store`` this is the original behavior: modules are
    ranked purely by ``AttackModule.applicability`` (static service/port/CVE
    match) and returned as ``(score, module)`` tuples. This is the default so
    every existing caller (and test) is unchanged in behavior -- the scores
    are simply ``float(applicability)`` instead of bare ``int``.

    With ``experience_store`` (any object exposing
    ``get_all_confidences(target_signature) -> dict[action_type, float]``,
    e.g. ``tools.experience_store.ExperienceStore``), each applicable module's
    static score is blended with its historical Bayesian confidence for the
    matching ``service:version:os`` target signature. A module that has
    *consistently succeeded* against this signature is promoted; one that has
    *consistently failed* is demoted below untried modules (which stay neutral
    at 0.5). The static applicability score remains the hard gate -- a module
    with 0 applicability is never included, and experience only refines the
    ordering among applicable modules (the confidence term swings the score
    by at most +/-10 around the static score). The min-samples gate inside
    ``get_all_confidences`` ensures thin data reads as neutral 0.5, so a
    single lucky/unlucky run cannot skew the ranking.

    Tier 1.7: activates the dormant ``ExperienceStore.get_all_confidences`` for
    module selection so the agent prefers proven modules and avoids repeating
    known-bad approaches.
    """
    scored: list[tuple[float, AttackModule]] = []
    for mod in list_modules():
        static = mod.applicability(ctx)
        if static <= 0:
            continue
        confidence = _module_experience_confidence(mod, ctx, experience_store)
        # Blend: static applicability is the gate; experience refines order.
        # confidence in [0, 1]; (confidence - 0.5) * 20 swings the score +/-10.
        composite = float(static) + (confidence - 0.5) * 20.0
        scored.append((composite, mod))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def _module_primary_service(mod: AttackModule, ctx: ModuleContext) -> tuple[str, str]:
    """Return ``(service_name, version)`` for this module against ``ctx``.

    Picks the first declared target service that is actually present on the
    target (falling back to the first declared service) and the version
    recorded for that service (``""`` if not found).

    This is the SINGLE source of truth shared by BOTH:

    * the **write side** -- ``generate_dynamic_script`` records an outcome via
      the mutator keyed on this ``service_name:version:os`` signature;
    * the **read side** -- ``_module_target_signature`` queries the
      ExperienceStore for the same signature.

    Sharing one picker guarantees the two sides can never disagree on which
    service+version a module's outcome was recorded against. That matters for
    multi-service modules (e.g. SMBRelay: ``[microsoft-ds, smb, netbios-ssn]``)
    where recon may report a non-first-declared service string: pre-Tier-1.7
    the write side hardcoded ``target_services[0]`` ('microsoft-ds'), found no
    matching service, and recorded an empty version, while the read side
    picked the present 'smb' with its real version -- so the historical
    confidence was silently never applied. (Tier 1.7 coherence fix.)
    """
    svc_names = {s.get("service", "").lower() for s in ctx.services}
    primary = next(
        (s for s in mod.target_services if s.lower() in svc_names),
        mod.target_services[0],
    )
    version = ""
    for s in ctx.services:
        if s.get("service", "").lower() == primary.lower():
            version = s.get("version", "")
            break
    return primary, version


def _module_target_signature(mod: AttackModule, ctx: ModuleContext) -> str | None:
    """Build the ``service:version:os`` signature an ExperienceStore would have
    recorded for this module against ``ctx``. Returns None when the module
    declares no target services (no signature to query).

    Uses the shared ``_module_primary_service`` picker so the read side agrees
    with the write side (``generate_dynamic_script``) on which service+version
    an outcome is recorded against -- see that helper's docstring for why this
    matters for multi-service modules."""
    if not mod.target_services:
        return None
    primary, version = _module_primary_service(mod, ctx)
    os_hint = ctx.target_os or "unknown"
    return f"{primary}:{version or ''}:{os_hint}"


def _module_experience_confidence(
    mod: AttackModule, ctx: ModuleContext, experience_store: Any | None
) -> float:
    """Return the module's mean Bayesian confidence across all mutation
    strategies tried against its target signature, or 0.5 (neutral) when
    there is no store, no signature, no recorded data, or the store raises."""
    if experience_store is None:
        return 0.5
    sig = _module_target_signature(mod, ctx)
    if sig is None:
        return 0.5
    try:
        confs = experience_store.get_all_confidences(sig)
    except Exception:
        return 0.5
    if not confs:
        return 0.5
    # action_type is recorded as "<module_name>:<mutation_strategy>"; aggregate
    # all strategies for this module so the ranking reflects "has this module
    # historically worked against this signature", strategy-agnostic.
    module_confs = [
        conf
        for action, conf in confs.items()
        if action == mod.name or action.startswith(mod.name + ":")
    ]
    if not module_confs:
        return 0.5
    return sum(module_confs) / len(module_confs)


def get_module(name: str) -> AttackModule | None:
    for cls in _MODULE_CLASSES:
        if cls.name.lower() == name.lower():
            return cls()
    for cls in _plugin_extra_module_classes():
        try:
            if cls.name.lower() == name.lower():
                return cls()
        except Exception:  # noqa: BLE001 -- best-effort plugin consult
            pass
    return None
