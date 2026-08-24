"""Phase 3 (group B): capability-metadata shape test.

Verifies that the AttackModule subclasses in group B files
(privesc, network_smb, ssh, services, persistence, detection,
orchestrator_phases, supply_chain, ics_iot) declare accurate
``requires`` / ``produces`` / ``read_only`` / ``cost`` / ``phase_hint`` class
attributes so ``find_producers`` composition + the planner's prerequisite
gating work. This is a SHAPE test only -- no run()/applicability() execution.
"""

from __future__ import annotations

from tools.attack_modules.base import AttackModule
from tools.attack_modules.modules.detection import (
    DetectionCoverageProbe,
    LogSourceEnum,
    OPSECPostureReport,
)
from tools.attack_modules.modules.ics_iot import (
    BACnetEnum,
    DNP3Enum,
    HMIDefaultCred,
    IoTDefaultCred,
    ModbusEnum,
    ModbusWriteCoil,
    ModbusWriteRegister,
    S7Enum,
    S7PlcStart,
    S7PlcStop,
)
from tools.attack_modules.modules.network_smb import (
    DumpHashes,
    EternalBlue,
    PassTheHash,
    SMBGhost,
    SMBNullSession,
    SMBRelay,
)
from tools.attack_modules.modules.orchestrator_phases import (
    LateralMovement,
    LocalExploitSuggester,
    ServiceMisconfiguration,
    TokenImpersonation,
    ValidateFinding,
)
from tools.attack_modules.modules.persistence import (
    LinuxPersistence,
    WebShellPersistence,
    WindowsPersistence,
)
from tools.attack_modules.modules.privesc import (
    CloudPrivesc,
    ContainerBreakout,
    DockerSockEscape,
    IMDSExploit,
    K8sPrivesc,
    KernelExploitCheck,
    LinuxPrivescCheck,
    S3BucketTakeover,
    SUIDEnumeration,
    WindowsPrivescCheck,
)
from tools.attack_modules.modules.services import (
    ElasticsearchExploit,
    FTPAnonymous,
    LDAPAnonymous,
    RDPBlueKeep,
    RDPExploit,
    RedisExploit,
)
from tools.attack_modules.modules.ssh import (
    OpenSSHCVECheck,
    RegreSSHion,
    SSHBruteForce,
)
from tools.attack_modules.modules.supply_chain import (
    ArtifactExposure,
    CICDMisconfig,
    DependencyConfusion,
    ExposedVCS,
    SupplyChainRecon,
)

_GROUP_B: list[tuple[AttackModule, str]] = [
    # privesc.py
    (LinuxPrivescCheck, "privesc"),
    (WindowsPrivescCheck, "privesc"),
    (SUIDEnumeration, "privesc"),
    (KernelExploitCheck, "privesc"),
    (ContainerBreakout, "privesc"),
    (CloudPrivesc, "privesc"),
    (K8sPrivesc, "privesc"),
    (IMDSExploit, "privesc"),
    (DockerSockEscape, "privesc"),
    (S3BucketTakeover, "privesc"),
    # network_smb.py
    (SMBGhost, "network_smb"),
    (EternalBlue, "network_smb"),
    (SMBRelay, "network_smb"),
    (SMBNullSession, "network_smb"),
    (PassTheHash, "network_smb"),
    (DumpHashes, "network_smb"),
    # ssh.py
    (SSHBruteForce, "ssh"),
    (RegreSSHion, "ssh"),
    (OpenSSHCVECheck, "ssh"),
    # services.py
    (RDPBlueKeep, "services"),
    (FTPAnonymous, "services"),
    (RedisExploit, "services"),
    (ElasticsearchExploit, "services"),
    (LDAPAnonymous, "services"),
    (RDPExploit, "services"),
    # persistence.py
    (LinuxPersistence, "persistence"),
    (WindowsPersistence, "persistence"),
    (WebShellPersistence, "persistence"),
    # detection.py
    (DetectionCoverageProbe, "detection"),
    (LogSourceEnum, "detection"),
    (OPSECPostureReport, "detection"),
    # orchestrator_phases.py
    (TokenImpersonation, "orchestrator_phases"),
    (ServiceMisconfiguration, "orchestrator_phases"),
    (LateralMovement, "orchestrator_phases"),
    (ValidateFinding, "orchestrator_phases"),
    (LocalExploitSuggester, "orchestrator_phases"),
    # supply_chain.py
    (ExposedVCS, "supply_chain"),
    (CICDMisconfig, "supply_chain"),
    (DependencyConfusion, "supply_chain"),
    (ArtifactExposure, "supply_chain"),
    (SupplyChainRecon, "supply_chain"),
    # ics_iot.py
    (ModbusEnum, "ics_iot"),
    (DNP3Enum, "ics_iot"),
    (S7Enum, "ics_iot"),
    (BACnetEnum, "ics_iot"),
    (HMIDefaultCred, "ics_iot"),
    (IoTDefaultCred, "ics_iot"),
    (ModbusWriteCoil, "ics_iot"),
    (ModbusWriteRegister, "ics_iot"),
    (S7PlcStop, "ics_iot"),
    (S7PlcStart, "ics_iot"),
]


def test_all_group_b_modules_annotate_capability_metadata() -> None:
    """Every group B module must set an explicit phase_hint (the one attr with
    no useful default "")."""
    missing: list[str] = []
    for cls, _file in _GROUP_B:
        if not getattr(cls, "phase_hint", ""):
            missing.append(f"{cls.__name__}.phase_hint")
    assert not missing, f"group B modules missing phase_hint: {missing}"


def test_privesc_modules_require_foothold() -> None:
    """Post-foothold privesc enumeration/exploitation gates on a foothold and
    points at elevated privileges."""
    for cls in (LinuxPrivescCheck, WindowsPrivescCheck, SUIDEnumeration,
                KernelExploitCheck, ContainerBreakout, CloudPrivesc, K8sPrivesc,
                IMDSExploit, DockerSockEscape, S3BucketTakeover):
        assert "foothold" in cls.requires, f"{cls.__name__} should require foothold"
    for cls in (IMDSExploit, DockerSockEscape, S3BucketTakeover):
        assert cls.read_only is False, f"{cls.__name__} is active exploitation"
        assert cls.phase_hint == "escalate"
    for cls in (LinuxPrivescCheck, WindowsPrivescCheck, SUIDEnumeration,
                KernelExploitCheck, ContainerBreakout, CloudPrivesc, K8sPrivesc):
        assert cls.read_only is True, f"{cls.__name__} is check-only"


def test_network_smb_metadata() -> None:
    assert "shell" in EternalBlue.produces and "foothold" in EternalBlue.produces
    assert SMBGhost.read_only is True  # check-only; real exploitation is EternalBlue
    assert "user_list" in SMBNullSession.produces and SMBNullSession.read_only is True
    assert "credentials" in PassTheHash.requires
    assert "hash_artifact" in DumpHashes.produces and "credentials" in DumpHashes.produces
    assert DumpHashes.phase_hint == "loot"
    assert "hash_artifact" in SMBRelay.produces or "credentials" in SMBRelay.produces


def test_ssh_and_services_metadata() -> None:
    assert "credentials" in SSHBruteForce.produces
    assert SSHBruteForce.phase_hint == "exploit"
    assert RegreSSHion.read_only is True and RegreSSHion.phase_hint == "enumerate"
    assert OpenSSHCVECheck.read_only is True and OpenSSHCVECheck.phase_hint == "enumerate"
    assert RDPBlueKeep.read_only is False and "shell" in RDPBlueKeep.produces
    assert FTPAnonymous.read_only is True and "credentials" in FTPAnonymous.produces
    assert "shell" in RedisExploit.produces and RedisExploit.read_only is False
    assert LDAPAnonymous.read_only is True and "user_list" in LDAPAnonymous.produces


def test_persistence_requires_foothold_produces_persistence() -> None:
    for cls in (LinuxPersistence, WindowsPersistence, WebShellPersistence):
        assert "foothold" in cls.requires
        assert "persistence" in cls.produces
        assert cls.read_only is False


def test_detection_modules_read_only_recon() -> None:
    for cls in (DetectionCoverageProbe, LogSourceEnum, OPSECPostureReport):
        assert cls.read_only is True
        assert cls.phase_hint in ("recon", "enumerate")


def test_orchestrator_phase_modules_require_foothold() -> None:
    assert "foothold" in TokenImpersonation.requires and TokenImpersonation.read_only is False
    assert "admin_priv" in TokenImpersonation.produces
    assert ServiceMisconfiguration.read_only is True
    assert "foothold" in LateralMovement.produces and LateralMovement.phase_hint == "pivot"
    assert ValidateFinding.read_only is True and ValidateFinding.phase_hint == "validate"
    assert "shell" in LocalExploitSuggester.requires


def test_supply_chain_modules_read_only_recon() -> None:
    for cls in (ExposedVCS, CICDMisconfig, DependencyConfusion,
                ArtifactExposure, SupplyChainRecon):
        assert cls.read_only is True
        assert cls.phase_hint == "recon"


def test_ics_iot_metadata() -> None:
    # Read-only enums.
    for cls in (ModbusEnum, DNP3Enum, S7Enum, BACnetEnum):
        assert cls.read_only is True and cls.phase_hint == "enumerate"
    # Default-cred checks yield credentials.
    for cls in (HMIDefaultCred, IoTDefaultCred):
        assert "credentials" in cls.produces and cls.read_only is True
    # Destructive write-side modules: dual-gated, active, require foothold.
    for cls in (ModbusWriteCoil, ModbusWriteRegister, S7PlcStop, S7PlcStart):
        assert cls.destructive_ics is True
        assert cls.read_only is False
        assert "foothold" in cls.requires
        assert cls.phase_hint == "exploit"
        assert cls.cost == "high"


def test_to_json_unchanged_shape() -> None:
    """to_json() must stay byte-identical (the test-pinned 5-key contract) -- the
    new capability attrs must NOT leak into to_json()."""
    j = EternalBlue().to_json()
    assert set(j.keys()) == {"name", "description", "target_services",
                             "target_ports", "required_cves"}


def test_capability_record_carries_new_attrs() -> None:
    """capability_record() (the superset) must surface the new metadata."""
    rec = DockerSockEscape().capability_record()
    assert rec["requires"] == DockerSockEscape.requires
    assert rec["produces"] == DockerSockEscape.produces
    assert rec["read_only"] is DockerSockEscape.read_only
    assert rec["phase_hint"] == DockerSockEscape.phase_hint
    assert rec["cost"] == DockerSockEscape.cost
