"""Phase 3 (group A): capability-metadata shape test.

Verifies that the AttackModule subclasses in group A files
(web, auth_creds, ad, crypto_jwt, deserialize, synthesis) declare accurate
``requires`` / ``produces`` / ``read_only`` / ``cost`` / ``phase_hint`` class
attributes so ``find_producers`` composition + the planner's prerequisite
gating work. This is a SHAPE test only -- no run()/applicability() execution.
"""

from __future__ import annotations

from tools.attack_modules.base import AttackModule
from tools.attack_modules.modules.ad import (
    ADCSEnum,
    BloodHoundCollect,
    GoldenTicket,
    ResponderRelay,
    SMBSigningCheck,
)
from tools.attack_modules.modules.auth_creds import (
    ADLDAPEnum,
    ASREPRoast,
    CredentialSpray,
    DCSyncAttack,
    HashCrack,
    Kerberoasting,
    PasswordSpray,
)
from tools.attack_modules.modules.crypto_jwt import JWTTamper
from tools.attack_modules.modules.deserialize import DeserializeAttack
from tools.attack_modules.modules.synthesis import (
    CVEToExploit,
    DiffPatchAnalysis,
    FuzzToExploit,
    WeaponizedExploit,
)
from tools.attack_modules.modules.web import (
    APIFuzzer,
    BasicAuthBuster,
    GraphQLIntrospect,
    LFITraversal,
    Log4jRCE,
    RaceRequest,
    RequestSmuggling,
    SQLInjection,
    SSRFProbe,
    SSTIProbe,
    TimingOracle,
    WebShellUpload,
    XSSScanner,
    XXEProbe,
)

# Group A modules + their file of origin, for the "all annotated" sweep.
_GROUP_A: list[tuple[AttackModule, str]] = [
    (Log4jRCE, "web"),
    (BasicAuthBuster, "web"),
    (APIFuzzer, "web"),
    (WebShellUpload, "web"),
    (SQLInjection, "web"),
    (XSSScanner, "web"),
    (SSTIProbe, "web"),
    (GraphQLIntrospect, "web"),
    (RaceRequest, "web"),
    (TimingOracle, "web"),
    (RequestSmuggling, "web"),
    (SSRFProbe, "web"),
    (XXEProbe, "web"),
    (LFITraversal, "web"),
    (CredentialSpray, "auth_creds"),
    (PasswordSpray, "auth_creds"),
    (HashCrack, "auth_creds"),
    (ASREPRoast, "auth_creds"),
    (Kerberoasting, "auth_creds"),
    (DCSyncAttack, "auth_creds"),
    (ADLDAPEnum, "auth_creds"),
    (ADCSEnum, "ad"),
    (BloodHoundCollect, "ad"),
    (ResponderRelay, "ad"),
    (GoldenTicket, "ad"),
    (SMBSigningCheck, "ad"),
    (JWTTamper, "crypto_jwt"),
    (DeserializeAttack, "deserialize"),
    (CVEToExploit, "synthesis"),
    (DiffPatchAnalysis, "synthesis"),
    (FuzzToExploit, "synthesis"),
    (WeaponizedExploit, "synthesis"),
]


def test_all_group_a_modules_annotate_capability_metadata() -> None:
    """Every group A module must set all five capability attrs to a non-default
    value (the ABC defaults are [], [], False, "medium", "" -- we require an
    explicit phase_hint at minimum so the planner can bucket the module)."""
    missing: list[str] = []
    for cls, _file in _GROUP_A:
        # phase_hint is the one attr with no useful default (""); require it.
        if not getattr(cls, "phase_hint", ""):
            missing.append(f"{cls.__name__}.phase_hint")
    assert not missing, f"group A modules missing phase_hint: {missing}"


def test_foothold_producers_exist() -> None:
    """At least one group A module must declare it produces a foothold/shell so
    find_producers("foothold") / find_producers("shell") return candidates."""
    producers: list[str] = []
    for cls, _file in _GROUP_A:
        if "foothold" in cls.produces or "shell" in cls.produces:
            producers.append(cls.__name__)
    assert "Log4jRCE" in producers
    assert "WebShellUpload" in producers
    assert "DeserializeAttack" in producers
    assert "GoldenTicket" in producers


def test_log4j_rce_metadata() -> None:
    assert Log4jRCE.requires == []
    assert "shell" in Log4jRCE.produces
    assert "foothold" in Log4jRCE.produces
    assert Log4jRCE.read_only is False
    assert Log4jRCE.phase_hint == "exploit"


def test_web_shell_upload_metadata() -> None:
    assert "webshell" in WebShellUpload.produces
    assert "foothold" in WebShellUpload.produces
    assert WebShellUpload.read_only is False
    assert WebShellUpload.phase_hint == "exploit"


def test_basic_auth_buster_produces_credentials() -> None:
    assert "credentials" in BasicAuthBuster.produces
    assert BasicAuthBuster.read_only is False
    assert BasicAuthBuster.phase_hint == "exploit"


def test_ad_ldap_enum_produces_user_list_read_only() -> None:
    assert "user_list" in ADLDAPEnum.produces
    assert ADLDAPEnum.read_only is True
    assert ADLDAPEnum.phase_hint == "enumerate"


def test_credential_spray_requires_user_list() -> None:
    assert "user_list" in CredentialSpray.requires
    assert "credentials" in CredentialSpray.produces
    assert CredentialSpray.phase_hint == "exploit"


def test_password_spray_requires_user_list() -> None:
    assert "user_list" in PasswordSpray.requires
    assert "credentials" in PasswordSpray.produces


def test_asrep_roast_chain() -> None:
    assert "user_list" in ASREPRoast.requires
    assert "hash_artifact" in ASREPRoast.produces
    assert ASREPRoast.phase_hint == "exploit"


def test_kerberoasting_chain() -> None:
    assert "user_list" in Kerberoasting.requires
    assert "hash_artifact" in Kerberoasting.produces


def test_hash_crack_consumes_hash_produces_credentials() -> None:
    assert "hash_artifact" in HashCrack.requires
    assert "credentials" in HashCrack.produces
    assert HashCrack.read_only is True
    assert HashCrack.phase_hint == "loot"


def test_dcsync_requires_admin_priv() -> None:
    assert "admin_priv" in DCSyncAttack.requires
    assert "hash_artifact" in DCSyncAttack.produces
    assert "credentials" in DCSyncAttack.produces
    assert DCSyncAttack.phase_hint == "escalate"


def test_golden_ticket_chain() -> None:
    assert "admin_priv" in GoldenTicket.requires
    assert "credentials" in GoldenTicket.produces
    assert GoldenTicket.phase_hint == "escalate"


def test_jwt_tamper_produces_credentials() -> None:
    assert "credentials" in JWTTamper.produces
    assert JWTTamper.read_only is False
    assert JWTTamper.phase_hint == "exploit"


def test_deserialize_attack_produces_shell() -> None:
    assert "shell" in DeserializeAttack.produces
    assert DeserializeAttack.read_only is False
    assert DeserializeAttack.phase_hint == "exploit"


def test_ad_cs_enum_read_only_requires_credentials() -> None:
    assert "credentials" in ADCSEnum.requires
    assert ADCSEnum.read_only is True
    assert ADCSEnum.phase_hint == "enumerate"


def test_bloodhound_collect_read_only() -> None:
    assert "credentials" in BloodHoundCollect.requires
    assert BloodHoundCollect.read_only is True
    assert BloodHoundCollect.phase_hint == "enumerate"


def test_responder_relay_produces_creds() -> None:
    assert "hash_artifact" in ResponderRelay.produces or "credentials" in ResponderRelay.produces
    assert ResponderRelay.read_only is False
    assert ResponderRelay.phase_hint == "exploit"


def test_smb_signing_check_read_only() -> None:
    assert SMBSigningCheck.read_only is True
    assert SMBSigningCheck.phase_hint == "enumerate"


def test_synthesis_stubs_are_read_only_info_carriers() -> None:
    for cls in (CVEToExploit, DiffPatchAnalysis, FuzzToExploit, WeaponizedExploit):
        assert cls.read_only is True, f"{cls.__name__} should be read-only (prompt-carrier)"
        assert cls.produces == [], f"{cls.__name__} should produce no artifact"
        assert cls.phase_hint == "exploit"


def test_enumerate_phase_modules() -> None:
    """Read-only detection/enumeration modules bucket into phase_hint='enumerate'."""
    for cls in (ADLDAPEnum, GraphQLIntrospect, TimingOracle, SMBSigningCheck, ADCSEnum, BloodHoundCollect):
        assert cls.phase_hint == "enumerate", f"{cls.__name__} should be enumerate"


def test_to_json_unchanged_shape() -> None:
    """to_json() must stay byte-identical (the test-pinned 5-key contract) -- the
    new capability attrs must NOT leak into to_json()."""
    j = Log4jRCE().to_json()
    assert set(j.keys()) == {"name", "description", "target_services", "target_ports", "required_cves"}


def test_capability_record_carries_new_attrs() -> None:
    """capability_record() (the superset) must surface the new metadata."""
    rec = DCSyncAttack().capability_record()
    assert rec["requires"] == DCSyncAttack.requires
    assert rec["produces"] == DCSyncAttack.produces
    assert rec["read_only"] is DCSyncAttack.read_only
    assert rec["phase_hint"] == DCSyncAttack.phase_hint
    assert rec["cost"] == DCSyncAttack.cost
