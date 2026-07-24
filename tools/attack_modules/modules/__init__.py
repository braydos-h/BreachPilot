"""Category modules re-exports."""

from tools.attack_modules.modules.web import (
    Log4jRCE,
    BasicAuthBuster,
    APIFuzzer,
    WebShellUpload,
    SQLInjection,
    XSSScanner,
    SSTIProbe,
    GraphQLIntrospect,
    RaceRequest,
    TimingOracle,
    RequestSmuggling,
)
from tools.attack_modules.modules.network_smb import (
    SMBGhost,
    EternalBlue,
    SMBRelay,
    SMBNullSession,
    PassTheHash,
    DumpHashes,
)
from tools.attack_modules.modules.ssh import (
    SSHBruteForce,
    RegreSSHion,
    OpenSSHCVECheck,
)
from tools.attack_modules.modules.services import (
    RDPBlueKeep,
    FTPAnonymous,
    RedisExploit,
    ElasticsearchExploit,
    LDAPAnonymous,
    RDPExploit,
)
from tools.attack_modules.modules.auth_creds import (
    CredentialSpray,
    PasswordSpray,
    HashCrack,
)
from tools.attack_modules.modules.privesc import (
    LinuxPrivescCheck,
    WindowsPrivescCheck,
    SUIDEnumeration,
    KernelExploitCheck,
    ContainerBreakout,
)
from tools.attack_modules.modules.crypto_jwt import JWTTamper
from tools.attack_modules.modules.deserialize import DeserializeAttack
from tools.attack_modules.modules.synthesis import (
    CVEToExploit,
    DiffPatchAnalysis,
    FuzzToExploit,
)

__all__ = [
    "Log4jRCE",
    "SMBGhost",
    "EternalBlue",
    "BasicAuthBuster",
    "APIFuzzer",
    "RDPBlueKeep",
    "SSHBruteForce",
    "RegreSSHion",
    "OpenSSHCVECheck",
    "SMBRelay",
    "SMBNullSession",
    "WebShellUpload",
    "SQLInjection",
    "XSSScanner",
    "CredentialSpray",
    "LinuxPrivescCheck",
    "WindowsPrivescCheck",
    "SUIDEnumeration",
    "KernelExploitCheck",
    "ContainerBreakout",
    "FTPAnonymous",
    "RedisExploit",
    "ElasticsearchExploit",
    "LDAPAnonymous",
    "RDPExploit",
    "JWTTamper",
    "SSTIProbe",
    "DeserializeAttack",
    "GraphQLIntrospect",
    "RaceRequest",
    "TimingOracle",
    "RequestSmuggling",
    "PasswordSpray",
    "HashCrack",
    "PassTheHash",
    "DumpHashes",
    "CVEToExploit",
    "DiffPatchAnalysis",
    "FuzzToExploit"
]
