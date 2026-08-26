"""Web subpackage re-exports."""

from tools.attack_modules.modules.web.sqli import LFITraversal, SQLInjection, SSRFProbe, SSTIProbe, XXEProbe
from tools.attack_modules.modules.web.upload import APIFuzzer, BasicAuthBuster, Log4jRCE, RaceRequest, WebShellUpload
from tools.attack_modules.modules.web.xss import GraphQLIntrospect, RequestSmuggling, TimingOracle, XSSScanner

__all__ = [
    "APIFuzzer",
    "BasicAuthBuster",
    "GraphQLIntrospect",
    "LFITraversal",
    "Log4jRCE",
    "RaceRequest",
    "RequestSmuggling",
    "SQLInjection",
    "SSRFProbe",
    "SSTIProbe",
    "TimingOracle",
    "WebShellUpload",
    "XSSScanner",
    "XXEProbe",
]
