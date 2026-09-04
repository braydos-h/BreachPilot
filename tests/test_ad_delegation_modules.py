"""Tests for the AD delegation / ESC execution modules in ad.py.

Imports DIRECTLY from the category module (not from the registry/package) so
these tests do not depend on registration wiring. Mirrors the structure of
tests/test_ad_kerberos_modules.py: class attrs, run() contracts,
applicability, capability metadata.
"""

from __future__ import annotations

from pathlib import Path

from tools.attack_modules.base import ModuleContext
from tools.attack_modules.modules.ad import (
    ESCChain,
    RBCDAttack,
    ShadowCredentials,
)

# --------------------------------------------------------------------------- helpers


def _ctx(services, target_ip="10.0.0.50", cves=None):
    return ModuleContext(
        target_ip=target_ip,
        target_os="windows",
        services=services,
        cves=cves or [],
        workspace=Path("exploit_workspace"),
    )


_LDAP = [{"service": "ldap", "port": "389/tcp", "version": ""}]
_KERB = [{"service": "kerberos", "port": "88/tcp", "version": ""}]
_DC = [
    {"service": "ldap", "port": "389/tcp", "version": ""},
    {"service": "kerberos", "port": "88/tcp", "version": ""},
    {"service": "microsoft-ds", "port": "445/tcp", "version": ""},
]
_HTTP = [{"service": "http", "port": "80/tcp", "version": ""}]


# --------------------------------------------------------------------------- class attrs


class TestClassAttrs:
    def test_rbcd_attrs(self):
        m = RBCDAttack()
        assert m.name == "RBCDAttack"
        assert "ldap" in m.target_services
        assert "kerberos" in m.target_services
        assert 389 in m.target_ports
        assert 88 in m.target_ports
        assert m.required_cves == []
        assert m.description

    def test_shadow_credentials_attrs(self):
        m = ShadowCredentials()
        assert m.name == "ShadowCredentials"
        assert "ldap" in m.target_services
        assert "kerberos" in m.target_services
        assert 389 in m.target_ports
        assert m.required_cves == []
        assert m.description

    def test_escchain_attrs(self):
        m = ESCChain()
        assert m.name == "ESCChain"
        assert "ldap" in m.target_services
        assert 389 in m.target_ports
        assert 445 in m.target_ports
        assert m.required_cves == []
        assert m.description


# --------------------------------------------------------------------------- run() contracts


class TestRunContract:
    def test_rbcd_run(self):
        ctx = _ctx(_DC, target_ip="10.0.0.50")
        r = RBCDAttack().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "RBCDAttack"
        assert r["workflow"], "workflow list must be non-empty"
        assert "10.0.0.50" in r["suggested_command"]
        assert "rbcd" in r["suggested_command"].lower()
        assert "getST" in r["suggested_command"] or "getst" in r["suggested_command"].lower()
        assert r["references"]

    def test_shadow_credentials_run(self):
        ctx = _ctx(_DC, target_ip="10.0.0.51")
        r = ShadowCredentials().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "ShadowCredentials"
        assert r["workflow"]
        assert "10.0.0.51" in r["suggested_command"]
        assert "shadow" in r["suggested_command"].lower()
        assert r["references"]

    def test_escchain_run(self):
        ctx = _ctx(_DC, target_ip="10.0.0.52")
        r = ESCChain().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "ESCChain"
        assert r["workflow"]
        assert "10.0.0.52" in r["suggested_command"]
        assert "certipy" in r["suggested_command"].lower()
        assert r["references"]


# --------------------------------------------------------------------------- applicability


class TestApplicability:
    def test_rbcd_matches_dc_services(self):
        assert RBCDAttack().applicability(_ctx(_DC)) > 0

    def test_rbcd_matches_ldap(self):
        assert RBCDAttack().applicability(_ctx(_LDAP)) > 0

    def test_rbcd_no_match_http(self):
        assert RBCDAttack().applicability(_ctx(_HTTP)) == 0

    def test_shadow_credentials_matches_dc_services(self):
        assert ShadowCredentials().applicability(_ctx(_DC)) > 0

    def test_shadow_credentials_matches_kerberos(self):
        assert ShadowCredentials().applicability(_ctx(_KERB)) > 0

    def test_shadow_credentials_no_match_http(self):
        assert ShadowCredentials().applicability(_ctx(_HTTP)) == 0

    def test_escchain_matches_dc_services(self):
        assert ESCChain().applicability(_ctx(_DC)) > 0

    def test_escchain_matches_ldap(self):
        assert ESCChain().applicability(_ctx(_LDAP)) > 0

    def test_escchain_no_match_http_only(self):
        # http alone scores: ESCChain lists http as a target service (CA
        # enrollment endpoint), so this documents the coupling, not a zero.
        assert ESCChain().applicability(_ctx(_HTTP)) > 0


# --------------------------------------------------------------------------- capability metadata


class TestCapabilityMetadata:
    def test_rbcd_capability(self):
        m = RBCDAttack()
        assert m.requires == ["credentials"]
        assert "credentials" in m.produces
        assert "foothold" in m.produces
        assert m.read_only is False
        assert m.phase_hint == "escalate"

    def test_shadow_credentials_capability(self):
        m = ShadowCredentials()
        assert m.requires == ["credentials"]
        assert "hash_artifact" in m.produces
        assert "credentials" in m.produces
        assert m.read_only is False
        assert m.phase_hint == "escalate"

    def test_escchain_capability(self):
        m = ESCChain()
        assert m.requires == ["credentials"]
        assert "credentials" in m.produces
        assert "hash_artifact" in m.produces
        assert m.read_only is False
        assert m.phase_hint == "exploit"
