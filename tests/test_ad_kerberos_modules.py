"""Tests for the Active Directory / Kerberos attack modules in auth_creds.

Imports DIRECTLY from the category module (not from the registry/package) so
these tests do not depend on Round 2 registration wiring.
"""

from __future__ import annotations

from pathlib import Path

from tools.attack_modules.base import ModuleContext
from tools.attack_modules.modules.auth_creds import (
    ADLDAPEnum,
    ASREPRoast,
    DCSyncAttack,
    Kerberoasting,
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


_KERB = [{"service": "kerberos", "port": "88/tcp", "version": ""}]
_LDAP = [{"service": "ldap", "port": "389/tcp", "version": ""}]
_DC = [
    {"service": "ldap", "port": "389/tcp", "version": ""},
    {"service": "microsoft-ds", "port": "445/tcp", "version": ""},
    {"service": "smb", "port": "445/tcp", "version": ""},
]
_HTTP = [{"service": "http", "port": "80/tcp", "version": ""}]


# --------------------------------------------------------------------------- class attrs

class TestClassAttrs:
    def test_asreproast_attrs(self):
        m = ASREPRoast()
        assert m.name == "ASREPRoast"
        assert "kerberos" in m.target_services
        assert 88 in m.target_ports
        assert m.required_cves == []
        assert m.description

    def test_kerberoasting_attrs(self):
        m = Kerberoasting()
        assert m.name == "Kerberoasting"
        assert m.target_services == ["kerberos"]
        assert 88 in m.target_ports
        # Phase 3: 464 (kpasswd) is not used by Kerberoasting; 389 (LDAP) is
        # where GetUserSPNs enumerates SPN-backed accounts.
        assert 389 in m.target_ports
        assert m.required_cves == []
        assert m.description

    def test_dcsync_attrs(self):
        m = DCSyncAttack()
        assert m.name == "DCSyncAttack"
        for svc in ("ldap", "microsoft-ds", "smb", "drsuapi"):
            assert svc in m.target_services
        for port in (389, 445, 3268):
            assert port in m.target_ports
        assert m.required_cves == []
        assert m.description

    def test_adldapenum_attrs(self):
        m = ADLDAPEnum()
        assert m.name == "ADLDAPEnum"
        assert m.target_services == ["ldap"]
        assert 389 in m.target_ports
        assert 3268 in m.target_ports
        assert m.required_cves == []
        assert m.description


# --------------------------------------------------------------------------- run() contracts

class TestRunContract:
    def test_asreproast_run(self):
        ctx = _ctx(_KERB, target_ip="10.0.0.50")
        r = ASREPRoast().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "ASREPRoast"
        assert r["workflow"], "workflow list must be non-empty"
        assert "10.0.0.50" in r["suggested_command"]
        assert r["references"]

    def test_kerberoasting_run(self):
        ctx = _ctx(_KERB, target_ip="10.0.0.99")
        r = Kerberoasting().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "Kerberoasting"
        assert r["workflow"]
        assert "10.0.0.99" in r["suggested_command"]
        assert "13100" in r["suggested_command"] or any("13100" in s for s in r["workflow"])

    def test_dcsync_run(self):
        ctx = _ctx(_DC, target_ip="10.0.0.5")
        r = DCSyncAttack().run(ctx)
        assert r["status"] == "info"
        assert r["module"] == "DCSyncAttack"
        assert r["workflow"]
        assert "10.0.0.5" in r["suggested_command"]
        assert "secretsdump" in r["suggested_command"]

    def test_adldapenum_run_script_generated(self):
        ctx = _ctx(_LDAP, target_ip="10.0.0.7")
        r = ADLDAPEnum().run(ctx)
        assert r["status"] == "script_generated"
        assert r["module"] == "ADLDAPEnum"
        assert r["script"]
        assert "10.0.0.7" in r["script"]
        assert ctx.target_ip in r["script"]


# --------------------------------------------------------------------------- applicability

class TestApplicability:
    def test_asreproast_matches_kerberos(self):
        assert ASREPRoast().applicability(_ctx(_KERB)) > 0

    def test_asreproast_no_match_http(self):
        assert ASREPRoast().applicability(_ctx(_HTTP)) == 0

    def test_kerberoasting_matches_kerberos(self):
        assert Kerberoasting().applicability(_ctx(_KERB)) > 0

    def test_dcsync_matches_dc_services(self):
        assert DCSyncAttack().applicability(_ctx(_DC)) > 0

    def test_dcsync_no_match_http(self):
        assert DCSyncAttack().applicability(_ctx(_HTTP)) == 0

    def test_adldapenum_matches_ldap(self):
        assert ADLDAPEnum().applicability(_ctx(_LDAP)) > 0

    def test_adldapenum_no_match_http(self):
        assert ADLDAPEnum().applicability(_ctx(_HTTP)) == 0


# --------------------------------------------------------------------------- script generation

class TestScriptGeneration:
    def test_adldapenum_generate_python_script_contains_target(self):
        ctx = _ctx(_LDAP, target_ip="10.0.0.7")
        script = ADLDAPEnum().generate_python_script(ctx)
        assert isinstance(script, str)
        assert script.strip()
        assert "10.0.0.7" in script
        # script must connect only to the owned target via the host variable default
        assert ctx.target_ip in script

    def test_adldapenum_script_is_runnable_python_string(self):
        ctx = _ctx(_LDAP, target_ip="10.0.0.7")
        script = ADLDAPEnum().generate_python_script(ctx)
        # The generated string must be a syntactically valid python program
        compile(script, "ad_ldap_enum_gen.py", "exec")