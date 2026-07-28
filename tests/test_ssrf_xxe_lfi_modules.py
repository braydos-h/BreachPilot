"""Tests for the new web-side attack modules: SSRFProbe, XXEProbe, LFITraversal.

These modules are imported DIRECTLY from the web module file -- they are not
yet registered in the registry/__init__ (Round 2 does that). The tests only
exercise the class contract and generated-script shape; no network is touched.
"""

from __future__ import annotations

from tools.attack_modules.modules.web import SSRFProbe, XXEProbe, LFITraversal
from tools.attack_modules.base import ModuleContext


def _http_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="linux",
        services=[
            {"service": "http", "port": "80/tcp", "version": ""},
            {"service": "https", "port": "443/tcp", "version": ""},
        ],
        cves=[],
    )


def _ssh_only_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="linux",
        services=[{"service": "ssh", "port": "22/tcp", "version": ""}],
        cves=[],
    )


# --- SSRFProbe -------------------------------------------------------------

def test_ssrf_probe_class_attrs():
    m = SSRFProbe()
    assert m.name == "SSRFProbe"
    assert "http" in m.target_services
    assert "https" in m.target_services
    assert m.target_ports  # non-empty
    assert m.required_cves == []
    assert m.description


def test_ssrf_probe_run_returns_script_generated():
    ctx = _http_ctx()
    m = SSRFProbe()
    result = m.run(ctx)
    assert result["status"] == "script_generated"
    assert result["module"] == "SSRFProbe"
    assert isinstance(result["script"], str) and result["script"]
    assert ctx.target_ip in result["script"]


def test_ssrf_probe_script_contains_target_and_metadata():
    ctx = _http_ctx()
    script = SSRFProbe().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    # Cloud metadata endpoint payload present
    assert ("169.254.169.254" in script) or ("meta-data" in script)


def test_ssrf_probe_applicability_http_vs_ssh():
    m = SSRFProbe()
    assert m.applicability(_http_ctx()) > 0
    assert m.applicability(_ssh_only_ctx()) == 0


# --- XXEProbe --------------------------------------------------------------

def test_xxe_probe_class_attrs():
    m = XXEProbe()
    assert m.name == "XXEProbe"
    assert "http" in m.target_services
    assert m.target_ports
    assert m.required_cves == []


def test_xxe_probe_run_returns_script_generated():
    ctx = _http_ctx()
    result = XXEProbe().run(ctx)
    assert result["status"] == "script_generated"
    assert result["module"] == "XXEProbe"
    assert result["script"]
    assert ctx.target_ip in result["script"]


def test_xxe_probe_script_has_entity_markup():
    ctx = _http_ctx()
    script = XXEProbe().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    assert ("<!ENTITY" in script) or ("<!DOCTYPE" in script)


def test_xxe_probe_applicability_http_vs_ssh():
    m = XXEProbe()
    assert m.applicability(_http_ctx()) > 0
    assert m.applicability(_ssh_only_ctx()) == 0


# --- LFITraversal ----------------------------------------------------------

def test_lfi_traversal_class_attrs():
    m = LFITraversal()
    assert m.name == "LFITraversal"
    assert "http" in m.target_services
    assert m.target_ports
    assert m.required_cves == []


def test_lfi_traversal_run_returns_script_generated():
    ctx = _http_ctx()
    result = LFITraversal().run(ctx)
    assert result["status"] == "script_generated"
    assert result["module"] == "LFITraversal"
    assert result["script"]
    assert ctx.target_ip in result["script"]


def test_lfi_traversal_script_has_passwd_payload():
    ctx = _http_ctx()
    script = LFITraversal().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    assert "etc/passwd" in script


def test_lfi_traversal_applicability_http_vs_ssh():
    m = LFITraversal()
    assert m.applicability(_http_ctx()) > 0
    assert m.applicability(_ssh_only_ctx()) == 0