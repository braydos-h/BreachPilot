"""Tests for supply-chain / CI-CD reconnaissance attack modules.

Detection-only modules against an authorized lab target (ctx.target_ip).
"""

from __future__ import annotations

from tools.attack_modules.base import ModuleContext
from tools.attack_modules.modules.supply_chain import (
    ArtifactExposure,
    CICDMisconfig,
    DependencyConfusion,
    ExposedVCS,
    SupplyChainRecon,
)


def _http_ctx(target_ip: str = "10.0.0.50") -> ModuleContext:
    return ModuleContext(
        target_ip=target_ip,
        target_os="linux",
        services=[{"service": "http", "port": "80/tcp"}, {"service": "https", "port": "443/tcp"}],
        cves=[],
    )


def _no_match_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="linux",
        services=[{"service": "ftp", "port": "21/tcp"}],
        cves=[],
    )


# --- class attribute tests -------------------------------------------------


def test_exposed_vcs_class_attrs():
    assert ExposedVCS.name == "ExposedVCS"
    assert "http" in ExposedVCS.target_services
    assert "https" in ExposedVCS.target_services
    assert 80 in ExposedVCS.target_ports
    assert 443 in ExposedVCS.target_ports
    assert 8080 in ExposedVCS.target_ports
    assert 8443 in ExposedVCS.target_ports
    assert 3000 in ExposedVCS.target_ports
    assert ExposedVCS.required_cves == []


def test_cicd_misconfig_class_attrs():
    assert CICDMisconfig.name == "CICDMisconfig"
    assert "http" in CICDMisconfig.target_services
    for port in (80, 443, 8080, 8443, 8081, 9090, 3000):
        assert port in CICDMisconfig.target_ports
    assert CICDMisconfig.required_cves == []


def test_dependency_confusion_class_attrs():
    assert DependencyConfusion.name == "DependencyConfusion"
    assert "http" in DependencyConfusion.target_services
    for port in (80, 443, 8080, 8443, 3000):
        assert port in DependencyConfusion.target_ports
    assert DependencyConfusion.required_cves == []


def test_artifact_exposure_class_attrs():
    assert ArtifactExposure.name == "ArtifactExposure"
    assert "http" in ArtifactExposure.target_services
    for port in (80, 443, 8080, 8443, 3000, 8081):
        assert port in ArtifactExposure.target_ports
    assert ArtifactExposure.required_cves == []


def test_supply_chain_recon_class_attrs():
    assert SupplyChainRecon.name == "SupplyChainRecon"
    for svc in ("http", "https", "ssh", "smb", "microsoft-ds"):
        assert svc in SupplyChainRecon.target_services
    for port in (80, 443, 22, 445, 8080):
        assert port in SupplyChainRecon.target_ports
    assert SupplyChainRecon.required_cves == []


# --- script_generated modules ---------------------------------------------


def test_exposed_vcs_run_and_script():
    ctx = _http_ctx()
    result = ExposedVCS().run(ctx)
    assert result["status"] == "script_generated"
    assert "script" in result and result["script"]
    assert ctx.target_ip in result["script"]
    script = ExposedVCS().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    assert ".git" in script


def test_cicd_misconfig_run_and_script():
    ctx = _http_ctx()
    result = CICDMisconfig().run(ctx)
    assert result["status"] == "script_generated"
    assert "script" in result and result["script"]
    assert ctx.target_ip in result["script"]
    script = CICDMisconfig().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    assert ("Jenkinsfile" in script) or (".github/workflows" in script) or ("gitlab-ci" in script)


def test_artifact_exposure_run_and_script():
    ctx = _http_ctx()
    result = ArtifactExposure().run(ctx)
    assert result["status"] == "script_generated"
    assert "script" in result and result["script"]
    assert ctx.target_ip in result["script"]
    script = ArtifactExposure().generate_python_script(ctx)
    assert script
    assert ctx.target_ip in script
    assert (".env" in script) or ("credentials" in script)


# --- info / workflow modules ----------------------------------------------


def test_dependency_confusion_run_is_info():
    ctx = _http_ctx()
    result = DependencyConfusion().run(ctx)
    assert result["status"] == "info"
    workflow = result.get("workflow")
    assert isinstance(workflow, list) and len(workflow) > 0
    text = " ".join(workflow).lower()
    # Must be framed as detection / reporting.
    assert ("detection" in text) or ("report" in text)
    # Must NOT instruct registering a malicious package in a public registry.
    assert "register a package" not in text
    assert "registering" not in text


def test_supply_chain_recon_run_is_info():
    ctx = _http_ctx()
    result = SupplyChainRecon().run(ctx)
    assert result["status"] == "info"
    workflow = result.get("workflow")
    assert isinstance(workflow, list) and len(workflow) > 0
    text = " ".join(workflow).lower()
    assert ("search_cve_intel" in text) or ("search_web_exploit" in text)


# --- applicability --------------------------------------------------------


def test_applicability_http_match():
    ctx = _http_ctx()
    assert ExposedVCS().applicability(ctx) > 0
    assert CICDMisconfig().applicability(ctx) > 0
    assert DependencyConfusion().applicability(ctx) > 0
    assert ArtifactExposure().applicability(ctx) > 0
    assert SupplyChainRecon().applicability(ctx) > 0


def test_applicability_no_match_zero():
    ctx = _no_match_ctx()
    # No http/https/ssh/smb services and no matching ports -> zero applicability.
    assert ExposedVCS().applicability(ctx) == 0
    assert CICDMisconfig().applicability(ctx) == 0
    assert DependencyConfusion().applicability(ctx) == 0
    assert ArtifactExposure().applicability(ctx) == 0
    assert SupplyChainRecon().applicability(ctx) == 0


def test_dependency_confusion_no_python_script():
    ctx = _http_ctx()
    assert DependencyConfusion().generate_python_script(ctx) == ""


def test_supply_chain_recon_no_python_script():
    ctx = _http_ctx()
    assert SupplyChainRecon().generate_python_script(ctx) == ""