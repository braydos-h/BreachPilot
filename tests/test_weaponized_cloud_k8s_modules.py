"""Tests for the WeaponizedExploit, CloudPrivesc, and K8sPrivesc attack modules.

Imports DIRECTLY from the module files -- not via the registry or package
__init__ -- to avoid coupling these tests to registration ordering owned by
other agents.
"""

from __future__ import annotations

from tools.attack_modules.modules.synthesis import WeaponizedExploit
from tools.attack_modules.modules.privesc import CloudPrivesc, K8sPrivesc
from tools.attack_modules.base import ModuleContext


# ---------------------------------------------------------------------------
# WeaponizedExploit
# ---------------------------------------------------------------------------

def _http_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="linux",
        services=[{"service": "http", "port": "80/tcp"}, {"service": "https", "port": "443/tcp"}],
        cves=["CVE-2021-44228"],
    )


def test_weaponized_exploit_class_attrs():
    m = WeaponizedExploit()
    assert m.name == "WeaponizedExploit"
    assert "http" in m.target_services
    assert "https" in m.target_services
    assert 80 in m.target_ports
    assert 443 in m.target_ports
    assert m.required_cves == []


def test_weaponized_exploit_run_returns_info_workflow():
    m = WeaponizedExploit()
    res = m.run(_http_ctx())
    assert res["status"] == "info"
    assert res["module"] == m.name
    assert isinstance(res["workflow"], list) and len(res["workflow"]) > 0
    assert isinstance(res["prompt_template"], str) and len(res["prompt_template"]) > 0


def test_weaponized_exploit_expected_shell_type_not_shell_type():
    m = WeaponizedExploit()
    res = m.run(_http_ctx())
    # Expresses INTENT only -- must not falsely claim a confirmed shell.
    assert res["expected_shell_type"] == "reverse"
    assert "shell_type" not in res, "run() must not set shell_type (confirmed-compromise signal)"
    assert "privilege_level" not in res, "run() must not set privilege_level"


def test_weaponized_exploit_applicability_http():
    m = WeaponizedExploit()
    assert m.applicability(_http_ctx()) > 0


def test_weaponized_exploit_applicability_no_match():
    m = WeaponizedExploit()
    ctx = ModuleContext(
        target_ip="10.0.0.50",
        services=[{"service": "ftp", "port": "21/tcp"}],
    )
    assert m.applicability(ctx) == 0


# ---------------------------------------------------------------------------
# CloudPrivesc
# ---------------------------------------------------------------------------

def _docker_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.60",
        target_os="linux",
        services=[{"service": "docker", "port": "2375/tcp"}],
    )


def test_cloud_privesc_run_script_generated():
    m = CloudPrivesc()
    ctx = _docker_ctx()
    res = m.run(ctx)
    assert res["status"] == "script_generated"
    assert res["module"] == m.name
    assert isinstance(res["script"], str) and len(res["script"]) > 0
    assert "169.254.169.254" in res["script"]
    assert ctx.target_ip in res["script"]


def test_cloud_privesc_applicability_docker():
    m = CloudPrivesc()
    assert m.applicability(_docker_ctx()) > 0


def test_cloud_privesc_applicability_ssh_only_is_zero():
    m = CloudPrivesc()
    ctx = ModuleContext(
        target_ip="10.0.0.60",
        services=[{"service": "ssh", "port": "22/tcp"}],
    )
    # ssh is not in CloudPrivesc.target_services, and 22 not in target_ports
    assert m.applicability(ctx) == 0


# ---------------------------------------------------------------------------
# K8sPrivesc
# ---------------------------------------------------------------------------

def _k8s_ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.70",
        target_os="linux",
        services=[{"service": "k8s", "port": "6443/tcp"}],
    )


def test_k8s_privesc_run_script_generated():
    m = K8sPrivesc()
    ctx = _k8s_ctx()
    res = m.run(ctx)
    assert res["status"] == "script_generated"
    assert res["module"] == m.name
    assert isinstance(res["script"], str) and len(res["script"]) > 0
    assert ("10250" in res["script"]) or ("kubelet" in res["script"])
    assert ctx.target_ip in res["script"]


def test_k8s_privesc_applicability_k8s():
    m = K8sPrivesc()
    assert m.applicability(_k8s_ctx()) > 0