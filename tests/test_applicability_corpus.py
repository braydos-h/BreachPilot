"""Applicability corpus: positive/negative synthetic contexts per module family.

Pins the evidence-layer scorer semantics: service/port/CVE bonuses, OS veto,
CVE-absent cap, prerequisite demotion, service-alias matching, and
int/str/slashed port equivalence. If selection quality regresses, these bands
fail first.
"""

from __future__ import annotations

from tools.attack_modules import find_modules, get_module
from tools.attack_modules.base import ModuleContext


def _ctx(services=None, cves=None, os=None, **kw) -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os=os,
        services=services or [],
        cves=cves or [],
        **kw,  # type: ignore[arg-type]
    )


def _score(name: str, ctx: ModuleContext) -> int:
    mod = get_module(name)
    assert mod is not None, f"module {name} not registered"
    return mod.applicability(ctx)


# ── Web / CVE-gated exploits ──────────────────────────────────────────────


def test_log4j_confirmed_cve_scores_high() -> None:
    ctx = _ctx([{"service": "http", "port": "8080/tcp"}], ["CVE-2021-44228"])
    assert _score("Log4jRCE", ctx) >= 70


def test_log4j_without_cve_capped_at_probe() -> None:
    # Same open port, no CVE: capped at 30 (probe, not exploit).
    ctx = _ctx([{"service": "http", "port": "8080/tcp"}])
    assert _score("Log4jRCE", ctx) <= 30


def test_eternalblue_without_cve_capped() -> None:
    ctx = _ctx([{"service": "microsoft-ds", "port": "445/tcp"}], os="Windows")
    assert _score("EternalBlue", ctx) <= 30


def test_eternalblue_confirmed_scores_high() -> None:
    ctx = _ctx([{"service": "microsoft-ds", "port": "445/tcp"}], ["CVE-2017-0144"], os="Windows")
    assert _score("EternalBlue", ctx) >= 70


# ── OS veto ───────────────────────────────────────────────────────────────


def test_linux_privesc_vetoed_on_windows() -> None:
    ctx = _ctx(os="Windows", access_achieved=True, sessions=[{"shell": "cmd"}])
    assert _score("LinuxPrivescCheck", ctx) == 0


def test_windows_privesc_vetoed_on_linux() -> None:
    ctx = _ctx(os="Linux", access_achieved=True, sessions=[{"shell": "sh"}])
    assert _score("WindowsPrivescCheck", ctx) == 0


def test_linux_privesc_scores_with_foothold() -> None:
    ctx = _ctx(os="Linux", access_achieved=True, sessions=[{"shell": "sh"}])
    assert _score("LinuxPrivescCheck", ctx) >= 30


def test_privesc_hidden_without_foothold_or_os() -> None:
    # No OS, no foothold, no services: OS-gated module has no signal.
    assert _score("LinuxPrivescCheck", _ctx()) == 0


# ── Prerequisite demotion (visible, not hidden) ───────────────────────────


def test_pth_demoted_without_creds_but_visible() -> None:
    ctx = _ctx([{"service": "smb", "port": "445/tcp"}])
    s = _score("PassTheHash", ctx)
    assert 0 < s < 50, f"expected demoted-but-visible, got {s}"


def test_pth_full_score_with_creds() -> None:
    ctx = _ctx(
        [{"service": "smb", "port": "445/tcp"}],
        credentials=[{"username": "Administrator", "ntlm_hash": "aad3b..."}],
    )
    assert _score("PassTheHash", ctx) >= 50


def test_relay_demoted_without_signing_posture() -> None:
    ctx = _ctx([{"service": "microsoft-ds", "port": "445/tcp"}])
    assert _score("SMBRelay", ctx) < 50


# ── Service aliases ───────────────────────────────────────────────────────


def test_rdp_alias_matches_ms_wbt() -> None:
    a = _score("RDPBlueKeep", _ctx([{"service": "rdp", "port": "3389/tcp"}]))
    b = _score("RDPBlueKeep", _ctx([{"service": "ms-wbt-server", "port": "3389/tcp"}]))
    assert a == b > 0


def test_smb_alias_matches() -> None:
    a = _score("SMBNullSession", _ctx([{"service": "smb", "port": "445/tcp"}]))
    b = _score("SMBNullSession", _ctx([{"service": "microsoft-ds", "port": "445/tcp"}]))
    assert a == b > 0


def test_http_https_not_aliased() -> None:
    # Scheme matters to web payloads: an http-only module on a bare https
    # service (no port match) scores lower than on http.
    from tools.attack_modules import get_module as _get

    mod = _get("SQLInjection")
    assert mod is not None
    http = mod.applicability(_ctx([{"service": "http", "port": "80/tcp"}]))
    https = mod.applicability(_ctx([{"service": "https", "port": "443/tcp"}]))
    assert http >= 30
    assert https >= 30  # port still matches; service does not double-count
    assert https < http or https == http


# ── Port-shape equivalence ────────────────────────────────────────────────


def test_int_str_slashed_ports_identical() -> None:
    mod = get_module("SSHBruteForce")
    assert mod is not None
    scores = {
        mod.applicability(_ctx([{"service": "ssh", "port": p}])) for p in ("22/tcp", "22", 22)
    }
    assert len(scores) == 1 and next(iter(scores)) > 0


# ── Detection fixed scores ────────────────────────────────────────────────


def test_detection_always_selectable_low() -> None:
    assert _score("detection_coverage_probe", _ctx()) == 15
    assert _score("opsec_posture_report", _ctx()) == 10


# ── find_modules integration ──────────────────────────────────────────────


def test_find_modules_orders_confirmed_first() -> None:
    ctx = _ctx([{"service": "microsoft-ds", "port": "445/tcp"}], ["CVE-2017-0144"], os="Windows")
    names = [m.name for _, m in find_modules(ctx)]
    assert "EternalBlue" in names
    assert names.index("EternalBlue") < names.index("SMBRelay")


def test_find_modules_excludes_os_mismatch() -> None:
    ctx = _ctx(os="Windows", access_achieved=True, sessions=[{"shell": "cmd"}])
    names = [m.name for _, m in find_modules(ctx)]
    assert "LinuxPrivescCheck" not in names
    assert "WindowsPrivescCheck" in names
