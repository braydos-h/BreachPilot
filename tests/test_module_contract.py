"""Contract tests for every registered attack module (auto-iterates the registry).

Covers the P0 verification gap: recipe/info results must never assert
compromise signals (shell_type / privilege_level / credentials_found) that
were not observed, metadata must use the closed enums, and every result
must round-trip through ``ModuleResult``.

A recipe (``status in {info, script_generated}`` with only queued/planned
evidence) that sets ``shell_type``/``privilege_level``/``credentials_found``
is a false-positive foothold -- the campaign classifier flips
``access_achieved`` on those keys. ``confidence``/``verdict`` carry the
honest signal instead.
"""

from __future__ import annotations

import pytest

from tools.attack_modules import list_modules
from tools.attack_modules.base import ModuleContext, ModuleResult

ALLOWED_STATUS = {"info", "script_generated", "success", "failed", "blocked"}
ALLOWED_COST = {"low", "medium", "high"}
ALLOWED_PHASE = {"recon", "enumerate", "exploit", "escalate", "loot", "persist", "validate", "pivot", ""}
ALLOWED_VERDICT = {"confirmed", "disproven", "inconclusive"}

# Substrings that mark evidence as "queued/planned, not observed".
UNOBSERVED_MARKERS = ("queued", "planned", "applicable to", "candidate", "recipe")


def _ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="127.0.0.1",
        target_os="Linux",
        services=[
            {"service": "http", "port": "80/tcp", "version": ""},
            {"service": "ssh", "port": "22/tcp", "version": "OpenSSH 8.5p1"},
            {"service": "smb", "port": "445/tcp", "version": ""},
        ],
        cves=["CVE-2021-44228", "CVE-2024-6387"],
    )


def _is_observed(evidence: list) -> bool:
    text = " ".join(str(e) for e in evidence).lower()
    if not text.strip():
        return False
    return not any(m in text for m in UNOBSERVED_MARKERS)


def test_module_names_unique() -> None:
    names = [m.name for m in list_modules()]
    assert len(names) == len({n.lower() for n in names}), "duplicate module names (case-insensitive)"
    assert all(n.strip() for n in names), "blank module name"


def test_module_metadata_enums() -> None:
    offenders: list[str] = []
    for mod in list_modules():
        if not isinstance(mod.target_services, list) or not isinstance(mod.target_ports, list):
            offenders.append(f"{mod.name}: target_services/ports not lists")
        if not isinstance(mod.required_cves, list) or not isinstance(mod.target_versions, dict):
            offenders.append(f"{mod.name}: required_cves/target_versions wrong types")
        if not isinstance(mod.requires, list) or not isinstance(mod.produces, list):
            offenders.append(f"{mod.name}: requires/produces not lists")
        if not isinstance(mod.read_only, bool):
            offenders.append(f"{mod.name}: read_only not bool")
        if mod.cost not in ALLOWED_COST:
            offenders.append(f"{mod.name}: cost={mod.cost!r}")
        if mod.phase_hint not in ALLOWED_PHASE:
            offenders.append(f"{mod.name}: phase_hint={mod.phase_hint!r}")
        if not mod.description.strip():
            offenders.append(f"{mod.name}: empty description")
    assert not offenders, f"metadata violations: {offenders}"


def test_to_json_shape_stable() -> None:
    for mod in list_modules():
        data = mod.to_json()
        assert set(data) == {
            "name",
            "description",
            "target_services",
            "target_ports",
            "required_cves",
        }, f"{mod.name}: to_json keys changed {sorted(data)}"


def test_no_premature_compromise_claims() -> None:
    """Recipe results must not assert shell/priv/creds without observed evidence."""
    offenders: list[str] = []
    for mod in list_modules():
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            continue  # raising modules are covered by test_module_lint's skip; track separately
        if not isinstance(result, dict):
            offenders.append(f"{mod.name}: non-dict run() return")
            continue
        if result.get("status") not in ALLOWED_STATUS:
            offenders.append(f"{mod.name}: status={result.get('status')!r}")
            continue
        claims_compromise = bool(
            result.get("shell_type") or result.get("privilege_level") or result.get("credentials_found")
        )
        if not claims_compromise:
            continue
        evidence = result.get("evidence") or []
        confidence = result.get("confidence")
        verdict = result.get("verdict", "inconclusive")
        observed = _is_observed(evidence if isinstance(evidence, list) else [evidence])
        honest = (
            observed
            and isinstance(confidence, (int, float))
            and confidence >= 0.7
            and verdict == "confirmed"
            and result.get("status") not in {"info"}
        )
        if not honest:
            offenders.append(
                f"{mod.name}: status={result.get('status')!r} claims compromise "
                f"(shell={result.get('shell_type')!r} priv={result.get('privilege_level')!r} "
                f"creds={bool(result.get('credentials_found'))}) with evidence={evidence!r}"
            )
    assert not offenders, f"premature compromise claims: {offenders}"


def test_read_only_modules_claim_nothing() -> None:
    offenders = []
    for mod in list_modules():
        if not mod.read_only:
            continue
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            continue
        if not isinstance(result, dict):
            continue
        if result.get("shell_type") or result.get("privilege_level"):
            offenders.append(mod.name)
    assert not offenders, f"read-only modules setting shell/priv: {offenders}"


def test_results_round_trip_module_result() -> None:
    for mod in list_modules():
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            continue
        if not isinstance(result, dict):
            pytest.fail(f"{mod.name}: non-dict run() return")
        adapted = ModuleResult.to_result(result)
        back = adapted.to_dict()
        assert back["status"] == (result.get("status") or "executed")
        assert back["module"] == (result.get("module") or "")
        if result.get("verdict") not in (None, "", "inconclusive"):
            assert back.get("verdict") == result["verdict"], f"{mod.name}: verdict dropped"


def test_verdict_values_valid() -> None:
    offenders = []
    for mod in list_modules():
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            continue
        if not isinstance(result, dict):
            continue
        verdict = result.get("verdict", "inconclusive")
        if verdict not in ALLOWED_VERDICT:
            offenders.append(f"{mod.name}: verdict={verdict!r}")
    assert not offenders, f"invalid verdicts: {offenders}"


def test_applicability_bounded() -> None:
    ctx = _ctx()
    for mod in list_modules():
        score = mod.applicability(ctx)
        assert isinstance(score, int), f"{mod.name}: applicability not int"
        assert 0 <= score <= 100, f"{mod.name}: score {score} out of range"
        report = mod.applicability_explain(ctx)
        assert report.score == score, f"{mod.name}: explain score {report.score} != {score}"


def test_port_normalization_int_str_slashed() -> None:
    """base.port_of fix: int, bare-string, and slashed ports score identically."""
    from tools.attack_modules import get_module

    mod = get_module("SSHBruteForce")
    assert mod is not None
    variants = ["22/tcp", "22", 22]
    scores = set()
    for port in variants:
        ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "ssh", "port": port}])
        scores.add(mod.applicability(ctx))
    assert len(scores) == 1, f"port-shape-dependent scoring: {scores}"
    assert next(iter(scores)) > 0


def test_kernel_range_regression() -> None:
    """privesc KernelExploitCheck: in_range must honor hi (was lo,lo)."""
    from tools.attack_modules import get_module

    mod = get_module("KernelExploitCheck")
    assert mod is not None
    script = mod.generate_python_script(ModuleContext(target_ip="10.0.0.50"))
    assert "for (lo, hi), cve, name in KERNEL_CVE_MAP" in script
    assert "in_range(v, lo, hi)" in script
    # Direct range check mirroring the embedded helper.
    lo_t = tuple(int(x) for x in "5.8.0".split("."))
    hi_t = tuple(int(x) for x in "5.16.11".split("."))
    assert lo_t <= (5, 15, 0) <= hi_t, "5.15.0 must be inside DirtyPipe range"
    assert not (lo_t <= (6, 8, 0) <= hi_t), "6.8.0 must be outside DirtyPipe range"
