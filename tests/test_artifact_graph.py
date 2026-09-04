"""Producer/consumer graph tests over the closed artifact vocabulary."""

from __future__ import annotations

import pytest

from tools.attack_modules import get_module, list_modules
from tools.attack_modules.artifacts import (
    ARTIFACT_VOCAB,
    TERMINAL_ARTIFACTS,
    is_known,
    is_satisfied,
    normalize,
    unknown_kinds,
)
from tools.attack_modules.base import ModuleContext
from tools.attack_modules.graph import (
    chain_to,
    consumers_of,
    dead_end_produces,
    find_cycle,
    missing_prerequisites,
    orphan_requires,
    producers_for,
    rank_producers,
)


def _ctx(**kw) -> ModuleContext:
    base = {
        "target_ip": "10.0.0.50",
        "target_os": "Linux",
        "services": [{"service": "smb", "port": "445/tcp"}],
    }
    base.update(kw)
    return ModuleContext(**base)  # type: ignore[arg-type]


def test_requires_produces_closed_vocab() -> None:
    offenders: list[str] = []
    for mod in list_modules():
        for k in unknown_kinds(mod.requires):
            offenders.append(f"{mod.name}.requires={k!r}")
        for k in unknown_kinds(mod.produces):
            offenders.append(f"{mod.name}.produces={k!r}")
    assert not offenders, f"non-vocab artifact kinds: {offenders}"


def test_every_requires_has_producer() -> None:
    orphans = orphan_requires()
    assert not orphans, f"requires with no producer: {orphans}"


def test_no_producer_consumer_cycle() -> None:
    assert find_cycle() == [], f"artifact cycle: {find_cycle()}"


def test_dead_ends_are_terminal_or_documented() -> None:
    dead = dead_end_produces()
    assert not dead, f"produced artifacts with no consumer: {dead}"


def test_signing_posture_chain() -> None:
    assert "signing_posture" in ARTIFACT_VOCAB
    producers = producers_for("signing_posture")
    assert [m.name for m in producers] == ["SMBSigningCheck"]
    consumers = {m.name for m in consumers_of("signing_posture")}
    assert {"SMBRelay", "ResponderRelay"} <= consumers


def test_rank_producers_cheapest_first() -> None:
    ranked = rank_producers("credentials")
    assert ranked, "no credential producers"
    costs = [m.cost for m in ranked]
    assert costs == sorted(costs, key=lambda c: {"low": 0, "medium": 1, "high": 2}[c])


def test_rank_producers_exclude_self() -> None:
    ranked = rank_producers("credentials", exclude="PasswordSpray")
    assert all(m.name != "PasswordSpray" for m in ranked)


def test_rank_producers_prefers_satisfied() -> None:
    # With a signing_posture finding, SMBRelay/ResponderRelay (requires
    # signing_posture) sort ahead of cred-gated ASREPRoast/Kerberoasting.
    ctx = _ctx(findings=["SMB signing_posture: signing not required on target"])
    ranked = rank_producers("hash_artifact", ctx)
    assert ranked
    assert not missing_prerequisites(ranked[0], ctx), (
        f"satisfiable producer should rank first, got {ranked[0].name} missing {missing_prerequisites(ranked[0], ctx)}"
    )
    # In a bare ctx every hash_artifact producer is honestly gated.
    bare = _ctx()
    assert all(missing_prerequisites(m, bare) for m in rank_producers("hash_artifact", bare))


def test_chain_to_credentials_from_scratch() -> None:
    chains = chain_to("credentials", _ctx(), depth=2)
    assert chains, "no chain produces credentials from a bare SMB ctx"
    # Every chain's first link must be runnable now (no missing prereqs).
    for chain in chains[:3]:
        assert not missing_prerequisites(chain[0], _ctx()), f"chain head blocked: {chain[0].name}"


def test_chain_to_admin_priv_needs_foothold_first() -> None:
    ctx = _ctx(access_achieved=True, sessions=[{"shell": "sh"}])
    chains = chain_to("admin_priv", ctx, depth=2)
    assert chains, "no admin_priv chain even with foothold"


def test_is_satisfied_closed_world() -> None:
    ctx = _ctx()
    assert not is_satisfied("typo_artifact", ctx), "unknown kinds must fail closed"
    assert not is_satisfied("credentials", ctx)
    assert is_satisfied("credentials", _ctx(credentials=[{"username": "a", "password": "b"}]))
    assert not is_satisfied("foothold", ctx)
    assert is_satisfied("foothold", _ctx(access_achieved=True))
    assert is_satisfied("creds", _ctx(credentials=[{"username": "a", "password": "b"}])), "alias"
    assert normalize("root_priv") == "admin_priv"


def test_producer_repair_metadata() -> None:
    # Pinned family contracts (capability_metadata_b, ad_delegation) keep
    # ESCChain.phase_hint == "exploit" and S3BucketTakeover foothold-gated;
    # assert the repairs that do not conflict with those pins.
    assert "signing_posture" in (get_module("SMBSigningCheck").produces or [])
    assert "signing_posture" in (get_module("SMBRelay").requires or [])
    assert "signing_posture" in (get_module("ResponderRelay").requires or [])
    assert set(get_module("LateralMovement").requires or []) == {"foothold", "credentials"}


def test_terminal_artifacts_exempt() -> None:
    assert "persistence" in TERMINAL_ARTIFACTS
    assert is_known("persistence")
