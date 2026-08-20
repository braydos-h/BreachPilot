"""Adversarial tests: isolation, confidence defaults, mutation, poisoning, cycles."""

import pytest

from tools.intelligence.evidence import (
    EvidenceReference,
    EvidenceSource,
    EvidenceStoreV2,
    ProvenanceChain,
    ProvenanceTracker,
)


def _ref(source_tool="nmap", target="10.0.0.1", content="open 22/tcp", **kw):
    return EvidenceReference.create(
        source_tool=source_tool,
        target=target,
        timestamp="2026-08-20T00:00:00Z",
        content=content,
        **kw,
    )


def test_unrelated_evidence_does_not_pollute():
    store = EvidenceStoreV2()
    store.put(_ref(source_tool="nmap", target="10.0.0.1", content="open 22/tcp"))
    store.put(_ref(source_tool="nmap", target="10.0.0.2", content="open 22/tcp"))
    store.put(_ref(source_tool="curl", target="10.0.0.1", content="HTTP 200"))
    assert store.count() == 3
    assert len(store.find_by_target("10.0.0.1")) == 2
    assert len(store.find_by_source_tool("nmap")) == 2
    assert all(r.target == "10.0.0.1" for r in store.find_by_target("10.0.0.1"))


def test_no_provenance_no_confidence():
    chain = ProvenanceChain(root_evidence_id="root", entries=[])
    assert chain.confidence_at("ghost") == 0.0
    assert chain.confidence_at("ghost") <= 0.5


def test_mutated_evidence_is_new_artifact():
    store = EvidenceStoreV2()
    original = _ref(content="open 22/tcp")
    first = store.put(original)
    mutated = _ref(content="open 22/tcp\n# tampered")
    second = store.put(mutated)
    assert first != second
    assert store.count() == 2
    assert store.get(first).content_hash != store.get(second).content_hash


def test_excerpt_poisoning_is_bounded():
    poisoned = "port 22 open\r\ninjected\x00payload\x1b[31mred\x7f"
    ref = _ref(relevant_excerpt=poisoned)
    assert "\n" not in ref.relevant_excerpt
    assert "\r" not in ref.relevant_excerpt
    assert "\x00" not in ref.relevant_excerpt
    assert "\x1b" not in ref.relevant_excerpt
    assert "\x7f" not in ref.relevant_excerpt
    assert ref.relevant_excerpt == "port 22 open injected payload [31mred"


def test_parent_chain_cycle_impossible():
    tracker = ProvenanceTracker()
    tracker.register_root("r1", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0")
    with pytest.raises(ValueError):
        tracker.register_derived("r1", "r1", EvidenceSource.NOTE, "agent", "conclude", "t1", "h1")
