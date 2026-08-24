"""Tests for the evidence provenance layer."""

import pytest

from tools.intelligence.evidence import (
    EvidenceLevel,
    EvidenceReference,
    EvidenceSource,
    EvidenceStoreV2,
    ProvenanceChain,
    ProvenanceEntry,
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


def test_create_stable_id_for_identical_inputs():
    a = _ref()
    b = _ref()
    assert a.ref_id == b.ref_id
    assert len(a.ref_id) == 16


def test_create_different_id_for_different_source():
    a = _ref(source_tool="nmap")
    b = _ref(source_tool="masscan")
    assert a.ref_id != b.ref_id


def test_from_dict_to_dict_round_trip():
    ref = _ref(
        producing_action="port_scan",
        relevant_excerpt="port 22 open",
        structured_fields={"port": 22, "state": "open"},
        confidence=0.9,
    )
    restored = EvidenceReference.from_dict(ref.to_dict())
    assert restored == ref


def test_from_dict_tolerates_missing_keys():
    ref = EvidenceReference.from_dict({"ref_id": "abc"})
    assert ref.ref_id == "abc"
    assert ref.source_tool == ""
    assert ref.confidence == 0.5
    assert ref.structured_fields == {}


def test_store_put_dedupes_identical_refs():
    store = EvidenceStoreV2()
    first = store.put(_ref())
    second = store.put(_ref())
    assert first == second
    assert store.count() == 1


def test_store_put_different_content_distinct():
    store = EvidenceStoreV2()
    a = store.put(_ref(content="open 22/tcp"))
    b = store.put(_ref(content="open 80/tcp"))
    assert a != b
    assert store.count() == 2


def test_store_find_and_count():
    store = EvidenceStoreV2()
    store.put(_ref(source_tool="nmap", target="10.0.0.1"))
    store.put(_ref(source_tool="nmap", target="10.0.0.2"))
    store.put(_ref(source_tool="curl", target="10.0.0.1"))
    assert store.count() == 3
    assert len(store.find_by_source_tool("nmap")) == 2
    assert len(store.find_by_target("10.0.0.1")) == 2
    assert store.get(store.list_all()[0].ref_id) is not None


def test_provenance_chain_root_to_leaf_order():
    chain = ProvenanceChain(
        root_evidence_id="root",
        entries=[
            ProvenanceEntry("root", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0"),
            ProvenanceEntry(
                "leaf", EvidenceSource.AGENT_OBSERVATION, "agent", "analyze", "t1", "h1", parent_evidence_id="root"
            ),
        ],
    )
    assert [e.evidence_id for e in chain.walk()] == ["root", "leaf"]


def test_confidence_at_multiplies_hops():
    chain = ProvenanceChain(
        root_evidence_id="root",
        entries=[
            ProvenanceEntry("root", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0", confidence=0.9),
            ProvenanceEntry(
                "mid",
                EvidenceSource.AGENT_OBSERVATION,
                "agent",
                "analyze",
                "t1",
                "h1",
                parent_evidence_id="root",
                confidence=0.8,
            ),
            ProvenanceEntry(
                "leaf", EvidenceSource.NOTE, "agent", "conclude", "t2", "h2", parent_evidence_id="mid", confidence=0.7
            ),
        ],
    )
    assert chain.confidence_at("leaf") == pytest.approx(0.9 * 0.8 * 0.7)


def test_lineage_root_to_id():
    chain = ProvenanceChain(
        root_evidence_id="root",
        entries=[
            ProvenanceEntry("root", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0"),
            ProvenanceEntry(
                "mid", EvidenceSource.AGENT_OBSERVATION, "agent", "analyze", "t1", "h1", parent_evidence_id="root"
            ),
            ProvenanceEntry("leaf", EvidenceSource.NOTE, "agent", "conclude", "t2", "h2", parent_evidence_id="mid"),
        ],
    )
    assert [e.evidence_id for e in chain.lineage("leaf")] == ["root", "mid", "leaf"]
    assert chain.lineage("unknown") == []


def test_normalize_clips_long_excerpts():
    long = "x" * 2000
    assert len(EvidenceReference.normalize(long)) == 500


def test_normalize_collapses_whitespace():
    assert EvidenceReference.normalize("  a\n\t b  ") == "a b"


def test_tracker_summary_counts_per_source():
    tracker = ProvenanceTracker()
    tracker.register_root("r1", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0")
    tracker.register_root("r2", EvidenceSource.MANUAL, "analyst", "note", "t0", "h0")
    tracker.register_derived("r1", "c1", EvidenceSource.AGENT_OBSERVATION, "agent", "analyze", "t1", "h1")
    summary = tracker.summary()
    assert summary[EvidenceSource.SCANNER.value] == 1
    assert summary[EvidenceSource.MANUAL.value] == 1
    assert summary[EvidenceSource.AGENT_OBSERVATION.value] == 1


def test_tracker_chain_for_and_derived():
    tracker = ProvenanceTracker()
    tracker.register_root("r1", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0")
    tracker.register_derived("r1", "c1", EvidenceSource.AGENT_OBSERVATION, "agent", "analyze", "t1", "h1")
    chain = tracker.chain_for("c1")
    assert chain is not None
    assert chain.root_evidence_id == "r1"
    assert [e.evidence_id for e in chain.walk()] == ["r1", "c1"]


def test_chain_round_trip():
    chain = ProvenanceChain(
        root_evidence_id="root",
        entries=[
            ProvenanceEntry("root", EvidenceSource.SCANNER, "nmap", "scan", "t0", "h0", confidence=0.9),
            ProvenanceEntry(
                "leaf", EvidenceSource.NOTE, "agent", "conclude", "t1", "h1", parent_evidence_id="root", confidence=0.5
            ),
        ],
    )
    restored = ProvenanceChain.from_dict(chain.to_dict())
    assert restored.root_evidence_id == chain.root_evidence_id
    assert [e.evidence_id for e in restored.walk()] == ["root", "leaf"]
    assert restored.entries[1].source is EvidenceSource.NOTE


def test_evidence_level_enum():
    assert EvidenceLevel.RAW.value == "raw"
    assert EvidenceLevel.DERIVED.value == "derived"
    assert EvidenceLevel.SUMMARIZED.value == "summarized"
