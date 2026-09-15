"""TODO 023: Host→Service→Hypothesis→Evidence→Finding chain renders."""

from __future__ import annotations

from target_graph import EDGE_TYPES, NODE_TYPES


def test_canonical_graph_types_exist():
    for node in ("host", "service", "hypothesis", "evidence", "finding", "credential", "access", "pivot"):
        assert node in NODE_TYPES, f"missing node {node}"
    for edge in ("hypothesizes", "produced_evidence", "indicates", "uses_credential", "grants_access", "pivots_to"):
        assert edge in EDGE_TYPES, f"missing edge {edge}"


def test_sample_chain_links():
    # Host → Service → Hypothesis → Evidence → Finding is expressible.
    chain = [
        ("host", "exposes", "service"),
        ("service", "hypothesizes", "hypothesis"),
        ("hypothesis", "produced_evidence", "evidence"),
        ("evidence", "indicates", "finding"),
        ("credential", "grants_access", "access"),
        ("pivot", "pivots_to", "host"),
    ]
    for src, edge, dst in chain:
        assert src in NODE_TYPES and dst in NODE_TYPES and edge in EDGE_TYPES
