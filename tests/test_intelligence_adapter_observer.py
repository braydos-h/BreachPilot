"""C4: ObserverAdapter wiring tests — evidence pipeline, graph updates, confidence."""

from __future__ import annotations

from observer import Observation
from tools.intelligence.adapters.observer_adapter import ObserverAdapter
from tools.intelligence.belief.state import EvidencePolarity

# The polarity tokens outcome_judge._explicit_evidence_scores matches
# (outcome_judge.py:804-807).
_SUPPORT_TOKENS = {"supports", "support", "confirmed", "confirm", "positive"}


def _obs_with_facts() -> Observation:
    obs = Observation(target="10.0.0.5", evidence_refs=["E-1"])
    obs.facts = ["Port 22 open", "Detected OS: Linux", "Server header: nginx"]
    obs.new_technologies = ["nginx"]
    obs.new_endpoints = ["10.0.0.5:22/tcp"]
    return obs


def test_infer_confidence_three_facts():
    obs = Observation(target="10.0.0.5")
    obs.facts = ["f1", "f2", "f3"]
    adapter = ObserverAdapter()
    assert adapter.infer_confidence(obs) == 0.6
    assert obs.confidence == 0.6


def test_infer_confidence_caps_at_0_9():
    obs = Observation(target="10.0.0.5")
    obs.facts = [f"fact {i}" for i in range(10)]
    obs.evidence_refs = ["E-1"]
    assert ObserverAdapter().infer_confidence(obs) == 0.9
    assert obs.confidence == 0.9


def test_populate_hypothesis_evidence_matches_outcome_judge_schema():
    obs = _obs_with_facts()
    entries = ObserverAdapter().populate_hypothesis_evidence(obs)
    assert len(obs.hypothesis_evidence) > 0
    assert all(e.polarity is EvidencePolarity.SUPPORTING for e in entries)
    assert entries[0].evidence_ref == "obs:10.0.0.5:0"
    for entry in obs.hypothesis_evidence:
        # The exact keys outcome_judge._explicit_evidence_scores reads
        assert "polarity" in entry and "confidence" in entry
        assert entry["polarity"] in _SUPPORT_TOKENS
        assert 0.0 <= entry["confidence"] <= 1.0


def test_populate_graph_updates_emits_exposes_and_runs():
    obs = _obs_with_facts()
    updates = ObserverAdapter().populate_graph_updates(obs, node_map={})
    relations = {(u["type"], u["relation"], u["edge_to"]) for u in updates}
    assert ("endpoint", "exposes", "10.0.0.5") in relations
    assert ("technology", "runs", "10.0.0.5") in relations
    assert all(u["edge_to"] == "10.0.0.5" for u in updates)


def test_populate_graph_updates_uses_node_map():
    obs = Observation(target="10.0.0.5")
    obs.new_endpoints = ["10.0.0.5:22/tcp"]
    updates = ObserverAdapter().populate_graph_updates(obs, node_map={"10.0.0.5:22/tcp": "GN-1"})
    assert updates[0]["node"] == "GN-1"


def test_classify_dead_end():
    assert ObserverAdapter().classify_dead_end("connection refused on port 80") is True
    assert ObserverAdapter().classify_dead_end("nmap done: 1 IP address scanned") is False
