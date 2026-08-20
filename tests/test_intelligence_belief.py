"""Tests for tools/intelligence/belief: evidence-driven confidence modelling."""

from tools.intelligence.belief import (
    CONFIRMED_THRESHOLD,
    BeliefState,
    BeliefStore,
    ConfidenceCalculator,
    ConfidenceUpdate,
    DeterministicUpdater,
    EvidenceObservation,
    EvidencePolarity,
    HypothesisStatus,
    NonModelConfidenceTag,
    compute_status,
)


def obs(
    ref: str,
    polarity: EvidencePolarity,
    weight: float = 0.5,
    independent: bool = True,
) -> EvidenceObservation:
    return EvidenceObservation(
        evidence_ref=ref,
        polarity=polarity,
        weight=weight,
        source="test",
        independent=independent,
    )


def new_state() -> BeliefState:
    bs = BeliefState(mission_id="m-1")
    bs.add_hypothesis(statement="service is vulnerable", target="10.0.0.5")
    return bs


def test_initial_confidence_is_half():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    assert bs.get(hid).current_confidence == 0.5


def test_supporting_observation_raises_confidence():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    bs.register_evidence(hid, obs("e1", EvidencePolarity.SUPPORTING, 0.4))
    assert bs.get(hid).current_confidence > 0.5


def test_contradicting_observation_lowers_confidence():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    bs.register_evidence(hid, obs("e1", EvidencePolarity.CONTRADICTING, 0.4))
    assert bs.get(hid).current_confidence < 0.5


def test_neutral_observation_does_not_change_confidence():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    before = bs.get(hid).current_confidence
    bs.register_evidence(hid, obs("e1", EvidencePolarity.NEUTRAL, 0.9))
    assert bs.get(hid).current_confidence == before


def fresh_hypothesis():
    bs = new_state()
    return bs.get(list(bs.hypotheses)[0])


def test_dependent_evidence_changes_less_than_independent():
    updater = DeterministicUpdater(rule=ConfidenceUpdate.STEP)
    h1 = fresh_hypothesis()
    h2 = fresh_hypothesis()
    indep = [obs(f"i{n}", EvidencePolarity.SUPPORTING, 0.5, independent=True) for n in range(2)]
    dep = [obs(f"d{n}", EvidencePolarity.SUPPORTING, 0.5, independent=False) for n in range(2)]
    updater.apply(h1, indep)
    updater.apply(h2, dep)
    assert h1.current_confidence > h2.current_confidence


def test_deterministic_ordering_same_inputs_same_output():
    updater = DeterministicUpdater(rule=ConfidenceUpdate.BAYESIAN_BETA)
    batch = [
        obs("a", EvidencePolarity.SUPPORTING, 0.4),
        obs("b", EvidencePolarity.CONTRADICTING, 0.2),
        obs("c", EvidencePolarity.SUPPORTING, 0.6),
    ]
    h1 = fresh_hypothesis()
    h2 = fresh_hypothesis()
    assert updater.apply(h1, batch) == updater.apply(h2, batch)


def test_bayesian_beta_monotonic_non_decreasing_on_support():
    updater = DeterministicUpdater(rule=ConfidenceUpdate.BAYESIAN_BETA)
    h = fresh_hypothesis()
    last = h.current_confidence
    for n in range(50):
        updater.apply(h, [obs(f"s{n}", EvidencePolarity.SUPPORTING, 0.9)])
        assert 0.0 <= h.current_confidence <= 1.0
        assert h.current_confidence >= last - 1e-12
        last = h.current_confidence


def test_compute_status_maps():
    assert compute_status(0.8, evidence_count=3, supporting_count=2) == HypothesisStatus.CONFIRMED
    assert compute_status(0.1, evidence_count=2, contradicting_count=1) == HypothesisStatus.REFUTED
    assert compute_status(0.3, evidence_count=1, supporting_count=1) == HypothesisStatus.SUSPECTED
    assert compute_status(0.6, evidence_count=1, supporting_count=1) == HypothesisStatus.LIKELY
    assert compute_status(0.2, evidence_count=0) == HypothesisStatus.UNKNOWN


def test_compute_status_requires_evidence_for_confirmed():
    assert compute_status(0.9, evidence_count=0) == HypothesisStatus.UNKNOWN
    assert compute_status(0.9, evidence_count=1, supporting_count=0) != HypothesisStatus.CONFIRMED


def test_non_model_confidence_tags_exist():
    for tag in (
        NonModelConfidenceTag.TOOL_EXECUTION_SUCCESS,
        NonModelConfidenceTag.OBSERVATION_CONFIDENCE,
        NonModelConfidenceTag.VULNERABILITY_LIKELIHOOD,
        NonModelConfidenceTag.PATH_VIABILITY,
        NonModelConfidenceTag.FINDING_CONFIRMATION,
    ):
        assert tag.value


def test_next_discriminating_check_prefers_unattempted():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    h = bs.get(hid)
    h.candidate_checks = ["check-b", "check-a"]
    assert bs.next_discriminating_check(hid, ["check-a", "check-b"]) == "check-b"
    h.check_fingerprints_attempted.add("check-b")
    assert bs.next_discriminating_check(hid, ["check-a", "check-b"]) == "check-a"
    assert bs.next_discriminating_check(hid, []) is None


def test_snapshot_load_round_trip():
    bs = new_state()
    hid = list(bs.hypotheses)[0]
    bs.register_evidence(hid, obs("e1", EvidencePolarity.SUPPORTING, 0.6))
    bs.get(hid).candidate_checks = ["nmap -p 80"]
    restored = BeliefState.load(bs.snapshot())
    orig = bs.get(hid)
    new = restored.get(hid)
    assert new.statement == orig.statement
    assert new.current_confidence == orig.current_confidence
    assert len(new.supporting_evidence) == 1
    assert new.supporting_evidence[0].evidence_ref == "e1"
    assert new.check_fingerprints_attempted == orig.check_fingerprints_attempted


def test_top_unresolved_orders_by_uncertainty():
    bs = new_state()
    ids = [bs.add_hypothesis(statement=f"h{i}", target="10.0.0.5") for i in range(3)]
    bs.get(ids[0]).current_confidence = 0.5
    bs.get(ids[1]).current_confidence = 0.9
    bs.get(ids[2]).current_confidence = 0.7
    top = bs.top_unresolved(2)
    assert [h.hypothesis_id for h in top] == [ids[0], ids[2]]


def test_belief_store_basics():
    store = BeliefStore()
    bs = new_state()
    store.upsert(bs)
    assert len(store) == 1
    assert "m-1" in store
    assert store.keys() == ["m-1"]
    assert store.get("m-1") is bs
    assert store.find_by_statement("service is vulnerable") == [bs]
    assert store.list_all() == [bs]
    hid = list(bs.hypotheses)[0]
    bs.get(hid).status = HypothesisStatus.CONFIRMED
    assert store.list_by_status(HypothesisStatus.CONFIRMED) == [bs]
    store.delete("m-1")
    assert len(store) == 0
