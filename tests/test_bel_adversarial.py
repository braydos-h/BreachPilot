"""Adversarial belief tests: model claims are not evidence.

These prove that confidence moves ONLY with registered evidence, that the
store never collapses supporting/contradicting sides, and that a bare
numeric claim on the state is not respected by the deterministic updater.
"""

from tools.intelligence.belief import (
    BeliefState,
    ConfidenceUpdate,
    DeterministicUpdater,
    EvidenceObservation,
    EvidencePolarity,
    HypothesisStatus,
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


def fresh():
    bs = BeliefState(mission_id="m-a")
    bs.add_hypothesis(statement="p", target="10.0.0.5")
    return bs, list(bs.hypotheses)[0]


def test_neutral_or_zero_weight_never_changes_confidence():
    for rule in (
        ConfidenceUpdate.STEP,
        ConfidenceUpdate.MULTIPLICATIVE,
        ConfidenceUpdate.BAYESIAN_BETA,
    ):
        updater = DeterministicUpdater(rule=rule)
        bs, hid = fresh()
        h = bs.get(hid)
        before = h.current_confidence
        updater.apply(h, [obs("n1", EvidencePolarity.NEUTRAL, 0.9)])
        updater.apply(h, [obs("n2", EvidencePolarity.SUPPORTING, 0.0)])
        updater.apply(h, [obs("n3", EvidencePolarity.CONTRADICTING, 0.0)])
        assert h.current_confidence == before


def test_one_hundred_contradictions_stay_clamped():
    for rule in (ConfidenceUpdate.STEP, ConfidenceUpdate.BAYESIAN_BETA):
        updater = DeterministicUpdater(rule=rule)
        bs, hid = fresh()
        h = bs.get(hid)
        for n in range(100):
            updater.apply(h, [obs(f"c{n}", EvidencePolarity.CONTRADICTING, 1.0)])
        assert 0.0 <= h.current_confidence <= 1.0


def test_contradictory_sequence_keeps_both_lists():
    bs, hid = fresh()
    updater = DeterministicUpdater(rule=ConfidenceUpdate.BAYESIAN_BETA)
    h = bs.get(hid)
    updater.apply(
        h,
        [
            obs("s1", EvidencePolarity.SUPPORTING, 0.8),
            obs("c1", EvidencePolarity.CONTRADICTING, 0.8),
            obs("s2", EvidencePolarity.SUPPORTING, 0.5),
        ],
    )
    assert len(h.supporting_evidence) == 2
    assert len(h.contradicting_evidence) == 1


def test_bare_confidence_claim_is_not_evidence():
    bs, hid = fresh()
    h = bs.get(hid)
    h.current_confidence = 0.99
    assert compute_status(h.current_confidence, evidence_count=0) == HypothesisStatus.UNKNOWN
    assert compute_status(h.current_confidence, evidence_count=1, supporting_count=0) != HypothesisStatus.CONFIRMED
    updater = DeterministicUpdater(rule=ConfidenceUpdate.BAYESIAN_BETA)
    assert updater.apply(h, []) == 0.99  # no observations: the updater moves nothing
    updater.apply(h, [obs("n1", EvidencePolarity.NEUTRAL, 1.0)])
    assert h.current_confidence == 0.99  # neutral evidence moves nothing either
    assert compute_status(h.current_confidence, len(h.supporting_evidence), 0, 0) != HypothesisStatus.CONFIRMED


def test_duplicate_evidence_refs_count_once():
    bs, hid = fresh()
    h = bs.get(hid)
    updater = DeterministicUpdater(rule=ConfidenceUpdate.BAYESIAN_BETA)
    updater.apply(h, [obs("dup", EvidencePolarity.SUPPORTING, 0.5) for _ in range(3)])
    assert h.independent_observation_count == 1
    assert len(h.supporting_evidence) == 1
    updater.apply(h, [obs("dup", EvidencePolarity.SUPPORTING, 0.5)])
    assert h.independent_observation_count == 1
