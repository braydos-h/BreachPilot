"""Adversarial proof that malformed model output is never silently accepted."""

from tools.intelligence.schemas import (
    OutcomeAssessment,
    OutcomeAssessmentSchema,
    PlannerProposal,
    PlannerProposalSchema,
    SafeSchemaLoader,
    dump_telemetry,
    extract_json_block,
    parse_json_block,
)


def test_prose_only_not_valid_default_used():
    loader = SafeSchemaLoader(
        PlannerProposalSchema(),
        lambda: PlannerProposal(hypothesis_id="d", statement="default", target=""),
        "PlannerProposal",
    )
    obj, result = loader.load("Sure, here's my analysis of the attack surface: nothing structured here.")
    assert obj.statement == "default"
    assert result.valid is False
    assert dump_telemetry()[-1]["ok"] is False


def test_list_where_dict_expected_is_invalid():
    loader = SafeSchemaLoader(
        OutcomeAssessmentSchema(),
        lambda: OutcomeAssessment(verdict="unknown"),
        "OutcomeAssessment",
    )
    obj, result = loader.load('["confirmed", "refuted"]')
    assert obj.verdict == "unknown"
    assert result.valid is False
    assert "object" in result.errors[0].lower()


def test_confirmed_verdict_without_evidence_is_valid_by_schema():
    raw = '{"verdict": "confirmed"}'
    assert parse_json_block(raw) == {"verdict": "confirmed"}
    schema = OutcomeAssessmentSchema()
    parsed = parse_json_block(raw)
    assert isinstance(parsed, dict)
    result = schema.validate(parsed)
    assert result.valid is True
    outcome = schema.coerce(parsed)
    assert outcome.verdict == "confirmed"


def test_missing_required_list_fields_repaired_with_error():
    schema = OutcomeAssessmentSchema()
    raw = {"verdict": "confirmed", "criteria_satisfied": "not-a-list"}
    result = schema.validate(raw)
    assert not result.valid
    repaired = schema.repair(dict(raw), list(result.errors))
    assert repaired["criteria_satisfied"] == []
    assert any("criteria_satisfied" in e for e in result.errors)


def test_unknown_keys_tolerated_missing_required_flagged():
    schema = PlannerProposalSchema()
    raw = {"extra_key": "ignored", "confidence": 0.5}
    result = schema.validate(raw)
    assert not result.valid
    assert any("statement" in e for e in result.errors)
    repaired = schema.repair(dict(raw), list(result.errors))
    assert schema.validate(repaired).valid


def test_oversized_statement_rejected():
    schema = PlannerProposalSchema()
    raw = {"statement": "x" * 10000, "target": "t"}
    result = schema.validate(raw)
    assert not result.valid
    assert any("500" in e for e in result.errors)
    repaired = schema.repair(dict(raw), list(result.errors))
    assert schema.validate(repaired).valid is False


def test_repair_once_missing_confidence_succeeds():
    loader = SafeSchemaLoader(PlannerProposalSchema(), lambda: None, "PlannerProposal")
    obj, result = loader.load('{"statement": "ok", "target": "t"}')
    assert isinstance(obj, PlannerProposal)
    assert result.valid is True
    assert result.repaired is True
    assert dump_telemetry()[-1]["ok"] is True


def test_repair_once_then_fallback_default():
    loader = SafeSchemaLoader(
        PlannerProposalSchema(),
        lambda: PlannerProposal(hypothesis_id="0", statement="fallback", target="x"),
        "PlannerProposal",
    )
    obj, result = loader.load('{"statement": "y" * 900, "target": "t"}')
    assert isinstance(obj, PlannerProposal)
    assert obj.statement == "fallback"
    assert result.valid is False
    assert dump_telemetry()[-1]["ok"] is False


def test_extract_json_handles_fence_and_wrapper():
    assert parse_json_block('```json\n{"a": [1, 2, 3]}\n```') == {"a": [1, 2, 3]}
    assert parse_json_block("Here is the result: [1, 2, 3]") == [1, 2, 3]
    assert extract_json_block("just prose") is None
