"""Tests for tools.intelligence.schemas: validation, repair, fallback, telemetry."""

import os

from tools.intelligence.schemas import (
    CandidatePath,
    CandidatePathSchema,
    CriticReviewSchema,
    HypothesisUpdateSchema,
    OutcomeAssessment,
    OutcomeAssessmentSchema,
    PlannerProposal,
    PlannerProposalSchema,
    SafeSchemaLoader,
    StrategyReviewSchema,
    dump_telemetry,
    extract_json_block,
    log_validation,
    parse_json_block,
)


def test_planner_proposal_valid():
    raw = {
        "hypothesis_id": "h1",
        "statement": "Attacker pivoted via SMB",
        "target": "10.0.0.5",
        "entity": "webserver",
        "technique_category": "lateral-movement",
        "rationale": "observed 445 traffic",
        "confidence": 0.8,
        "expected_information_gain": 0.7,
        "suggested_checks": ["check 1", "check 2"],
    }
    result = PlannerProposalSchema().validate(raw)
    assert result.valid
    proposal = PlannerProposalSchema().coerce(raw)
    assert isinstance(proposal, PlannerProposal)
    assert proposal.hypothesis_id == "h1"
    assert proposal.statement == raw["statement"]
    assert proposal.target == "10.0.0.5"
    assert proposal.confidence == 0.8
    assert proposal.suggested_checks == ["check 1", "check 2"]


def test_planner_proposal_empty_statement_repaired():
    schema = PlannerProposalSchema()
    raw = {"statement": "   ", "target": "10.0.0.5"}
    result = schema.validate(raw)
    assert not result.valid
    assert any("empty" in e for e in result.errors)
    repaired = schema.repair(dict(raw), list(result.errors))
    repaired_result = schema.validate(repaired)
    assert repaired_result.valid
    proposal = schema.coerce(repaired)
    assert proposal.statement == "untitled hypothesis"


def test_planner_proposal_confidence_clamped():
    schema = PlannerProposalSchema()
    raw = {"statement": "ok", "target": "t", "confidence": 2.0}
    assert not schema.validate(raw).valid
    proposal = schema.coerce(schema.repair(dict(raw), []))
    assert proposal.confidence == 1.0


def test_candidate_path_missing_steps_defaults_and_invalid():
    schema = CandidatePathSchema()
    raw = {"score": 0.4}
    result = schema.validate(raw)
    assert not result.valid
    assert any("steps" in e for e in result.errors)
    repaired = schema.repair(dict(raw), list(result.errors))
    assert repaired["steps"] == []
    repaired_result = schema.validate(repaired)
    assert not repaired_result.valid
    path = schema.coerce(repaired)
    assert isinstance(path, CandidatePath)
    assert path.steps == []
    assert path.score == 0.4


def test_candidate_path_negative_score_repaired():
    schema = CandidatePathSchema()
    raw = {"steps": ["a"], "score": -3}
    assert not schema.validate(raw).valid
    repaired = schema.repair(dict(raw), [])
    assert repaired["score"] == 0.0
    assert schema.validate(repaired).valid


def test_outcome_verdict_confirmed_empty_criteria_valid():
    schema = OutcomeAssessmentSchema()
    raw = {"verdict": "confirmed", "criteria_satisfied": []}
    result = schema.validate(raw)
    assert result.valid
    outcome = schema.coerce(raw)
    assert isinstance(outcome, OutcomeAssessment)
    assert outcome.verdict == "confirmed"


def test_critic_invalid_decision_repaired_to_modify():
    schema = CriticReviewSchema()
    raw = {"decision": "approve2", "objections": []}
    result = schema.validate(raw)
    assert not result.valid
    repaired = schema.repair(dict(raw), list(result.errors))
    assert repaired["decision"] == "modify"
    assert schema.validate(repaired).valid


def test_hypothesis_update_bogus_status_repaired():
    schema = HypothesisUpdateSchema()
    raw = {"statement": "s", "target": "t", "status": "bogus"}
    result = schema.validate(raw)
    assert not result.valid
    repaired = schema.repair(dict(raw), list(result.errors))
    assert repaired["status"] == "open"
    assert schema.validate(repaired).valid


def test_strategy_missing_lists_repaired():
    schema = StrategyReviewSchema()
    raw = {"overall_assessment": "  messy  "}
    result = schema.validate(raw)
    assert not result.valid
    repaired = schema.repair(dict(raw), list(result.errors))
    assert repaired["top_unresolved"] == []
    assert repaired["overall_assessment"] == "messy"


def test_extract_json_block_fence():
    text = '```json\n{"a": 1, "nested": {"b": [1, 2]}}\n```'
    block = extract_json_block(text)
    assert block is not None
    assert parse_json_block(text) == {"a": 1, "nested": {"b": [1, 2]}}


def test_extract_json_block_chat_wrapper():
    text = 'Here is the result: {"decision": "approve", "confidence": 0.8} thanks!'
    assert parse_json_block(text) == {"decision": "approve", "confidence": 0.8}


def test_extract_json_block_prose_only():
    assert extract_json_block("No JSON here, just words and numbers 42.") is None
    assert parse_json_block("Still nothing.") is None


def test_extract_json_block_list():
    assert parse_json_block('steps: ["a", "b"]') == ["a", "b"]


def test_telemetry_appended_and_dump():
    log_validation("TestSchema", True, [], source="test")
    assert dump_telemetry()
    assert dump_telemetry()[-1]["schema"] == "TestSchema"
    assert dump_telemetry()[-1]["ok"] is True


def test_log_validation_writes_jsonl(tmp_path):
    path = os.path.join(str(tmp_path), "telemetry.jsonl")
    log_validation("TestSchema", False, ["boom"], source="test", path=path)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    assert len(lines) == 1
    assert "boom" in lines[0]


def test_safe_loader_unparseable_falls_back_and_logs():
    schema = PlannerProposalSchema()
    loader = SafeSchemaLoader(
        schema, lambda: PlannerProposal(hypothesis_id="d", statement="default", target=""), "PlannerProposal"
    )
    before = len(dump_telemetry())
    obj, result = loader.load("this is prose without any json")
    assert result.valid is False
    assert result.errors == ["no JSON block found"]
    assert isinstance(obj, PlannerProposal)
    assert obj.statement == "default"
    assert len(dump_telemetry()) == before + 1
    assert dump_telemetry()[-1]["ok"] is False
    assert dump_telemetry()[-1]["schema"] == "PlannerProposal"


def test_safe_loader_broken_json():
    loader = SafeSchemaLoader(PlannerProposalSchema(), lambda: None, "PlannerProposal")
    obj, result = loader.load('{"statement": "oops, unterminated')
    assert obj is None
    assert result.valid is False
    assert result.errors == ["unparseable"]
    assert dump_telemetry()[-1]["errors"] == ["unparseable"]


def test_safe_loader_valid_roundtrip():
    loader = SafeSchemaLoader(PlannerProposalSchema(), lambda: None, "PlannerProposal")
    obj, result = loader.load('{"statement": "hyp", "target": "10.0.0.1", "confidence": 0.8}')
    assert isinstance(obj, PlannerProposal)
    assert result.valid is True
    assert obj.statement == "hyp"
    assert obj.confidence == 0.8
    assert dump_telemetry()[-1]["ok"] is True


def test_safe_loader_one_repair_round_then_fallback():
    loader = SafeSchemaLoader(PlannerProposalSchema(), lambda: None, "PlannerProposal")
    obj, result = loader.load('{"statement": "ok", "target": "t", "confidence": 0.5}')
    assert isinstance(obj, PlannerProposal)
    assert result.valid is True
    assert result.repaired is False

    loader2 = SafeSchemaLoader(
        PlannerProposalSchema(),
        lambda: PlannerProposal(hypothesis_id="0", statement="fallback", target="x"),
        "PlannerProposal",
    )
    obj2, result2 = loader2.load('{"statement": "' + ("x" * 1000) + '", "target": "t"}')
    assert result2.valid is False
    assert isinstance(obj2, PlannerProposal)
    assert obj2.statement == "fallback"
    assert dump_telemetry()[-1]["ok"] is False


def test_safe_loader_repair_once_success():
    loader = SafeSchemaLoader(PlannerProposalSchema(), lambda: None, "PlannerProposal")
    obj, result = loader.load('{"target": "10.0.0.9"}')
    assert isinstance(obj, PlannerProposal)
    assert obj.statement == "untitled hypothesis"
    assert result.valid is True
    assert result.repaired is True
    assert any("repaired" in e for e in result.errors)
