"""Tests for safety reviewer."""

import pytest
from tools.safety_reviewer import (
    build_safety_review_prompt,
    parse_safety_review,
    SafetyReview,
)


def test_build_prompt():
    prompt = build_safety_review_prompt("some results", "10.0.0.1", "backdoor")
    assert "10.0.0.1" in prompt
    assert "backdoor" in prompt
    assert "some results" in prompt


def test_parse_valid_json():
    text = '{"safe_to_proceed": true, "reasoning": "Looks like a lab", "concerns": [], "recommended_next_steps": ["Proceed"]}'
    review = parse_safety_review(text)
    assert review.safe_to_proceed is True
    assert review.reasoning == "Looks like a lab"


def test_parse_markdown_fenced():
    text = '```json\n{"safe_to_proceed": false, "reasoning": "No"}\n```'
    review = parse_safety_review(text)
    assert review.safe_to_proceed is False


def test_parse_invalid_defaults_safe():
    review = parse_safety_review("not json")
    assert review.safe_to_proceed is False
    assert "Could not parse" in review.reasoning


def test_parse_string_false_does_not_proceed():
    """LLMs often emit "false" as a string instead of a JSON boolean.
    bool("false") would be True (non-empty string) -- a fail-open bug.
    The parser must coerce strings explicitly so "false" blocks."""
    text = '{"safe_to_proceed": "false", "reasoning": "Looks risky"}'
    review = parse_safety_review(text)
    assert review.safe_to_proceed is False
    assert review.reasoning == "Looks risky"


def test_parse_string_true_proceeds():
    """Symmetric: string "true" should proceed."""
    text = '{"safe_to_proceed": "true", "reasoning": "Lab system"}'
    review = parse_safety_review(text)
    assert review.safe_to_proceed is True


def test_prompt_marks_truncation():
    """When recon results exceed 4000 chars, the prompt must signal truncation."""
    long_results = "x" * 5000
    prompt = build_safety_review_prompt(long_results, "10.0.0.1", "recon")
    assert "[truncated]" in prompt


def test_prompt_no_truncation_marker_when_short():
    prompt = build_safety_review_prompt("short", "10.0.0.1", "recon")
    assert "[truncated]" not in prompt
