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
