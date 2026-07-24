"""Tests for the runtime-skill cross-mission feedback loop (Tier 2.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from db import DatabaseManager
from tools.experience_store import ExperienceStore
from tools.skill_feedback import (
    record_skill_loaded,
    record_skill_outcome,
    skill_observation_count,
    skill_prior,
)


@pytest.fixture
def skill_db(tmp_path):
    db = DatabaseManager(tmp_path / "skills.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


@pytest.fixture
def store(skill_db):
    return ExperienceStore(skill_db, min_samples=1)


def _write_skill(root: Path, name: str, tags: list[str]) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {name} description.\n"
        "tags:\n" + "".join(f"- {t}\n" for t in tags)
        + "---\n# Skill\n\n## Workflow\nAuthorized use only.",
        encoding="utf-8",
    )


def _registry(tmp_path: Path):
    from tools.skill_registry import load_skill_registry

    _write_skill(tmp_path, "alpha-skill", ["nmap", "reconnaissance", "network-security"])
    _write_skill(tmp_path, "beta-skill", ["api", "web", "owasp"])
    return load_skill_registry([tmp_path], base_dir=tmp_path)


# ── skill_feedback module ────────────────────────────────────────────────


def test_record_skill_loaded_round_trip(store):
    rid = record_skill_loaded(store, "alpha-skill", metadata={"run": 1})
    assert rid is not None
    # A load is a neutral partial -- counts as an observation but the prior
    # stays at 0.5 with a single observation (min_samples=1 -> 1 row is enough,
    # but Beta(1+0.5, 1+0.5)=0.5).
    assert skill_observation_count(store, "alpha-skill") == 1
    assert skill_prior(store, "alpha-skill") == pytest.approx(0.5)


def test_posterior_updates_on_success_failure(store):
    # Two successes -> prior rises above neutral.
    record_skill_outcome(store, "alpha-skill", success=True)
    record_skill_outcome(store, "alpha-skill", success=True)
    assert skill_prior(store, "alpha-skill") > 0.5

    # Two failures on a different skill -> prior falls below neutral.
    record_skill_outcome(store, "beta-skill", success=False)
    record_skill_outcome(store, "beta-skill", success=False)
    assert skill_prior(store, "beta-skill") < 0.5


def test_skill_feedback_noop_without_store():
    # All accessors must degrade to safe defaults with no store.
    assert record_skill_loaded(None, "x") is None
    assert record_skill_outcome(None, "x", success=True) is None
    assert skill_prior(None, "x") == 0.5
    assert skill_observation_count(None, "x") == 0


def test_skill_feedback_never_raises_on_bad_store():
    class _Broken:
        def record_outcome(self, *a, **k):
            raise RuntimeError("db down")

        def get_confidence(self, *a, **k):
            raise RuntimeError("db down")

        def observation_count(self, *a, **k):
            raise RuntimeError("db down")

    broken = _Broken()
    assert record_skill_loaded(broken, "x") is None
    assert record_skill_outcome(broken, "x", success=True) is None
    assert skill_prior(broken, "x") == 0.5
    assert skill_observation_count(broken, "x") == 0


# ── selector boost integration ───────────────────────────────────────────


def _select(store, registry, *, feedback_min=3, feedback_weight=8, services=None):
    from tools.skill_selector import select_runtime_skills

    return select_runtime_skills(
        registry,
        config={"skills": {
            "enabled": True,
            "default_enabled": [],
            "max_active_skills": 6,
            "min_contextual_skills": 0,
            "default_skill_weight": 5,
            "context_skill_weight": 10,
            "feedback_enabled": True,
            "feedback_skill_weight": feedback_weight,
            "feedback_min_observations": feedback_min,
        }},
        goal_name="recon",
        goal_description="recon",
        mode="recon",
        services=services or [],
        experience_store=store,
    )


def test_selector_boost_applied_after_min_observations(tmp_path, store):
    registry = _registry(tmp_path)
    # Give alpha-skill a strong positive track record (5 successes).
    for _ in range(5):
        record_skill_outcome(store, "alpha-skill", success=True)
    assert skill_observation_count(store, "alpha-skill") >= 3

    sel = _select(store, registry, feedback_min=3, feedback_weight=8)
    alpha = next(a for a in sel.activations if a.name == "alpha-skill")
    assert "feedback:prior" in alpha.signals


def test_selector_boost_actually_raises_score(tmp_path, store):
    """The boost is a real score bump, not just a signal tag."""
    registry = _registry(tmp_path)
    for _ in range(5):
        record_skill_outcome(store, "alpha-skill", success=True)

    with_boost = _select(store, registry, feedback_min=3, feedback_weight=8)
    no_boost = _select(store, registry, feedback_min=99, feedback_weight=8)
    a_with = next(a for a in with_boost.activations if a.name == "alpha-skill")
    a_without = next(a for a in no_boost.activations if a.name == "alpha-skill")
    assert a_with.score > a_without.score


def test_selector_no_boost_below_min_observations(tmp_path, store):
    registry = _registry(tmp_path)
    # Only 2 observations -- below the default min of 3.
    record_skill_outcome(store, "alpha-skill", success=True)
    record_skill_outcome(store, "alpha-skill", success=True)

    sel = _select(store, registry, feedback_min=3, feedback_weight=8)
    alpha = next(a for a in sel.activations if a.name == "alpha-skill")
    assert "feedback:prior" not in alpha.signals


def test_negative_outcome_does_not_exclude_skill(tmp_path, store):
    """Advisory invariant: a poor track record must never hide a skill.

    A skill that the context matches (via service tags) must still be
    selectable even when its feedback posterior is well below neutral -- the
    feedback term is boost-only, never a penalty. beta-skill matches the
    'api' service context regardless of its poor history.
    """
    registry = _registry(tmp_path)
    for _ in range(5):
        record_skill_outcome(store, "beta-skill", success=False)
    assert skill_prior(store, "beta-skill") < 0.5

    sel = _select(
        store, registry, feedback_min=3, feedback_weight=8,
        services=["https 443 graphql api"],
    )
    names = {a.name for a in sel.activations}
    assert "beta-skill" in names  # still selectable -- context match, no penalty
    beta = next(a for a in sel.activations if a.name == "beta-skill")
    assert "feedback:prior" not in beta.signals  # no boost (prior < 0.5), but no penalty


def test_selector_feedback_disabled_skips_boost(tmp_path, store):
    from tools.skill_selector import select_runtime_skills

    registry = _registry(tmp_path)
    for _ in range(5):
        record_skill_outcome(store, "alpha-skill", success=True)

    sel = select_runtime_skills(
        registry,
        config={"skills": {
            "enabled": True,
            "default_enabled": [],
            "max_active_skills": 6,
            "min_contextual_skills": 0,
            "default_skill_weight": 5,
            "context_skill_weight": 10,
            "feedback_enabled": False,
        }},
        goal_name="recon",
        goal_description="recon",
        mode="recon",
        experience_store=store,
    )
    alpha = next(a for a in sel.activations if a.name == "alpha-skill")
    assert "feedback:prior" not in alpha.signals


def test_observation_count_method_on_store(skill_db):
    """ExperienceStore.observation_count is the raw row count the feedback
    loop gates on (separate from the Beta posterior)."""
    store = ExperienceStore(skill_db, min_samples=1)
    assert store.observation_count("skill:alpha", "skill") == 0
    record_skill_loaded(store, "alpha")
    record_skill_outcome(store, "alpha", success=True)
    assert store.observation_count("skill:alpha", "skill") == 2