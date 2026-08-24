"""Phase 1.1 — ``ExperienceStore.record_outcome`` action-suffix conditioning.

Verifies that an optional ``action_suffix`` (e.g. ``"shell"``, ``"creds"``,
``"partial"``) is appended to ``action_type`` for storage so the Bayesian
posterior conditions on the distinct outcome class, AND that existing callers
passing a bare ``action_type`` remain byte-identical (backward compatibility).
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id, _now_iso
from tools.experience_store import ExperienceStore


@pytest.fixture
def exp_db(tmp_path):
    db = DatabaseManager(tmp_path / "research.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    yield db


def _insert_lessons_row(conn, *, target_signature, action_type, outcome):
    conn.execute(
        """INSERT INTO lessons(id, pattern_hash, target_signature, action_type,
           outcome, confidence, embedding_json, metadata_json, created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            _new_id("EXP"),
            f"{target_signature}:{action_type}",
            target_signature,
            action_type,
            outcome,
            0.5,
            "[]",
            "[]",
            _now_iso(),
        ),
    )


# ── Backward compatibility ──────────────────────────────────────────────────


def test_record_outcome_without_suffix_unchanged(exp_db):
    """No ``action_suffix`` -> stored action_type is the bare action_type."""
    store = ExperienceStore(exp_db, min_samples=1)
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce:generate", "success")
    with exp_db.connection() as conn:
        row = conn.execute(
            "SELECT action_type, pattern_hash FROM lessons "
            "WHERE target_signature = ? AND outcome = 'success'",
            ("ssh:8.2:linux",),
        ).fetchone()
    assert row["action_type"] == "SSHBruteForce:generate"
    assert row["pattern_hash"] == "ssh:8.2:linux:SSHBruteForce:generate"


def test_record_outcome_empty_suffix_unchanged(exp_db):
    """Empty ``action_suffix`` is the same as no suffix (falsy guard)."""
    store = ExperienceStore(exp_db, min_samples=1)
    store.record_outcome("t", "act", "success", action_suffix="")
    with exp_db.connection() as conn:
        row = conn.execute(
            "SELECT action_type FROM lessons WHERE target_signature = 't'"
        ).fetchone()
    assert row["action_type"] == "act"


# ── Suffix conditioning ─────────────────────────────────────────────────────


def test_record_outcome_with_suffix_appends_to_action_type(exp_db):
    store = ExperienceStore(exp_db, min_samples=1)
    store.record_outcome("t", "act", "success", action_suffix="shell")
    with exp_db.connection() as conn:
        row = conn.execute(
            "SELECT action_type, pattern_hash FROM lessons WHERE target_signature = 't'"
        ).fetchone()
    assert row["action_type"] == "act:shell"
    assert row["pattern_hash"] == "t:act:shell"


def test_suffixed_and_bare_action_types_condition_distinctly(exp_db):
    """The Bayesian posterior for ``act:shell`` must be independent of ``act``:
    a shell success must NOT promote the bare ``act`` action, and vice versa."""
    store = ExperienceStore(exp_db, min_samples=1)

    # Record two shell successes (suffixed) and one bare failure.
    store.record_outcome("t", "act", "success", action_suffix="shell")
    store.record_outcome("t", "act", "success", action_suffix="shell")
    store.record_outcome("t", "act", "failure")  # bare, no suffix

    # Suffixed action: two successes -> Beta(3,1) mean = 0.75.
    assert store.get_confidence("t", "act:shell") == pytest.approx(0.75, abs=0.01)
    # Bare action: one failure -> Beta(1,2) mean = 1/3.
    assert store.get_confidence("t", "act") == pytest.approx(1.0 / 3.0, abs=0.01)


def test_distinct_suffixes_condition_distinctly(exp_db):
    """shell vs creds vs partial suffixes are three separate Beta buckets."""
    store = ExperienceStore(exp_db, min_samples=1)
    # shell: 2 successes
    store.record_outcome("t", "m", "success", action_suffix="shell")
    store.record_outcome("t", "m", "success", action_suffix="shell")
    # creds: 1 failure
    store.record_outcome("t", "m", "failure", action_suffix="creds")
    # partial: 1 partial
    store.record_outcome("t", "m", "partial", action_suffix="partial")

    assert store.get_confidence("t", "m:shell") == pytest.approx(0.75, abs=0.01)
    assert store.get_confidence("t", "m:creds") == pytest.approx(1.0 / 3.0, abs=0.01)
    # partial counts 0.5 toward alpha and beta: Beta(1+0.5, 1+0.5) mean = 0.5
    assert store.get_confidence("t", "m:partial") == pytest.approx(0.5, abs=0.01)


def test_get_all_confidences_sees_suffixed_actions_as_distinct(exp_db):
    """``get_all_confidences`` aggregates by ``action_type`` column, so suffixed
    and bare actions show up as independent keys."""
    store = ExperienceStore(exp_db, min_samples=1)
    store.record_outcome("t", "m", "success", action_suffix="shell")
    store.record_outcome("t", "m", "failure", action_suffix="creds")
    all_conf = store.get_all_confidences("t")
    assert "m:shell" in all_conf
    assert "m:creds" in all_conf
    assert "m" not in all_conf  # bare never recorded


def test_observation_count_distinguishes_suffixed_actions(exp_db):
    store = ExperienceStore(exp_db, min_samples=1)
    store.record_outcome("t", "m", "success", action_suffix="shell")
    store.record_outcome("t", "m", "success", action_suffix="shell")
    store.record_outcome("t", "m", "failure", action_suffix="creds")
    assert store.observation_count("t", "m:shell") == 2
    assert store.observation_count("t", "m:creds") == 1
    assert store.observation_count("t", "m") == 0
