"""Tests for semantic memory and experience store."""

from __future__ import annotations

import json

import pytest

from db import DatabaseManager, _now_iso
from tools.experience_store import ExperienceStore
from tools.semantic_memory import SemanticMemoryManager


@pytest.fixture
def temp_db(tmp_path):
    # ponytail: previously a hardcoded test_workspace_semantic/ path that
    # persisted across runs and accumulated stale rows, polluting later
    # tests (UNIQUE-constraint collisions, inflated confidence scores).
    # tmp_path is pytest-provided: unique per test, auto-cleaned.
    db_path = tmp_path / "research.db"
    db = DatabaseManager(db_path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    yield db


# ── SemanticMemoryManager Tests ───────────────────────────────────────────


def test_store_and_retrieve_embedding(temp_db):
    mgr = SemanticMemoryManager(temp_db, ollama_host="http://localhost:11434")
    # Mock embedding generation to avoid needing Ollama
    mgr._generate_embedding = lambda text: [0.1, 0.2, 0.3] if "test" in text else None

    eid = mgr.store_embedding("memories", "MEM-001", "test fact", mission_id="M-001")
    assert eid is not None
    assert eid.startswith("EMB-")

    similar = mgr.find_similar("test query", source_table="memories", top_k=5, mission_id="M-001")
    assert len(similar) >= 1
    assert similar[0]["source_id"] == "MEM-001"
    assert similar[0]["similarity"] > 0.99  # identical vectors


def test_find_similar_lessons(temp_db):
    mgr = SemanticMemoryManager(temp_db)
    mgr._generate_embedding = lambda text: [0.5, 0.5, 0.5] if "lesson" in text else [0.1, 0.1, 0.1]

    lid = mgr.store_lesson(
        target_signature="ssh:8.2:linux",
        action_type="SSHBruteForce",
        outcome="success",
        text="lesson: ssh brute force succeeded",
        confidence=0.9,
    )
    assert lid is not None

    lessons = mgr.find_similar_lessons("ssh brute force", action_type="SSHBruteForce", top_k=5)
    assert len(lessons) >= 1
    assert lessons[0]["target_signature"] == "ssh:8.2:linux"


def test_cosine_similarity():
    import numpy as np

    a = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    b = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    assert SemanticMemoryManager._cosine_similarity(a, b) == pytest.approx(1.0)

    c = np.array([0.0, 1.0, 0.0], dtype=np.float32)
    assert SemanticMemoryManager._cosine_similarity(a, c) == pytest.approx(0.0)

    d = np.array([0.0, 0.0, 0.0], dtype=np.float32)
    assert SemanticMemoryManager._cosine_similarity(a, d) == 0.0


def test_summarize_episodes_no_memories(temp_db):
    mgr = SemanticMemoryManager(temp_db)
    result = mgr.summarize_episodes("episodic", "M-001")
    # No memories -> empty string (not an error message) so the caller's
    # ``if not summary`` falls to the factual fallback cleanly.
    assert result == ""


# ── ExperienceStore Tests ─────────────────────────────────────────────────


def test_record_and_query_confidence(temp_db):
    store = ExperienceStore(temp_db)
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "failure")

    conf = store.get_confidence("ssh:8.2:linux", "SSHBruteForce")
    # Beta(1+2+0, 1+1+0) = Beta(3, 2) mean = 3/5 = 0.6
    assert conf == pytest.approx(0.6, abs=0.01)


def test_get_best_action(temp_db):
    store = ExperienceStore(temp_db)
    # min_samples=3 (Tier 1.1): give each real candidate enough outcomes to
    # clear the gate, so the selector compares real Beta means, not 0.5 ties.
    for _ in range(3):
        store.record_outcome("http:nginx:linux", "SQLInjection", "failure")
    for _ in range(3):
        store.record_outcome("http:nginx:linux", "BasicAuthBuster", "success")

    best = store.get_best_action("http:nginx:linux", ["SQLInjection", "BasicAuthBuster", "APIFuzzer"])
    assert best is not None
    assert best[0] == "BasicAuthBuster"
    assert best[1] > 0.5


def test_update_from_exploit_result(temp_db):
    store = ExperienceStore(temp_db)
    # min_samples defaults to 3 (Tier 1.1): a single outcome would read as a
    # neutral 0.5, so record enough to clear the gate and show the success bias.
    for _ in range(3):
        store.update_from_exploit_result(
            service_name="redis",
            version="6.0",
            os_hint="linux",
            module_name="RedisExploit",
            mutation_strategy="parameter_tweak",
            success=True,
        )
    conf = store.get_confidence("redis:6.0:linux", "RedisExploit:parameter_tweak")
    assert conf > 0.5


def test_get_all_confidences(temp_db):
    store = ExperienceStore(temp_db)
    # min_samples=3 (Tier 1.1): record enough per action to clear the gate.
    for _ in range(3):
        store.record_outcome("smb:windows10", "EternalBlue", "success")
    for _ in range(3):
        store.record_outcome("smb:windows10", "SMBGhost", "failure")

    all_conf = store.get_all_confidences("smb:windows10")
    assert "EternalBlue" in all_conf
    assert "SMBGhost" in all_conf
    assert all_conf["EternalBlue"] > all_conf["SMBGhost"]


# ── Tier 1.1: min-samples gate + time decay + embedding soundness ──────────


def test_get_confidence_min_samples_gate(temp_db):
    """Thin data (n < min_samples) reads as a neutral 0.5, not a confident ratio."""
    store = ExperienceStore(temp_db, min_samples=3)
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")  # n=1
    assert store.get_confidence("ssh:8.2:linux", "SSHBruteForce") == 0.5
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")  # n=2
    assert store.get_confidence("ssh:8.2:linux", "SSHBruteForce") == 0.5
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")  # n=3
    # n=3 clears the gate -> Beta(4,1)=0.8
    assert store.get_confidence("ssh:8.2:linux", "SSHBruteForce") > 0.5


def test_get_confidence_time_decay(temp_db):
    """An ancient outcome weighs less than a recent one (exponential decay)."""
    from datetime import datetime, timedelta, timezone

    store = ExperienceStore(temp_db, min_samples=1, time_decay_days=30.0)
    for _ in range(3):
        store.record_outcome("svc:1.0:linux", "Mod", "success")
    # Fresh: Beta(4,1)=0.8
    fresh = store.get_confidence("svc:1.0:linux", "Mod")
    assert fresh > 0.7

    # Backdate every row 300 days -> decay weight ~exp(-10) ~ 0 -> Beta(1,1)=0.5
    with temp_db.connection(write=True) as conn:
        conn.execute(
            "UPDATE lessons SET created_at=? WHERE target_signature=?",
            ((datetime.now(timezone.utc) - timedelta(days=300)).isoformat(), "svc:1.0:linux"),
        )
    decayed = store.get_confidence("svc:1.0:linux", "Mod")
    assert decayed < 0.55  # essentially neutral once decayed


def test_get_confidence_no_decay_when_disabled(temp_db):
    """time_decay_days<=0 means every row weighs 1.0 (pre-1.1 behavior)."""
    from datetime import datetime, timedelta, timezone

    store = ExperienceStore(temp_db, min_samples=1, time_decay_days=0.0)
    for _ in range(3):
        store.record_outcome("svc:2.0:linux", "Mod", "success")
    with temp_db.connection(write=True) as conn:
        conn.execute(
            "UPDATE lessons SET created_at=? WHERE target_signature=?",
            ((datetime.now(timezone.utc) - timedelta(days=9999)).isoformat(), "svc:2.0:linux"),
        )
    # Even ancient rows count fully when decay is disabled -> Beta(4,1)=0.8
    assert store.get_confidence("svc:2.0:linux", "Mod") > 0.7


def test_find_similar_lessons_filters_empty_embeddings(temp_db):
    """record_outcome writes '[]' embeddings; find_similar_lessons must skip them."""
    mgr = SemanticMemoryManager(temp_db)
    mgr._generate_embedding = lambda text: [0.5, 0.5, 0.5]
    # A real lesson carrying a real embedding.
    mgr.store_lesson("ssh:8.2:linux", "SSHBruteForce", "success", "ssh brute force lesson", confidence=0.9)
    # A record_outcome row with a zero-length embedding (the polluter).
    store = ExperienceStore(temp_db)
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")

    lessons = mgr.find_similar_lessons("ssh brute force", top_k=10)
    # Only the real lesson survives the '[]' filter; the polluter must NOT tie
    # at cosine 0.0 and sneak into recall.
    assert len(lessons) == 1
    assert lessons[0]["target_signature"] == "ssh:8.2:linux"


def test_generate_embedding_logs_failure(temp_db, monkeypatch, caplog):
    """A down Ollama must surface a WARNING, not silently return None."""
    import logging
    import urllib.request

    mgr = SemanticMemoryManager(temp_db, ollama_host="http://localhost:11434")

    def boom(*args, **kwargs):
        raise ConnectionError("ollama unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with caplog.at_level(logging.WARNING, logger="tools.semantic_memory"):
        result = mgr._generate_embedding("anything")
    assert result is None
    assert any("semantic embedding failed" in r.message for r in caplog.records)


def test_store_lesson_skips_when_embedding_fails(temp_db):
    """store_lesson returns None and writes no row when no embedding can be made."""
    mgr = SemanticMemoryManager(temp_db)
    mgr._generate_embedding = lambda text: None
    lid = mgr.store_lesson("ssh:8.2:linux", "SSHBruteForce", "success", "lesson text", confidence=0.9)
    assert lid is None
    with temp_db.connection() as conn:
        n = conn.execute("SELECT COUNT(*) AS c FROM lessons").fetchone()["c"]
    assert n == 0


# ── H14 / NaN / json guards ────────────────────────────────────────────────


def test_find_similar_skips_dimension_mismatch_row(temp_db):
    """A stored row whose embedding dimension differs from the query must not
    crash find_similar (H14). The shape guard in _cosine_similarity neutralizes
    the mismatch to a 0.0 (no-information) score, so the bad row sinks to the
    bottom of recall instead of raising ValueError out of np.dot."""
    mgr = SemanticMemoryManager(temp_db)
    # Query produces a 3-dim vector.
    mgr._generate_embedding = lambda text: [0.1, 0.2, 0.3]

    # Store a good 3-dim row.
    mgr.store_embedding("memories", "MEM-GOOD", "test fact", mission_id="M-001")
    # Inject a corrupt row with a mismatched (5-dim) embedding directly.
    with temp_db.connection(write=True) as conn:
        conn.execute(
            "INSERT INTO embeddings(id, mission_id, source_table, source_id, embedding_json, created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("EMB-BAD", "M-001", "memories", "MEM-BAD", json.dumps([0.1, 0.2, 0.3, 0.4, 0.5]), _now_iso()),
        )

    # Must not raise.
    similar = mgr.find_similar("test query", source_table="memories", top_k=10, mission_id="M-001")
    by_id = {c["source_id"]: c for c in similar}
    # Good row is present and ranks above the mismatched row.
    assert "MEM-GOOD" in by_id
    assert by_id["MEM-GOOD"]["similarity"] > 0.99
    # The mismatched row is neutralized to 0.0 (no crash, no false match).
    assert by_id["MEM-BAD"]["similarity"] == 0.0
    assert by_id["MEM-GOOD"]["similarity"] > by_id["MEM-BAD"]["similarity"]


def test_cosine_similarity_nan_inputs_return_zero():
    """_cosine_similarity must return 0.0 for NaN/inf inputs (NaN guard)."""
    import numpy as np

    finite = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    nan_vec = np.array([float("nan"), 1.0, 0.0], dtype=np.float32)
    inf_vec = np.array([float("inf"), 1.0, 0.0], dtype=np.float32)

    assert SemanticMemoryManager._cosine_similarity(finite, nan_vec) == 0.0
    assert SemanticMemoryManager._cosine_similarity(nan_vec, finite) == 0.0
    assert SemanticMemoryManager._cosine_similarity(finite, inf_vec) == 0.0

    # Shape mismatch also returns 0.0.
    other_dim = np.array([1.0, 0.0], dtype=np.float32)
    assert SemanticMemoryManager._cosine_similarity(finite, other_dim) == 0.0


def test_find_similar_skips_corrupt_embedding_json(temp_db):
    """A row with corrupt (non-JSON) embedding_json must be skipped, not crash."""
    mgr = SemanticMemoryManager(temp_db)
    mgr._generate_embedding = lambda text: [0.1, 0.2, 0.3]

    # Store a valid row.
    mgr.store_embedding("memories", "MEM-GOOD", "test fact", mission_id="M-001")
    # Inject a row with garbage embedding_json directly.
    with temp_db.connection(write=True) as conn:
        conn.execute(
            "INSERT INTO embeddings(id, mission_id, source_table, source_id, embedding_json, created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("EMB-CORRUPT", "M-001", "memories", "MEM-CORRUPT", "not-valid-json", _now_iso()),
        )

    similar = mgr.find_similar("test query", source_table="memories", top_k=10, mission_id="M-001")
    ids = {c["source_id"] for c in similar}
    assert "MEM-GOOD" in ids
    assert "MEM-CORRUPT" not in ids


def test_find_similar_lessons_skips_corrupt_metadata_json(temp_db):
    """A lessons row with corrupt metadata_json is skipped, not crashing recall."""
    mgr = SemanticMemoryManager(temp_db)
    mgr._generate_embedding = lambda text: [0.5, 0.5, 0.5]

    # Good lesson.
    mgr.store_lesson("ssh:8.2:linux", "SSHBruteForce", "success", "lesson text", confidence=0.9)
    # Inject a lesson row with valid embedding but corrupt metadata_json.
    with temp_db.connection(write=True) as conn:
        conn.execute(
            "INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, confidence, "
            "embedding_json, metadata_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "LSN-CORRUPT",
                "ssh:8.2:linux:success",
                "ssh:8.2:linux",
                "SSHBruteForce",
                "success",
                0.5,
                json.dumps([0.5, 0.5, 0.5]),
                "not-valid-json",
                _now_iso(),
            ),
        )

    lessons = mgr.find_similar_lessons("lesson text", top_k=10)
    ids = {lesson["id"] for lesson in lessons}
    assert any("ssh:8.2:linux" == lesson["target_signature"] and lesson["id"] != "LSN-CORRUPT" for lesson in lessons)
    assert "LSN-CORRUPT" not in ids


def test_generate_embedding_returns_none_for_nonfinite(temp_db, monkeypatch):
    """Ollama returning NaN/inf in the embedding must yield None, not a poison vector."""
    import urllib.request

    mgr = SemanticMemoryManager(temp_db, ollama_host="http://localhost:11434")

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps({"embedding": [float("nan"), 0.5, 0.5]}).encode("utf-8")

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: FakeResp())
    result = mgr._generate_embedding("anything")
    assert result is None
