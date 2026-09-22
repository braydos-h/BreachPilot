"""Characterization tests for the ``tools.memory`` package split (todo 06).

Pins the post-split contract: shared helpers, the per-attempt tactical
store, Bayesian experience confidence, session checkpointing, and the
MemoryService facade. SQLite-backed stores use ``tmp_path``; no network,
no model calls.

Split map (``tools.memory_service`` is a thin shim over all of these):

- ``tools.memory.helpers`` — cap_text, one_line, take_last, decay_weight,
  beta_mean, cosine_similarity
- ``tools.memory.attack_store`` — AttackMemoryItem, AttackMemoryStore
- ``tools.memory.experience`` — ExperienceStore
- ``tools.memory.semantic`` — SemanticMemoryManager (import surface only)
- ``tools.memory.session`` — SessionState, SessionManager, _load_resume_state
- ``tools.memory.service`` — MemoryService
"""

from __future__ import annotations

from pathlib import Path

import tools.memory_service as ms
from db import DatabaseManager
from tools.memory import attack_store as _attack
from tools.memory import experience as _experience
from tools.memory import helpers as _helpers
from tools.memory import service as _service
from tools.memory import session as _session


def test_shim_reexports_canonical_objects():
    assert ms.AttackMemoryStore is _attack.AttackMemoryStore
    assert ms.AttackMemoryItem is _attack.AttackMemoryItem
    assert ms.ATTACK_MEMORY_DB == _attack.ATTACK_MEMORY_DB == "attack_memory.db"
    assert ms.ExperienceStore is _experience.ExperienceStore
    assert ms.SessionManager is _session.SessionManager
    assert ms.SessionState is _session.SessionState
    assert ms.MemoryService is _service.MemoryService
    assert ms.cap_text is _helpers.cap_text
    assert ms.beta_mean is _helpers.beta_mean


def test_cap_text_truncation():
    assert ms.cap_text("hello", 10) == "hello"
    assert ms.cap_text("hello world", 8).endswith("...")
    assert ms.cap_text("hello", 0) == ""


def test_one_line_collapses_whitespace():
    assert ms.one_line("a\n  b\tc") == "a b c"


def test_take_last_window():
    assert ms.take_last([1, 2, 3, 4], 2) == [3, 4]
    assert ms.take_last([1, 2], 0) == []
    assert ms.take_last([], 5) == []


def test_beta_mean_prior_is_neutral():
    assert ms.beta_mean(0.0, 0.0) == 0.5
    assert ms.beta_mean(3.0, 1.0) > 0.5
    assert ms.beta_mean(1.0, 3.0) < 0.5


def test_decay_weight_fresh_and_disabled():
    assert ms.decay_weight("not-a-timestamp", 90.0) == 1.0
    assert ms.decay_weight("2020-01-01T00:00:00+00:00", 0.0) == 1.0
    assert 0.0 < ms.decay_weight("2020-01-01T00:00:00+00:00", 90.0) < 1.0


def test_attack_store_note_roundtrip(tmp_path: Path):
    store = ms.AttackMemoryStore(tmp_path, "sess-1", "127.0.0.1")
    assert store.capture_note("notes", "k1", "v1") is True
    assert store.capture_note("notes", "k2", "") is False
    items = store.list_items("notes")
    assert any(i.item_key == "k1" and i.item_value == "v1" for i in items)
    assert "k1" in store.format_context()


def test_attack_store_capture_tool_result_counts(tmp_path: Path):
    store = ms.AttackMemoryStore(tmp_path, "sess-1", "127.0.0.1")
    n = store.capture_tool_result("nmap", "PORT 22/tcp open ssh\nCVE-2021-44228 suspected", True)
    assert isinstance(n, int) and n >= 0


def test_experience_thin_data_is_neutral(tmp_path: Path):
    db = DatabaseManager(tmp_path / "exp.db")
    exp = ms.ExperienceStore(db)
    exp.record_outcome("sig", "act", "success")
    assert exp.get_confidence("sig", "act") == 0.5
    assert exp.observation_count("sig", "act") == 1
    assert exp.observation_count("sig", "other") == 0


def test_session_state_json_roundtrip():
    state = ms.SessionState(session_id="s", target_ip="127.0.0.1", target_cve="CVE-2021-44228")
    restored = ms.SessionState.from_json(state.to_json())
    assert restored.session_id == "s"
    assert restored.target_ip == "127.0.0.1"
    assert restored.target_cve == "CVE-2021-44228"


def test_session_manager_new_and_save(tmp_path: Path):
    manager = ms.SessionManager(tmp_path)
    state = manager.new_session(target_ip="127.0.0.1")
    assert state.target_ip == "127.0.0.1"
    manager.record_action("probe", "open port", success=True)
    manager.save()
    assert (tmp_path / "session_state.json").exists()
    assert manager.load() is not None


def test_memory_service_facade_unwired_confidence(tmp_path: Path):
    svc = ms.MemoryService(tmp_path, session_id="s", target_ip="127.0.0.1")
    assert svc.get_confidence("sig", "act") == 0.5
    assert svc.observation_count("sig", "act") == 0
    assert svc.get_all_confidences("sig") == {}


def test_memory_service_facade_wired_experience(tmp_path: Path):
    db = DatabaseManager(tmp_path / "svc.db")
    svc = ms.MemoryService(tmp_path, session_id="s", target_ip="127.0.0.1", db=db)
    svc.record_outcome("sig", "act", "failure")
    assert svc.observation_count("sig", "act") == 1


def test_semantic_manager_import_surface():
    from tools.memory import semantic as _sem

    assert hasattr(_sem, "SemanticMemoryManager")
    assert ms.SemanticMemoryManager is _sem.SemanticMemoryManager
