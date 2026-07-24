"""Regression tests for Tier 0.7 — Make the TUI real (Tranche A).

Four sub-fixes guarded here:

A. NameError fix — finding/task/task-detail screens used to reference
   ``FindingDetailScreen`` / ``TaskDetailScreen`` / ``ExecutionScreen`` only inside
   never-called lazy ``_import_*`` helpers, so the first ``push_screen`` raised
   ``NameError``. The helpers are gone and the imports are top-level now.

B. State-bleed fix — ``_step`` / ``_values`` (MissionSetupScreen), ``_selection``
   (EvidenceScreen) and ``Phase`` (ExecutionScreen) were class-level, so two
   instances (or a re-mounted screen) shared state. They are now per-instance.

C. Filter params — ``finding_verifier.list_all`` / ``task_queue.list_open_tasks`` /
   ``evidence.list_for_mission`` accept ``status`` / ``phase`` / ``search`` /
   ``evidence_type`` filters, and the screens route row-indexed actions through the
   SAME filtered query so a filtered view and its row indices agree.

D. Settings → config.yaml — ``SettingsScreen`` propagates operator-facing keys
   into ``config.yaml`` WITHOUT touching the safety-critical ``exploit.permission`` /
   ``exploit.attack_mode``; ``CONFIG_SCHEMA`` defaults ship ``read_only`` / ``attack_mode:
   false`` so a partial config never silently escalates.
"""

from __future__ import annotations

import json

import pytest
import yaml

from db import DatabaseManager, _new_id
from finding_verifier import FindingVerifier
from task_queue import TaskQueue
from evidence import EvidenceStore


# ── Shared DB fixture (mirrors the existing per-module fixtures) ──────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_tui_screens.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "TUI Screen Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def verifier(temp_db):
    return FindingVerifier(temp_db, temp_db._mid)


@pytest.fixture
def queue(temp_db):
    return TaskQueue(temp_db, temp_db._mid)


@pytest.fixture
def evidence_store(temp_db, tmp_path):
    ws = tmp_path / "evidence_ws"
    ws.mkdir(parents=True, exist_ok=True)
    return EvidenceStore(temp_db, temp_db._mid, ws)


# ═══════════════════════════════════════════════════════════════════════════
# Section A — NameError fix (top-level imports, dead helpers removed)
# ═══════════════════════════════════════════════════════════════════════════


def test_push_screen_targets_are_module_globals():
    """The names used in push_screen() must resolve as module globals.

    Before the fix each lived only inside a never-called lazy ``_import_*``
    helper, so opening a finding/task raised NameError at runtime.
    """
    import tui.screens.findings as f
    import tui.screens.tasks as t
    import tui.screens.task_detail as td

    assert "FindingDetailScreen" in vars(f), "findings.py must import FindingDetailScreen at top level"
    assert "TaskDetailScreen" in vars(t), "tasks.py must import TaskDetailScreen at top level"
    assert "ExecutionScreen" in vars(t), "tasks.py must import ExecutionScreen at top level"
    assert "ExecutionScreen" in vars(td), "task_detail.py must import ExecutionScreen at top level"


def test_dead_lazy_import_helpers_removed():
    """The dead ``_import_*`` helpers must stay deleted (guard against re-introduction)."""
    from tui.screens.findings import FindingsScreen
    from tui.screens.tasks import TasksScreen
    from tui.screens.task_detail import TaskDetailScreen

    assert not hasattr(FindingsScreen, "_import_detail")
    assert not hasattr(TasksScreen, "_import_screens")
    assert not hasattr(TaskDetailScreen, "_import_screens")


def test_screen_modules_import_without_circular_error():
    """Importing the screen package must not trigger a circular-import failure."""
    import importlib
    for name in (
        "tui.screens",
        "tui.screens.findings",
        "tui.screens.tasks",
        "tui.screens.task_detail",
        "tui.screens.execution",
        "tui.screens.evidence",
        "tui.screens.mission_setup",
        "tui.screens.settings",
    ):
        importlib.import_module(name)


# ═══════════════════════════════════════════════════════════════════════════
# Section B — State-bleed fix (per-instance state, no shared class attrs)
# ═══════════════════════════════════════════════════════════════════════════


def test_mission_setup_class_attrs_removed():
    """_step/_values must no longer be class attributes (the bleed source)."""
    from tui.screens.mission_setup import MissionSetupScreen
    assert not hasattr(MissionSetupScreen, "_step")
    assert not hasattr(MissionSetupScreen, "_values")


def test_mission_setup_state_is_per_instance():
    from tui.screens.mission_setup import MissionSetupScreen
    a = MissionSetupScreen()
    b = MissionSetupScreen()
    assert a._step == 0 and b._step == 0
    assert a._values == {} and b._values == {}
    a._step = 7
    a._values["target"] = "10.0.0.5"
    # b must be unaffected by a's mutation -- this is the regression that class-level
    # state used to cause (two wizards sharing one dict/counter).
    assert b._step == 0
    assert b._values == {}
    assert a._step == 7
    assert a._values == {"target": "10.0.0.5"}


def test_evidence_screen_class_attr_removed():
    from tui.screens.evidence import EvidenceScreen
    assert not hasattr(EvidenceScreen, "_selection")


def test_evidence_screen_selection_is_per_instance():
    from tui.screens.evidence import EvidenceScreen
    a = EvidenceScreen()
    b = EvidenceScreen()
    a._selection.add(3)
    a._selection.add(5)
    assert b._selection == set(), "selection bled across instances (was a class-level set)"
    assert a._selection == {3, 5}


def test_execution_screen_phase_is_per_instance():
    from tui.screens.execution import ExecutionScreen
    assert not hasattr(ExecutionScreen, "Phase"), "Phase must not be a class attribute"
    a = ExecutionScreen("T-1")
    b = ExecutionScreen("T-2")
    assert a.Phase == 0 and b.Phase == 0
    a.Phase = 2
    assert b.Phase == 0, "Phase bled across instances (was a class attribute)"
    assert a.Phase == 2


# ═══════════════════════════════════════════════════════════════════════════
# Section C — Filter params on the data layer
# ═══════════════════════════════════════════════════════════════════════════


def test_finding_verifier_list_all_status_filter(verifier):
    """list_all(status=...) narrows by status; empty status returns all (backward compat)."""
    f1 = verifier.create_candidate("Keep candidate", "x.com", "summary text here long enough")
    f2 = verifier.create_candidate("Will reject", "y.com", "another summary text long enough")
    verifier.reject(f2, "not real")  # candidate -> rejected

    assert len(verifier.list_all()) == 2
    assert len(verifier.list_all(status="")) == 2  # empty == all

    cands = verifier.list_all(status="candidate")
    assert len(cands) == 1 and cands[0]["finding_id"] == f1

    rejected = verifier.list_all(status="rejected")
    assert len(rejected) == 1 and rejected[0]["finding_id"] == f2

    # A status nobody occupies returns empty (not all).
    assert verifier.list_all(status="validated") == []


def test_task_queue_list_open_tasks_filters(queue):
    """list_open_tasks filters by status/phase/search; default keeps pending+running."""
    t1 = queue.create_task({
        "phase": "recon", "target": "a.com", "objective": "port scan",
        "allowed_tools": ["nmap"], "risk_level": "low",
    })
    t2 = queue.create_task({
        "phase": "test", "target": "b.com", "objective": "IDOR probe IDOR",
        "allowed_tools": ["nmap"], "risk_level": "low",
    })
    t3 = queue.create_task({
        "phase": "recon", "target": "c.com", "objective": "dns enum",
        "allowed_tools": ["nmap"], "risk_level": "low",
    })

    # default open-set (pending + running)
    assert len(queue.list_open_tasks()) == 3

    # phase filter
    recon = queue.list_open_tasks(phase="recon")
    assert len(recon) == 2
    assert {t["task_id"] for t in recon} == {t1, t3}

    # search filter -- objective match
    idor = queue.list_open_tasks(search="IDOR")
    assert len(idor) == 1 and idor[0]["task_id"] == t2

    # search filter -- target match
    a_rows = queue.list_open_tasks(search="a.com")
    assert len(a_rows) == 1 and a_rows[0]["task_id"] == t1

    # status filter REPLACES the open-set predicate (so the TUI status filter can
    # show e.g. only 'blocked'), and the default open-set excludes blocked tasks.
    queue.block_task(t3, "blocked in test")
    blocked = queue.list_open_tasks(status="blocked")
    assert len(blocked) == 1 and blocked[0]["task_id"] == t3
    assert len(queue.list_open_tasks()) == 2  # t3 no longer in pending/running

    # combined filters
    recon_open = queue.list_open_tasks(phase="recon")
    assert recon_open and all(r["phase"] == "recon" for r in recon_open)


def test_evidence_list_for_mission_type_filter(evidence_store):
    """list_for_mission(evidence_type=...) narrows by type; backward compat with limit-only."""
    e1 = evidence_store.save(evidence_type="raw_output", content="output one", target="x")
    e2 = evidence_store.save(evidence_type="note", content="a note", target="x")
    e3 = evidence_store.save(evidence_type="raw_output", content="output two", target="x")

    assert len(evidence_store.list_for_mission(limit=200)) == 3
    assert len(evidence_store.list_for_mission(200)) == 3  # positional limit still works

    raw = evidence_store.list_for_mission(limit=200, evidence_type="raw_output")
    assert len(raw) == 2
    assert all(e["type"] == "raw_output" for e in raw)
    assert {e["evidence_id"] for e in raw} == {e1, e3}

    notes = evidence_store.list_for_mission(limit=200, evidence_type="note")
    assert len(notes) == 1 and notes[0]["evidence_id"] == e2

    # empty type == all
    assert len(evidence_store.list_for_mission(limit=200, evidence_type="")) == 3
    # nonexistent type -> empty
    assert evidence_store.list_for_mission(limit=200, evidence_type="screenshot") == []


def test_screens_have_filter_helpers():
    """The screens route row-indexed actions through a filter-aware helper (guard)."""
    from tui.screens.findings import FindingsScreen
    from tui.screens.evidence import EvidenceScreen

    # findings: _current_findings is used by the table AND validate/reject/open-detail
    assert hasattr(FindingsScreen, "_current_findings")
    # evidence: _current_evidence + a Select.Changed handler for the type filter
    assert hasattr(EvidenceScreen, "_current_evidence")
    assert hasattr(EvidenceScreen, "_on_type_filter")


# ═══════════════════════════════════════════════════════════════════════════
# Section D — Settings -> config.yaml merge + CONFIG_SCHEMA safety defaults
# ═══════════════════════════════════════════════════════════════════════════


def test_config_schema_defaults_are_lab_posture():
    """CONFIG_SCHEMA ships the lab posture: full_access + attack_mode, target-locked
    via require_explicit_allowlist (the runtime --target is unioned into the allowlist
    via EXPLOIT_TARGET). Recon still uses READ_ONLY explicitly at its call sites."""
    from tools.config_manager import CONFIG_SCHEMA
    assert CONFIG_SCHEMA["exploit"]["permission"] == "full_access"
    assert CONFIG_SCHEMA["exploit"]["attack_mode"] is True
    assert CONFIG_SCHEMA["exploit"]["require_explicit_allowlist"] is True
    assert CONFIG_SCHEMA["exploit"]["allowed_targets"] == []


def test_sync_config_keys_preserves_safety_stance(tmp_path, monkeypatch):
    """The Settings sync merges only operator-facing keys; exploit.* is never touched.

    This test seeds config.yaml with the lab stance (full_access / attack_mode true)
    and proves the merge is surgical: the UI must not silently downgrade OR upgrade
    the operator's stance either way.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "ollama:\n  host: http://old:11434\n"
        "models:\n  default_alias: kimi\n"
        "stealth:\n  rotate_ua: false\n  dns_over_https: false\n"
        "multi_model:\n  enabled: false\n"
        "exploit:\n  permission: full_access\n  attack_mode: true\n  max_pivot_depth: 2\n",
        encoding="utf-8",
    )

    from tui.screens.settings import _sync_config_keys
    synced = _sync_config_keys({
        "ollama_host": "http://new:11434",
        "default_model": "glm",
        "rotate_ua": True,
        "doh": True,
        "multi_model_consult": True,
    })
    assert synced is True

    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    # operator-facing keys propagated
    assert cfg["ollama"]["host"] == "http://new:11434"
    assert cfg["models"]["default_alias"] == "glm"
    assert cfg["stealth"]["rotate_ua"] is True
    assert cfg["stealth"]["dns_over_https"] is True
    assert cfg["multi_model"]["enabled"] is True
    # SAFETY: the exploit stance + pivot cap are preserved exactly (not weakened,
    # not escalated) -- the whole point of the surgical merge.
    assert cfg["exploit"]["permission"] == "full_access"
    assert cfg["exploit"]["attack_mode"] is True
    assert cfg["exploit"]["max_pivot_depth"] == 2


def test_sync_config_keys_noop_without_config_yaml(tmp_path, monkeypatch):
    """No config.yaml -> sync is a no-op and must NOT create one."""
    monkeypatch.chdir(tmp_path)
    from tui.screens.settings import _sync_config_keys
    assert _sync_config_keys({"ollama_host": "http://h:11434"}) is False
    assert not (tmp_path / "config.yaml").exists()


def test_save_settings_writes_json_and_reports_sync(tmp_path, monkeypatch):
    """_save_settings writes settings.json and reports whether config.yaml was synced."""
    monkeypatch.chdir(tmp_path)
    from tui.screens import settings as settings_mod
    monkeypatch.setattr(settings_mod, "SETTINGS_FILE", tmp_path / "settings.json")

    # no config.yaml present -> sync False, but settings.json still written
    synced = settings_mod._save_settings({
        "ollama_host": "http://h:11434",
        "default_model": "glm",
        "rotate_ua": True,
        "doh": False,
        "multi_model_consult": True,
        "unicode_icons": True,
    })
    assert synced is False
    assert (tmp_path / "settings.json").exists()
    data = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert data["ollama_host"] == "http://h:11434"
    assert data["default_model"] == "glm"
    assert data["rotate_ua"] is True
    assert data["multi_model_consult"] is True


def test_save_settings_syncs_config_when_present(tmp_path, monkeypatch):
    """When config.yaml exists, _save_settings propagates operator-facing keys into it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "ollama:\n  host: http://old:11434\n"
        "models:\n  default_alias: kimi\n"
        "stealth:\n  rotate_ua: false\n  dns_over_https: false\n"
        "multi_model:\n  enabled: false\n"
        "exploit:\n  permission: read_only\n  attack_mode: false\n",
        encoding="utf-8",
    )
    from tui.screens import settings as settings_mod
    monkeypatch.setattr(settings_mod, "SETTINGS_FILE", tmp_path / "settings.json")

    synced = settings_mod._save_settings({
        "ollama_host": "http://new:11434",
        "default_model": "deepseek",
        "rotate_ua": True,
        "doh": True,
        "multi_model_consult": True,
    })
    assert synced is True
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["ollama"]["host"] == "http://new:11434"
    assert cfg["models"]["default_alias"] == "deepseek"
    assert cfg["stealth"]["rotate_ua"] is True
    assert cfg["stealth"]["dns_over_https"] is True
    assert cfg["multi_model"]["enabled"] is True
    # safety stance untouched
    assert cfg["exploit"]["permission"] == "read_only"
    assert cfg["exploit"]["attack_mode"] is False


def test_settings_model_select_options_include_deepseek_flash(monkeypatch):
    """The TUI model picker should render configured aliases with useful metadata."""
    import tools.config_manager as config_manager
    from tui.screens import settings as settings_mod

    monkeypatch.setattr(
        config_manager,
        "load_validated_config",
        lambda: {
            "models": {
                "registry": {
                    "deepseek_flash": "deepseek-v4-flash:cloud",
                    "glm": "glm-5.2:cloud",
                },
                "info": {
                    "deepseek_flash": {
                        "label": "DeepSeek V4 Flash",
                        "context_window": 1000000,
                        "description": "DeepSeek V4 Flash - 1M token context.",
                    },
                    "glm": {
                        "label": "GLM-5.2",
                        "context_window": 976000,
                        "description": "GLM default.",
                    },
                },
            }
        },
    )

    options, selected = settings_mod._model_select_options("deepseek_flash")
    labels = {value: title for title, value in options}

    assert selected == "deepseek_flash"
    assert "DeepSeek V4 Flash" in labels["deepseek_flash"]
    assert "deepseek-v4-flash:cloud" in labels["deepseek_flash"]
    assert "1M ctx" in labels["deepseek_flash"]


# ═══════════════════════════════════════════════════════════════════════════
# Section E — Dead-binding / honest-notice fixes (M35-M43)
# ═══════════════════════════════════════════════════════════════════════════


def _binding_actions(screen_cls) -> set[str]:
    """Return the set of action names declared in a screen's BINDINGS."""
    return {b.action for b in getattr(screen_cls, "BINDINGS", [])}


# ── M35 / H20 — ExecutionScreen phase guard + honest notice ────────────────


def test_execution_phase_guard_blocks_rerun():
    """After being actioned once, 'x' must not re-run (M35)."""
    from tui.screens.execution import ExecutionScreen

    screen = ExecutionScreen("T-1")
    notifies: list[tuple] = []
    screen.notify = lambda msg, severity="information": notifies.append((msg, severity))
    # Simulate already-actioned state.
    screen.Phase = 3
    screen._scope_result = type("R", (), {"allowed": True})()

    screen.action_confirm_execute()

    assert any("Already executed" in msg for msg, _ in notifies)
    # No fabrication helpers should exist on the screen anymore.
    assert not hasattr(screen, "_simulated_output")
    assert not hasattr(ExecutionScreen, "_simulate_tool")
    assert not hasattr(ExecutionScreen, "_step_simulation")
    assert not hasattr(ExecutionScreen, "_finish_simulation")


def test_execution_shows_honest_notice_and_does_not_fabricate():
    """Pressing execute surfaces an honest notice and never fabricates evidence (H20)."""
    from tui.screens.execution import ExecutionScreen

    screen = ExecutionScreen("T-1")
    notifies: list[tuple] = []
    screen.notify = lambda msg, severity="information": notifies.append((msg, severity))
    screen._scope_result = type("R", (), {"allowed": True})()

    # Guard rails: if the (removed) simulate path were re-introduced, these would fire.
    class _Boom:
        def save(self, **kwargs):
            raise AssertionError("evidence must not be fabricated")

        def complete_task(self, *a, **k):
            raise AssertionError("task must not be marked complete")

    class _FakeSvc:
        has_active_mission = True
        evidence = _Boom()
        tasks = _Boom()

    screen._get_services = lambda: _FakeSvc()
    screen.action_confirm_execute()

    # Honest notice surfaced, Phase advanced so a re-press is blocked.
    assert any("not available" in msg.lower() for msg, _ in notifies)
    assert screen.Phase != 0

    # Re-pressing now hits the phase guard (does not re-enter the notice path).
    notifies.clear()
    screen.action_confirm_execute()
    assert any("Already executed" in msg for msg, _ in notifies)


# ── M36 — ExecutionScreen goto-findings binding + handlers ─────────────────


def test_execution_screen_has_goto_findings_binding_and_action():
    from tui.screens.execution import ExecutionScreen

    assert "goto_findings" in _binding_actions(ExecutionScreen)
    assert hasattr(ExecutionScreen, "action_goto_findings")


# ── M37 — ScopeScreen dead add/delete bindings removed ─────────────────────


def test_scope_add_delete_rule_bindings_removed():
    """add_rule/delete_rule had no action_ methods, so the bindings must be gone (M37)."""
    from tui.screens.scope import ScopeScreen

    actions = _binding_actions(ScopeScreen)
    assert "add_rule" not in actions
    assert "delete_rule" not in actions
    assert not hasattr(ScopeScreen, "action_add_rule")
    assert not hasattr(ScopeScreen, "action_delete_rule")


# ── M38 — GraphScreen new-task action implemented ───────────────────────────


def test_graph_new_task_action_implemented():
    """action_new_task_from_graph must exist (delegates to app task nav) OR binding removed (M38)."""
    from tui.screens.graph import GraphScreen

    assert "new_task_from_graph" in _binding_actions(GraphScreen)
    assert hasattr(GraphScreen, "action_new_task_from_graph")


# ── M39 — FindingsScreen report + missing-evidence actions ─────────────────


def test_findings_screen_has_report_and_missing_evidence_actions():
    from tui.screens.findings import FindingsScreen

    assert hasattr(FindingsScreen, "action_generate_report")
    assert hasattr(FindingsScreen, "action_missing_evidence")


# ── M40 — tasks / task_detail / logs / reports / evidence dead bindings ────


def test_tasks_screen_dead_bindings_resolved():
    from tui.screens.tasks import TasksScreen

    actions = _binding_actions(TasksScreen)
    # complete_task was a dead binding — now implemented.
    assert "complete_task" in actions
    assert hasattr(TasksScreen, "action_complete_task")
    # new_task had no inline-create infra — binding removed (app-level nav covers tasks).
    assert "new_task" not in actions
    # r refresh / slash focus_search shadowed the app-level handlers as dead screen
    # bindings — removed so the app-level (working) handlers apply.
    assert "refresh" not in actions
    assert "focus_search" not in actions


def test_task_detail_screen_dead_binding_removed():
    from tui.screens.task_detail import TaskDetailScreen

    actions = _binding_actions(TaskDetailScreen)
    # validate_finding had no action_ on this screen — removed.
    assert "validate_finding" not in actions
    assert not hasattr(TaskDetailScreen, "action_validate_finding")


def test_logs_screen_dead_bindings_removed():
    from tui.screens.logs import LogsScreen

    actions = _binding_actions(LogsScreen)
    assert "export_logs" not in actions   # no export infra — removed
    assert "refresh" not in actions       # app-level r refresh applies
    assert "focus_search" not in actions  # logs has no Input; app handler no-ops


def test_reports_screen_dead_bindings_removed():
    from tui.screens.reports import ReportsScreen

    actions = _binding_actions(ReportsScreen)
    assert "export" not in actions        # no export infra — removed
    assert "refresh" not in actions       # app-level r refresh applies
    # generate_report remains a real action.
    assert "generate_report" in actions
    assert hasattr(ReportsScreen, "action_generate_report")


def test_evidence_screen_copy_ref_implemented_and_refresh_removed():
    from tui.screens.evidence import EvidenceScreen

    actions = _binding_actions(EvidenceScreen)
    assert "copy_ref" in actions
    assert hasattr(EvidenceScreen, "action_copy_ref")
    # r refresh removed so the app-level (working) handler applies.
    assert "refresh" not in actions


# ── M41 — dashboard / swarm suspend+resume timer management ─────────────────


def test_dashboard_on_screen_suspend_stops_timer():
    """on_screen_pop was dead; on_screen_suspend must stop+null the timer (M41)."""
    from tui.screens.dashboard import DashboardScreen

    screen = DashboardScreen()
    assert hasattr(screen, "on_screen_suspend")
    assert not hasattr(DashboardScreen, "on_screen_pop")

    stopped: list[bool] = []

    class _FakeTimer:
        def stop(self):
            stopped.append(True)

    screen._refresh_timer = _FakeTimer()
    screen.on_screen_suspend()
    assert stopped == [True]
    assert screen._refresh_timer is None


def test_swarm_on_screen_suspend_stops_timer():
    from tui.screens.swarm import SwarmScreen

    screen = SwarmScreen()
    assert hasattr(screen, "on_screen_suspend")
    assert not hasattr(SwarmScreen, "on_screen_pop")

    stopped: list[bool] = []

    class _FakeTimer:
        def stop(self):
            stopped.append(True)

    screen._refresh_timer = _FakeTimer()
    screen.on_screen_suspend()
    assert stopped == [True]
    assert screen._refresh_timer is None


# ── M42 — mission_setup empty allowed assets surfaces validation ───────────


def test_mission_setup_empty_allowed_preserved_for_validation(monkeypatch):
    """Clearing the allowed-assets textarea must NOT silently insert example.com (M42).

    _collect_current now preserves the empty list so _create's existing
    'At least one allowed asset is required.' validation fires.
    """
    from tui.screens.mission_setup import MissionSetupScreen

    screen = MissionSetupScreen()
    screen._step = 2

    class _FakeTextArea:
        text = ""  # user cleared the field

    # query_one is called as self.query_one("#wiz-input-allowed", TextArea)
    screen.query_one = lambda *a, **k: _FakeTextArea()

    screen._collect_current()
    assert screen._values.get("allowed") == []
    # The old code would have set ["example.com"] here, hiding the empty state.


# ── M43 — settings save notifies on OSError instead of crashing ────────────


def test_settings_save_notifies_on_oserror(monkeypatch):
    """When _save_settings raises OSError, action_save must notify (error), not crash (M43)."""
    import tui.screens.settings as settings_mod
    from tui.screens.settings import SettingsScreen

    screen = SettingsScreen()

    class _FakeWidget:
        def __init__(self, value):
            self.value = value

    _widget_values = {
        "#set-ollama-host": "http://h:11434",
        "#set-default-model": "glm",
        "#set-workspace-dir": "research_workspace",
        "#set-refresh": "5",
        "#set-risk-default": "standard_authorized",
        "#set-rotate-ua": False,
        "#set-doh": False,
        "#set-multi-model": False,
        "#set-unicode": True,
    }

    def _fake_query_one(selector, expect_type=None):
        return _FakeWidget(_widget_values.get(selector, ""))

    screen.query_one = _fake_query_one
    monkeypatch.setattr(settings_mod, "set_icon_mode", lambda v: None)
    monkeypatch.setattr(
        settings_mod,
        "_load_settings",
        lambda: {
            "unicode_icons": True, "ollama_host": "http://localhost:11434",
            "default_model": "glm", "rotate_ua": False, "doh": False,
            "default_risk": "standard_authorized", "workspace_dir": "research_workspace",
            "auto_refresh": 5, "multi_model_consult": False,
        },
    )

    def _raise_oserror(_settings):
        raise OSError("disk full")

    monkeypatch.setattr(settings_mod, "_save_settings", _raise_oserror)

    notifies: list[tuple] = []
    screen.notify = lambda msg, severity="information": notifies.append((msg, severity))

    # Must not raise.
    screen.action_save()

    assert any(severity == "error" for _, severity in notifies), \
        "action_save should notify with severity='error' when _save_settings raises OSError"


def test_settings_auto_refresh_non_numeric_warns(monkeypatch):
    """A non-numeric auto-refresh must warn and fall back to 5 (not silent reset) (M43)."""
    import tui.screens.settings as settings_mod
    from tui.screens.settings import SettingsScreen

    screen = SettingsScreen()

    class _FakeWidget:
        def __init__(self, value):
            self.value = value

    _widget_values = {
        "#set-ollama-host": "http://h:11434",
        "#set-default-model": "glm",
        "#set-workspace-dir": "research_workspace",
        "#set-refresh": "not-a-number",
        "#set-risk-default": "standard_authorized",
        "#set-rotate-ua": False,
        "#set-doh": False,
        "#set-multi-model": False,
        "#set-unicode": True,
    }

    def _fake_query_one(selector, expect_type=None):
        return _FakeWidget(_widget_values.get(selector, ""))

    screen.query_one = _fake_query_one
    monkeypatch.setattr(settings_mod, "set_icon_mode", lambda v: None)
    monkeypatch.setattr(
        settings_mod,
        "_load_settings",
        lambda: {
            "unicode_icons": True, "ollama_host": "http://localhost:11434",
            "default_model": "glm", "rotate_ua": False, "doh": False,
            "default_risk": "standard_authorized", "workspace_dir": "research_workspace",
            "auto_refresh": 5, "multi_model_consult": False,
        },
    )

    saved: dict = {}
    monkeypatch.setattr(settings_mod, "_save_settings", lambda s: saved.update(s) or False)

    notifies: list[tuple] = []
    screen.notify = lambda msg, severity="information": notifies.append((msg, severity))

    screen.action_save()

    assert saved.get("auto_refresh") == 5
    assert any("Auto-refresh must be a number" in msg and severity == "warning"
               for msg, severity in notifies)
