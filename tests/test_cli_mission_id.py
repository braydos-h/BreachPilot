"""Regression tests for Tier 1.3 — CLI ``--mission-id`` (Flow B resume surface).

``cli._load_mission`` historically always returned the latest ``active``
mission. Tier 1.3 adds an explicit ``--mission-id`` flag (on every subcommand
except ``init-mission``) so an operator can reattach to a SPECIFIC mission —
the one they were running before a crash/restart — instead of silently
operating on whichever mission happens to be newest+active. A resumed
mission may be ``paused``, so the by-id lookup must NOT filter on status.

These tests would have caught the original gap: with two missions in the DB,
``next-task --mission-id <older>`` must target the named mission's tasks, not
the latest active one's; and a nonexistent id must error (not fall back to
latest-active, which would be a silent wrong-mission hazard).
"""

from __future__ import annotations

import pytest

import cli
from mission import MissionController


def _mission_yaml(program: str, asset: str) -> str:
    return (
        f"program_name: {program}\n"
        f"objective: resume-cli test\n"
        f"risk_profile: low_noise_non_destructive\n"
        f"allowed_assets:\n"
        f"  - {asset}\n"
        f"disallowed_assets: []\n"
        f"forbidden_actions:\n"
        f"  - denial_of_service\n"
        f"testing_modes:\n"
        f"  - recon\n"
        f"  - analysis\n"
    )


@pytest.fixture
def isolated_workspace(tmp_path, monkeypatch):
    """Point the CLI at a throwaway research_workspace/ so tests don't touch
    the operator's real DB."""
    ws = tmp_path / "research_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(cli.WS_ENV, str(ws))
    # Also reset any cached workspace root via _workspace_root (it reads env
    # live, so no extra monkeypatching needed).
    return ws


def _create_mission(isolated_workspace, program: str, asset: str) -> str:
    """Create a real mission row via the production path (MissionController) and
    return its id. We use MissionController directly rather than shelling out
    to cmd_init_mission so we don't depend on stdout parsing."""
    cfg_path = isolated_workspace / f"{program}.yaml"
    cfg_path.write_text(_mission_yaml(program, asset), encoding="utf-8")

    import yaml

    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    db = cli._load_db()
    ctrl = MissionController(db, isolated_workspace)
    mission = ctrl.create_from_config(config)
    return mission.mission_id


def _parse(*argv: str):
    return cli.build_parser().parse_args(argv)


# ── _load_mission by-id semantics ──────────────────────────────────────────


def test_load_mission_by_id_ignores_status(isolated_workspace):
    """By-id lookup must return the named mission regardless of status (a
    resumed mission may be 'paused'), unlike the default latest-active path."""
    mid = _create_mission(isolated_workspace, "ProgA", "10.0.0.50")
    db = cli._load_db()
    # Mark it paused -- a resumed campaign is often not 'active'.
    with db.connection(write=True) as conn:
        conn.execute("UPDATE missions SET status='paused' WHERE id=?", (mid,))

    # by id -> found even though not active
    row = cli._load_mission(db, mid)
    assert row is not None and row["id"] == mid
    # default path -> NOT found (it's paused, not active)
    assert cli._load_mission(db, None) is None


def test_load_mission_nonexistent_id_returns_none_not_latest(isolated_workspace):
    """A wrong --mission-id must NOT silently fall back to the latest active
    mission (that would operate on the wrong campaign). It returns None so the
    command surfaces an error."""
    _create_mission(isolated_workspace, "ProgActive", "10.0.0.10")  # latest active
    db = cli._load_db()
    assert cli._load_mission(db, "M-DOES-NOT-EXIST") is None


# ── CLI flag wiring ─────────────────────────────────────────────────────────


def test_mission_id_flag_present_on_subcommands(isolated_workspace):
    """Every operating subcommand accepts --mission-id; init-mission does not
    (it creates a new mission, so resuming is meaningless there)."""
    for cmd in ["next-task", "list-tasks", "status", "list-findings", "list-scope"]:
        args = _parse(cmd, "--mission-id", "M-X")
        assert getattr(args, "mission_id", None) == "M-X", f"{cmd} missing --mission-id"
    # flag may also appear before the positional (run-task / validate-finding)
    assert _parse("run-task", "--mission-id", "M-X", "T-1").mission_id == "M-X"
    # default is None when omitted
    assert _parse("next-task").mission_id is None


def test_init_mission_has_no_mission_id_flag(isolated_workspace):
    """init-mission must NOT accept --mission-id (it mints a new mission; an id
    arg there would be confusing/contradictory). argparse rejects unknown
    args, so passing --mission-id to it must error."""
    with pytest.raises(SystemExit):
        _parse("init-mission", "--mission-id", "M-X", "--config", "x.yaml")


# ── End-to-end: --mission-id targets the NAMED mission, not the newest ──────


def test_next_task_mission_id_targets_named_not_latest(isolated_workspace):
    """Two missions exist; the NEWER one is latest-active. ``next-task
    --mission-id <older>`` must pull a task from the OLDER mission's queue,
    proving the flag selects the named campaign rather than defaulting to the
    newest active one."""
    older_mid = _create_mission(isolated_workspace, "Older", "10.0.0.50")
    newer_mid = _create_mission(isolated_workspace, "Newer", "10.0.0.99")
    assert older_mid != newer_mid

    # Put a task ONLY in the older mission.
    db = cli._load_db()
    from task_queue import TaskQueue

    TaskQueue(db, older_mid).create_task(
        {
            "task_id": "T-OLDER-1",
            "phase": "recon",
            "target": "10.0.0.50",
            "objective": "older mission task",
            "status": "pending",
        }
    )

    # Run the CLI command against the older mission id.
    args = _parse("next-task", "--mission-id", older_mid)
    rc = cli.cmd_next_task(args)
    assert rc == 0
    # And it did NOT accidentally resolve to the newer mission (no task there).
    args2 = _parse("next-task", "--mission-id", newer_mid)
    # newer mission has no pending tasks -> "No pending tasks. Planning needed."
    rc2 = cli.cmd_next_task(args2)
    assert rc2 == 0


def test_next_task_wrong_mission_id_errors(isolated_workspace, capsys):
    """A nonexistent --mission-id must print an error mentioning the id and
    return nonzero (not silently fall through to latest-active)."""
    _create_mission(isolated_workspace, "Active", "10.0.0.10")  # so latest-active exists
    args = _parse("next-task", "--mission-id", "M-GONE")
    rc = cli.cmd_next_task(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "M-GONE" in out, "error must name the missing id"
    assert "No mission" in out.lower() or "no mission" in out.lower()


def test_status_without_mission_id_uses_latest_active(isolated_workspace, capsys):
    """Back-compat: with no --mission-id, status still resolves the latest
    active mission (the historical behavior). The newer mission wins."""
    older_mid = _create_mission(isolated_workspace, "Older", "10.0.0.50")
    newer_mid = _create_mission(isolated_workspace, "Newer", "10.0.0.99")
    args = _parse("status")
    rc = cli.cmd_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    # The newer mission is the latest active -> its id appears in the status.
    assert newer_mid in out
    assert older_mid not in out
