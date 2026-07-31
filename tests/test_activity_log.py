"""Tests for ``tools/activity_log.py`` — JSONL audit trail + CLI line printer.

Covers the buffer-flush threshold, JSONL file contents, line formatting with
severity labels and ANSI colors, the in-memory event cap, the progress
helpers, and the convenience wrappers (ping/triage/tool_call/blocked/etc.).
"""

from __future__ import annotations

import json

from tools.activity_log import (
    ICONS,
    SEVERITY_COLOR,
    ActivityEvent,
    ActivityLog,
)

# ── Constants ───────────────────────────────────────────────────────────────


def test_icons_has_known_categories():
    for cat in ("ping", "triage", "basic_scan", "service_scan", "vuln_scan", "report", "blocked"):
        assert cat in ICONS


def test_severity_color_has_known_severities():
    for sev in ("critical", "high", "medium", "low", "info", "warning", "error"):
        assert sev in SEVERITY_COLOR


# ── ActivityEvent dataclass ────────────────────────────────────────────────


def test_activity_event_defaults():
    e = ActivityEvent(timestamp="12:00:00", icon="*", category="info", message="hi")
    assert e.detail == ""
    assert e.host == ""
    assert e.severity == "info"


# ── JSONL audit trail ───────────────────────────────────────────────────────


def test_log_creates_audit_file_on_first_flush(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.log("info", "first message")
    # Buffer threshold is 10; not flushed yet.
    assert not (tmp_path / "activity.jsonl").exists()
    for _ in range(9):
        log.log("info", "filler")
    # 10th event triggers flush.
    assert (tmp_path / "activity.jsonl").exists()
    log._flush_audit()  # ensure nothing pending


def test_audit_jsonl_contains_all_event_fields(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.log("ping", "sweep result", detail="10.0.0.0/24", host="10.0.0.5", severity="warning")
    log._flush_audit()
    lines = (tmp_path / "activity.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["category"] == "ping"
    assert entry["message"] == "sweep result"
    assert entry["detail"] == "10.0.0.0/24"
    assert entry["host"] == "10.0.0.5"
    assert entry["severity"] == "warning"
    assert "time" in entry


def test_buffer_flush_at_threshold(tmp_path):
    log = ActivityLog(tmp_path, plain=True, max_events=100)
    for i in range(9):
        log.log("info", f"m{i}")
    assert not (tmp_path / "activity.jsonl").exists()
    log.log("info", "m9")  # 10th -> flush
    assert (tmp_path / "activity.jsonl").exists()
    content = (tmp_path / "activity.jsonl").read_text(encoding="utf-8")
    assert content.count("\n") == 10


def test_flush_audit_idempotent_when_empty(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log._flush_audit()  # no-op, should not error
    assert not (tmp_path / "activity.jsonl").exists()


def test_flush_writes_remaining_buffer(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    for i in range(5):
        log.log("info", f"m{i}")
    log._flush_audit()
    content = (tmp_path / "activity.jsonl").read_text(encoding="utf-8")
    assert content.count("\n") == 5


# ── In-memory event cap ─────────────────────────────────────────────────────


def test_events_capped_to_max_events(tmp_path):
    log = ActivityLog(tmp_path, plain=True, max_events=5)
    for i in range(10):
        log.log("info", f"m{i}")
    assert len(log.events) == 5
    # oldest popped; the last 5 remain (m5..m9)
    assert log.events[0].message == "m5"
    assert log.events[-1].message == "m9"
    log._flush_audit()


# ── Line formatting ─────────────────────────────────────────────────────────


def test_fmt_line_basic(tmp_path):
    e = ActivityEvent(timestamp="12:00:00", icon="*", category="info", message="hello", severity="high")
    log = ActivityLog(tmp_path, plain=True)
    line = log._fmt_line(e)
    assert "12:00:00" in line
    assert "[HIGH]" in line
    assert "hello" in line
    log._flush_audit()


def test_fmt_line_unknown_severity_defaults_info(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    e = ActivityEvent(timestamp="t", icon="*", category="info", message="m", severity="bogus")
    line = log._fmt_line(e)
    assert "[INFO]" in line


def test_fmt_line_includes_host_when_present(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    e = ActivityEvent(timestamp="t", icon="*", category="info", message="m", host="10.0.0.5", severity="low")
    line = log._fmt_line(e)
    assert "[10.0.0.5]" in line


def test_fmt_line_omits_host_when_empty(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    e = ActivityEvent(timestamp="t", icon="*", category="info", message="m", severity="low")
    line = log._fmt_line(e)
    assert "[" not in line.split("m")[1]  # no trailing [host]


def test_fmt_line_uses_default_icon_for_unknown_category(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    e = ActivityEvent(timestamp="t", icon="?", category="totally_unknown", message="m", severity="info")
    line = log._fmt_line(e)
    # ICONS.get -> "*" default
    assert " * " in line


# ── print (plain vs colored) ─────────────────────────────────────────────────


def test_print_plain_no_color(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=True)
    log._print("hello", severity="error")
    captured = capsys.readouterr()
    assert "hello" in captured.out
    assert "\x1b[" not in captured.out


def test_print_colored_includes_ansi(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=False)
    log._print("boom", severity="critical")
    captured = capsys.readouterr()
    assert "\x1b[" in captured.out
    assert "boom" in captured.out


def test_log_prints_detail_lines(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=True)
    log.log("info", "msg", detail="line1\nline2\nline3\nline4")
    captured = capsys.readouterr()
    # Only first 3 detail lines are printed.
    assert "line1" in captured.out
    assert "line2" in captured.out
    assert "line3" in captured.out
    assert "line4" not in captured.out


# ── progress ────────────────────────────────────────────────────────────────


def test_progress_no_subnets_set(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    p = log.progress()
    assert "elapsed" in p
    assert "subnets" not in p


def test_progress_with_subnets(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.set_progress(subnets_total=4, subnets_done=2)
    p = log.progress()
    assert "subnets 2/4" in p
    assert "elapsed" in p


def test_set_progress_updates_dict(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.set_progress(subnets_total=10)
    assert log._overall_progress["subnets_total"] == 10


def test_print_progress_plain(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=True)
    log.print_progress()
    out = capsys.readouterr().out
    assert "elapsed" in out


def test_print_progress_colored(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=False)
    log.print_progress()
    out = capsys.readouterr().out
    assert "\x1b[" in out


# ── context manager + start/stop ─────────────────────────────────────────────


def test_context_manager_returns_self(tmp_path):
    with ActivityLog(tmp_path, plain=True) as log:
        assert isinstance(log, ActivityLog)
        log._flush_audit()


def test_start_stop_noop(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.start()
    log.stop()


# ── convenience wrappers ─────────────────────────────────────────────────────


def test_ping_increments_subnets_done(tmp_path, capsys):
    log = ActivityLog(tmp_path, plain=True)
    log.set_progress(subnets_total=2, subnets_done=0)
    log.ping("10.0.0.0/24", "1 host up")
    assert log._overall_progress["subnets_done"] == 1
    assert log.events[-1].category == "ping"
    log._flush_audit()


def test_triage_logs_category(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.triage("10.0.0.0/24", "2 ports open")
    assert log.events[-1].category == "triage"
    assert "Triage scan" in log.events[-1].message
    log._flush_audit()


def test_tool_call_includes_args_and_result(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.tool_call("run_nmap_basic", {"target_ip": "10.0.0.5"}, result="22/tcp open")
    e = log.events[-1]
    assert "Args:" in e.detail
    assert "target_ip" in e.detail
    assert "22/tcp open" in e.detail
    log._flush_audit()


def test_blocked_uses_warning_severity(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.blocked("out of scope")
    e = log.events[-1]
    assert e.category == "blocked"
    assert e.severity == "warning"
    assert "out of scope" in e.detail
    log._flush_audit()


def test_report_written(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.report_written(tmp_path / "report.md")
    e = log.events[-1]
    assert e.category == "report"
    assert "Report written" in e.message
    log._flush_audit()


def test_budget_warning(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.budget_warning(remaining=5, kind="minutes")
    e = log.events[-1]
    assert e.category == "budget"
    assert e.severity == "warning"
    assert "5" in e.message
    log._flush_audit()
