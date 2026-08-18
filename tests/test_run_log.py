from __future__ import annotations

import io
import logging
import sys

from tools.run_log import RunLog


def _capture_streams(monkeypatch) -> tuple[io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    return out, err


def test_run_log_captures_print_and_logging(tmp_path, monkeypatch) -> None:
    out, err = _capture_streams(monkeypatch)

    RunLog.attach(tmp_path)
    try:
        print("console line")
        logging.getLogger("tools.some_module").error("boom: %s", "detail")
        logging.getLogger("tools.some_module").debug("hidden detail")
    finally:
        RunLog.detach()

    text = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "console line" in text
    assert "boom: detail" in text
    assert "hidden detail" in text
    # Terminal still sees everything (tee pass-through).
    assert out.getvalue() == "console line\n"
    # Streams restored to the monkeypatched originals.
    assert sys.stdout is out
    assert sys.stderr is err


def test_run_log_strips_ansi_and_redraws(tmp_path, monkeypatch) -> None:
    _capture_streams(monkeypatch)
    RunLog.attach(tmp_path)
    try:
        print("\x1b[1;31m[ERROR]\x1b[0m red\r\x1b[Kraw")
    finally:
        RunLog.detach()
    text = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "\x1b[" not in text
    assert "\r" not in text
    assert "[ERROR] redraw" in text


def test_run_log_removes_root_handler_on_detach(tmp_path, monkeypatch) -> None:
    _capture_streams(monkeypatch)
    root = logging.getLogger()
    before_handlers = set(root.handlers)
    before_level = root.level
    RunLog.attach(tmp_path)
    assert set(root.handlers) - before_handlers
    RunLog.detach()
    assert set(root.handlers) == before_handlers
    assert root.level == before_level
