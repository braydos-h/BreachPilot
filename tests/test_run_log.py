from __future__ import annotations

import asyncio
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


def test_overlapping_run_logs_stay_isolated_when_first_run_detaches(tmp_path, monkeypatch) -> None:
    out, err = _capture_streams(monkeypatch)
    root = logging.getLogger()
    before_handlers = set(root.handlers)
    before_level = root.level
    a_started = asyncio.Event()
    b_started = asyncio.Event()
    a_finished = asyncio.Event()

    async def run_a() -> None:
        RunLog.attach(tmp_path / "run-a")
        try:
            print("A before overlap")
            logging.getLogger("run-log-test").warning("A log before overlap")
            a_started.set()
            await b_started.wait()
            print("A finishing while B remains active")
            logging.getLogger("run-log-test").warning("A final log")
        finally:
            RunLog.detach()
            a_finished.set()

    async def run_b() -> None:
        await a_started.wait()
        RunLog.attach(tmp_path / "run-b")
        try:
            print("B before A ends")
            logging.getLogger("run-log-test").warning("B log before A ends")
            b_started.set()
            await a_finished.wait()
            # A's detach must not restore the process streams or remove the
            # shared handler while this independent run still owns a session.
            print("B after A ends")
            logging.getLogger("run-log-test").warning("B log after A ends")
        finally:
            RunLog.detach()

    async def interleave() -> None:
        await asyncio.gather(run_a(), run_b())

    asyncio.run(interleave())

    a_log = (tmp_path / "run-a" / "run.log").read_text(encoding="utf-8")
    b_log = (tmp_path / "run-b" / "run.log").read_text(encoding="utf-8")
    assert "A before overlap" in a_log
    assert "A log before overlap" in a_log
    assert "A finishing while B remains active" in a_log
    assert "A final log" in a_log
    assert "B before A ends" not in a_log
    assert "B log before A ends" not in a_log
    assert "B after A ends" not in a_log
    assert "B log after A ends" not in a_log
    assert "B before A ends" in b_log
    assert "B log before A ends" in b_log
    assert "B after A ends" in b_log
    assert "B log after A ends" in b_log
    assert "A before overlap" not in b_log
    assert "A finishing while B remains active" not in b_log
    assert "A final log" not in b_log
    assert "A before overlap" in out.getvalue()
    assert "B after A ends" in out.getvalue()
    assert sys.stdout is out
    assert sys.stderr is err
    assert set(root.handlers) == before_handlers
    assert root.level == before_level
