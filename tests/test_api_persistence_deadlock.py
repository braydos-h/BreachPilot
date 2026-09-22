"""P0-01: first construction must not self-deadlock; each DB gets WAL/FULL."""

from __future__ import annotations

import sqlite3
import threading

from tools.api.persistence import ApiPersistence


def test_first_construction_does_not_deadlock(tmp_path):
    d1, d2 = tmp_path / "a", tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    errors: list = []

    def make(p):
        try:
            ApiPersistence(p)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t1 = threading.Thread(target=make, args=(d1,))
    t1.start()
    t1.join(timeout=10)
    assert not t1.is_alive(), "deadlock: _init_db -> _connect re-acquired non-reentrant Lock"
    assert not errors
    ApiPersistence(d2)  # second DB file must init independently
    for d in (d1, d2):
        conn = sqlite3.connect(str(d / "api_runtime.db"))
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        finally:
            conn.close()
        assert mode.upper() == "WAL", f"{d} journal_mode={mode}"
        assert int(sync) == 2, f"{d} synchronous={sync} (expected FULL=2)"
