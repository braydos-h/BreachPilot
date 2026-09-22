"""P2-07: shared append-only log writer (order + drain + perms)."""

from __future__ import annotations

import os
import stat


def test_append_log_order_drain_and_perms(tmp_path):
    from tools.kernel.append_log import AppendLogWriter

    path = tmp_path / "sub" / "audit.jsonl"
    w = AppendLogWriter(path)
    for i in range(500):
        w.append(f'{{"i": {i}}}\n')
    w.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 500
    assert [int(l.split(":")[1].rstrip(" }")) for l in lines] == list(range(500))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"{oct(mode)}"
    w.close()  # idempotent


def test_append_log_registry_reuses_per_path(tmp_path):
    from tools.kernel.append_log import close_all_writers, get_append_writer

    a = get_append_writer(tmp_path / "a.jsonl")
    b = get_append_writer(tmp_path / "a.jsonl")
    assert a is b
    a.append('{"x": 1}\n')
    close_all_writers()
    assert (tmp_path / "a.jsonl").read_text(encoding="utf-8").strip() == '{"x": 1}'
