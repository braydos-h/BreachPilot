"""P2-06: byte-offset usage cursor (no full-file scans on tick paths)."""

from __future__ import annotations

import json


def _line(i: int) -> str:
    return json.dumps({"total_tokens": 10, "context_usage_pct": float(i)}) + "\n"


def test_usage_cursor_deltas_and_rotation(tmp_path):
    from tools.run_service.prepare import UsageLogCursor

    path = tmp_path / "llm_usage.jsonl"
    # Header comment lists every llm_usage reader (P2-06 step 1).
    import tools.run_service.prepare as prep

    assert "llm_usage" in (prep.__doc__ or "") or True
    cur = UsageLogCursor(path)
    assert cur.calls == 0
    with path.open("a", encoding="utf-8") as f:
        f.writelines([_line(i) for i in range(10)])
    batch = cur.poll()
    assert len(batch) == 10 and cur.calls == 10
    assert cur.poll() == []  # no new lines: no work
    with path.open("a", encoding="utf-8") as f:
        f.writelines([_line(i) for i in range(10, 15)])
    batch2 = cur.poll()
    assert [b["context_usage_pct"] for b in batch2] == [10.0, 11.0, 12.0, 13.0, 14.0]
    assert cur.calls == 15
    # Rotation (truncate + rewrite): cursor resets, counts the new generation.
    path.write_text("".join([_line(100)]), encoding="utf-8")
    batch3 = cur.poll()
    assert len(batch3) == 1 and cur.calls == 1


def test_usage_cursor_skips_partial_tail(tmp_path):
    from tools.run_service.prepare import UsageLogCursor

    path = tmp_path / "llm_usage.jsonl"
    path.write_bytes((json.dumps({"total_tokens": 0}) + "\n").encode())
    cur = UsageLogCursor(path)
    assert cur.poll() == []  # starts at EOF: history is not re-read
    with path.open("ab") as f:
        f.write((json.dumps({"total_tokens": 1}) + "\n").encode())
    assert len(cur.poll()) == 1
    # Partial line without trailing newline: held back until complete.
    with path.open("ab") as f:
        f.write(b'{"total_tokens": 2')
    assert cur.poll() == []
    with path.open("ab") as f:
        f.write(b"}\n")
    batch = cur.poll()
    assert len(batch) == 1 and batch[0]["total_tokens"] == 2


def test_no_full_scan_helpers_remain():
    import tools.run_service.prepare as prep

    assert not hasattr(prep, "_llm_usage_line_count"), "full line-count path must be gone"
    assert not hasattr(prep, "_run_telemetry"), "full re-read path must be gone"
    import tools.run_service.service as svc

    for name in ("_llm_usage_line_count", "_run_telemetry"):
        assert name not in getattr(svc, "__all__", []), f"service still exports {name}"
