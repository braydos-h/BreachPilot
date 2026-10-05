"""Regression coverage for the segmented audit module extraction."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


def _chained_record(index: int, previous_hash: str) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": f"t{index}",
        "target_ip": "10.0.0.50",
        "action": "run_exploit_terminal",
        "approved": True,
        "status": "completed",
        "prev_hash": previous_hash,
    }
    canonical = json.dumps(record, sort_keys=True, default=str, ensure_ascii=True)
    record["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return record


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_segmented_audit_compat_imports_rotation_and_modes(tmp_path: Path):
    import tools.kernel.audit as audit
    import tools.kernel.segmented_audit as segmented
    import tools.mcp_shared as mcp_shared

    # Historical imports stay valid while the canonical implementation moves.
    assert audit.SegmentedAuditWriter is segmented.SegmentedAuditWriter
    assert audit.AppendLogWriter is segmented.AppendLogWriter
    assert audit.audit_segment_path is segmented.audit_segment_path
    assert audit.audit_checkpoint_path is segmented.audit_checkpoint_path
    assert audit.verify_segmented_chain is segmented.verify_segmented_chain
    for name in (
        "_BLOCKED_RESULT_MARKERS",
        "_REDACTED",
        "_SECRET_ARG_NAMES",
        "_WHOLESALE_REDACT_FIELDS",
        "_audit_log",
        "_extract_audit_target",
        "_mask_secret_content",
        "_redact_args",
        "_redact_nested",
        "_result_is_blocked",
        "make_audit_tool",
        "make_require_allowlist",
    ):
        assert getattr(mcp_shared, name) is getattr(audit, name)

    base = tmp_path / "exploit_audit.jsonl"
    writer = audit.SegmentedAuditWriter(base, max_records=1)
    first = _chained_record(1, "")
    second = _chained_record(2, str(first["hash"]))
    try:
        writer.append(json.dumps(first) + "\n")
        writer.append(json.dumps(second) + "\n")
        assert writer.active_index == 2
        assert writer.last_hash == second["hash"]
    finally:
        writer.close()

    first_segment = audit.audit_segment_path(base, 1)
    active_segment = audit.audit_segment_path(base, 2)
    checkpoint = audit.audit_checkpoint_path(base)
    assert json.loads(first_segment.read_text(encoding="utf-8").splitlines()[1]) == first
    assert json.loads(active_segment.read_text(encoding="utf-8").splitlines()[1]) == second
    assert all(_mode(path) == 0o600 for path in (first_segment, active_segment, checkpoint))

    valid, reason = audit.verify_segmented_chain(base)
    assert valid, reason
    assert "2 segments" in reason


def test_segmented_audit_reopen_quarantines_torn_tail(tmp_path: Path):
    from tools.kernel.audit import SegmentedAuditWriter, audit_segment_path, verify_segmented_chain

    base = tmp_path / "exploit_audit.jsonl"
    writer = SegmentedAuditWriter(base, max_records=1)
    writer.append('{"tool_name":"first","status":"completed"}\n')
    writer.append('{"tool_name":"second","status":"completed"}\n')
    writer.close()

    active_tail = audit_segment_path(base, 2)
    with active_tail.open("ab") as handle:
        handle.write(b'{"torn":')

    recovered = SegmentedAuditWriter(base, max_records=1)
    recovered.close()

    quarantined = list(tmp_path.glob("exploit_audit-0002.quarantined-*.jsonl"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes().endswith(b'{"torn":')
    assert _mode(quarantined[0]) == 0o600
    assert b'{"torn":' not in active_tail.read_bytes()
    valid, reason = verify_segmented_chain(base)
    assert valid, reason


def test_segmented_audit_detects_sealed_record_tampering_even_if_next_link_is_rewritten(tmp_path: Path):
    from tools.kernel.audit import SegmentedAuditWriter, audit_segment_path, verify_segmented_chain

    base = tmp_path / "exploit_audit.jsonl"
    writer = SegmentedAuditWriter(base, max_records=1)
    first = _chained_record(1, "")
    second = _chained_record(2, str(first["hash"]))
    writer.append(json.dumps(first) + "\n")
    writer.append(json.dumps(second) + "\n")  # seals segment 1 and creates active segment 2
    writer.close()

    segment_1 = audit_segment_path(base, 1)
    segment_2 = audit_segment_path(base, 2)
    original = segment_1.read_bytes()
    changed = original.replace(b"10.0.0.50", b"10.0.0.51", 1)
    assert changed != original
    segment_1.write_bytes(changed)

    lines = segment_2.read_bytes().splitlines()
    header = json.loads(lines[0])
    header["previous_segment_hash"] = hashlib.sha256(changed).hexdigest()
    lines[0] = json.dumps(header, sort_keys=True).encode("utf-8")
    segment_2.write_bytes(b"\n".join(lines) + b"\n")

    valid, reason = verify_segmented_chain(base)

    assert not valid
    assert "root hash mismatch" in reason


def test_segmented_audit_rejects_broken_sealed_segment_link(tmp_path: Path):
    from tools.kernel.audit import SegmentedAuditWriter, audit_segment_path, verify_segmented_chain

    base = tmp_path / "exploit_audit.jsonl"
    writer = SegmentedAuditWriter(base, max_records=1)
    writer.append('{"tool_name":"first","status":"completed"}\n')
    writer.append('{"tool_name":"second","status":"completed"}\n')
    writer.close()

    active_segment = audit_segment_path(base, 2)
    lines = active_segment.read_bytes().splitlines()
    header = json.loads(lines[0])
    header["previous_segment_hash"] = "0" * 64
    lines[0] = json.dumps(header, sort_keys=True).encode("utf-8")
    active_segment.write_bytes(b"\n".join(lines) + b"\n")

    valid, reason = verify_segmented_chain(base)

    assert not valid
    assert "previous_segment_hash mismatch" in reason
