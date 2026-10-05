"""JSONL event-log persistence, recovery, and indexed replay helpers."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any

_DURABILITY_MODES = ("strict", "balanced", "fast")
_FSYNC_INTERVAL_SECONDS = 0.25

# P2-01 indexed replay: `events.idx` sidecar — binary rows
# `(sequence:u64, byte_offset:u64)` checkpointed every _IDX_EVERY events by
# the writer thread. A checkpoint (S, O) means "event S+1 begins at byte
# offset O". Paged reads seek to the nearest checkpoint below the target and
# parse only the needed byte range: O(page), not O(N).
_IDX_EVERY = 256
_IDX_STRUCT = struct.Struct("<QQ")
_IDX_NAME = "events.idx"
_IDX_MAGIC = b"BPIDX1\x00\x00"
_IDX_HEADER = struct.Struct("<8sQQ")
_IDX_ORDER_SORTED = 0x01
# Events that force an fsync even in `balanced` (never lose decisions /
# terminal transitions to a crash inside the 250ms window).
_IMPORTANT_EVENT_TYPES = frozenset(
    {
        "run_finished",
        "run_failed",
        "run_checkpoint",
        "decision",
        "decision_created",
        "hitl_decision",
        "approval",
    }
)
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "interrupted"})


def _is_important_event(event_type: str, payload: Any) -> bool:
    """True when an event must survive a crash even in `balanced` mode."""
    if event_type in _IMPORTANT_EVENT_TYPES:
        return True
    if event_type == "state" and isinstance(payload, dict):
        return str(payload.get("state", "")) in _TERMINAL_STATES
    return False


def _load_index(idx_path: Path, file_size: int) -> list[tuple[int, int]] | None:
    """Load and validate checkpoints; None when missing/corrupt/stale/unsorted.

    Corrupt, truncated, or unordered sidecars are never fatal: the caller
    falls back to a full read once, then rebuilds the index. The
    ORDER_SORTED flag is required: only files the new writer produced (or
    verified-sorted rebuilds) may use O(page) seeks.
    """
    try:
        data = idx_path.read_bytes()
    except OSError:
        return None
    if len(data) < _IDX_HEADER.size or (len(data) - _IDX_HEADER.size) % _IDX_STRUCT.size != 0:
        return None
    try:
        magic, flags, _reserved = _IDX_HEADER.unpack_from(data)
    except struct.error:
        return None
    if magic != _IDX_MAGIC or not (flags & _IDX_ORDER_SORTED):
        return None
    recs = [(int(s), int(o)) for s, o in _IDX_STRUCT.iter_unpack(data[_IDX_HEADER.size :])]
    prev_s, prev_o = 0, 0
    for s, o in recs:
        if s <= prev_s or o < prev_o or o > file_size:
            return None
        prev_s, prev_o = s, o
    return recs


def _seek_for_seq(recs: list[tuple[int, int]], seq: int) -> int:
    """Byte offset from which parsing covers ``seq`` (largest checkpoint below it)."""
    offset = 0
    for s, o in recs:
        if s < seq:
            offset = o
        else:
            break
    return offset


def _parse_first_seq(path: Path) -> int | None:
    """Sequence of the first event (one line parsed)."""
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if isinstance(seq, int) and not isinstance(seq, bool):
                    return seq
                return None
    except OSError:
        return None
    return None


def _parse_last_seq(path: Path, file_size: int) -> int | None:
    """Sequence of the final non-empty event, including oversized JSONL rows.

    Walk backward in bounded blocks to locate the final record boundary, then
    read that complete record. A fixed-size tail can begin in the middle of a
    valid event and incorrectly reset sequence numbering after restart.
    """
    if file_size <= 0:
        return None
    try:
        with path.open("rb") as f:
            end = file_size
            while end > 0:
                # Find the last non-whitespace byte without assuming an
                # event-size limit. Typical files need one read; larger tail
                # records continue in fixed-size blocks.
                scan_end = end
                while scan_end > 0:
                    start = max(0, scan_end - 65536)
                    f.seek(start)
                    chunk = f.read(scan_end - start)
                    content = chunk.rstrip(b" \t\r\n")
                    if content:
                        content_end = start + len(content)
                        break
                    scan_end = start
                else:
                    return None

                # Find the newline preceding that byte; if none exists, the
                # file contains a single JSONL record.
                scan_end = content_end
                while scan_end > 0:
                    start = max(0, scan_end - 65536)
                    f.seek(start)
                    chunk = f.read(scan_end - start)
                    newline = chunk.rfind(b"\n")
                    if newline >= 0:
                        line_start = start + newline + 1
                        break
                    if start == 0:
                        line_start = 0
                        break
                    scan_end = start

                f.seek(line_start)
                try:
                    evt = json.loads(f.read(content_end - line_start).decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    evt = None
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if isinstance(seq, int) and not isinstance(seq, bool):
                    return seq
                # Preserve a prior valid sequence when the log ends in a
                # partial or malformed row, matching recovery from older logs.
                if line_start == 0:
                    return None
                end = line_start - 1
    except OSError:
        return None
    return None


def _parse_seq_range(
    path: Path, start_offset: int, want_from: int, want_to: int | None, end_size: int
) -> list[dict[str, Any]]:
    """Parse events with ``want_from <= seq < want_to`` from ``start_offset``.

    Stops at ``end_size`` (concurrent-writer snapshot) or ``want_to``.
    Assumes gapless sequencing (guaranteed by writer-side sequencing).
    """
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            f.seek(start_offset)
            while True:
                if f.tell() >= end_size:
                    break
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if not isinstance(seq, int) or isinstance(seq, bool):
                    continue
                if seq < want_from:
                    continue
                if want_to is not None and seq >= want_to:
                    break
                events.append(evt)
    except OSError:
        return events
    return events


def _empty_page() -> dict[str, Any]:
    return {
        "events": [],
        "oldest_sequence": None,
        "latest_sequence": None,
        "has_more_before": False,
        "first_returned_sequence": None,
        "last_returned_sequence": None,
        "omitted_before": 0,
        "next_before": None,
    }


def _shape_indexed_page(
    window: list[dict[str, Any]],
    oldest: int,
    latest: int,
    base_count: int,
    after: int,
    tail: int | None,
    before: int | None,
    limit: int | None,
) -> dict[str, Any]:
    """Shape a paged result from an indexed window (gapless arithmetic).

    ``base_count`` is the population the window was drawn from (``total``
    for tail pages, the ``seq < before`` count for before pages). Mirrors
    the legacy full-read branches in ``replay_page`` exactly: same keys,
    same newest-first order for ``before`` pages, same ``tail=0``-means-all
    edge.
    """
    if tail is not None:
        want = base_count if tail <= 0 else min(tail, base_count)
        events = window[-want:] if want < len(window) else list(window)
        if events:
            first_returned = events[0]["sequence"]
            last_returned = events[-1]["sequence"]
            omitted_before = base_count - len(events)
            has_more_before = omitted_before > 0
            next_before = first_returned if has_more_before else None
        else:
            first_returned = last_returned = next_before = None
            has_more_before = False
            omitted_before = 0
    elif before is not None:
        events = list(reversed(window))
        if events:
            first_returned = window[0]["sequence"]
            last_returned = window[-1]["sequence"]
            omitted_before = base_count - len(window)
            has_more_before = omitted_before > 0
            next_before = first_returned if has_more_before else None
        else:
            first_returned = last_returned = next_before = None
            has_more_before = False
            omitted_before = 0
    else:
        events = list(window)
        if events:
            first_returned = events[0]["sequence"]
            last_returned = events[-1]["sequence"]
        else:
            first_returned = last_returned = None
        has_more_before = False
        omitted_before = 0
        next_before = None
    return {
        "events": events,
        "oldest_sequence": oldest,
        "latest_sequence": latest,
        "has_more_before": has_more_before,
        "first_returned_sequence": first_returned,
        "last_returned_sequence": last_returned,
        "omitted_before": omitted_before,
        "next_before": next_before,
    }


def _open_index_for_append(idx_path: Path) -> Any:
    """Open the sidecar for appends, (re)writing the header when needed.

    A corrupt/foreign file is truncated back to a fresh header so the writer
    never grows garbage the reader would reject.
    """
    try:
        size = idx_path.stat().st_size
    except OSError:
        size = 0
    if size == 0:
        handle = idx_path.open("ab")
        try:
            handle.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
            handle.flush()
        except OSError:
            pass
        return handle
    try:
        head = idx_path.read_bytes()[: _IDX_HEADER.size]
        magic, _flags, _reserved = _IDX_HEADER.unpack(head)
        if magic == _IDX_MAGIC:
            return idx_path.open("ab")
    except (OSError, struct.error):
        pass
    handle = idx_path.open("wb")
    try:
        handle.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
        handle.flush()
    except OSError:
        pass
    return handle


def _read_jsonl_events(path: Path) -> list[dict[str, Any]]:
    """Read the full ordered list of parsed events from ``events.jsonl``."""
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(evt)
    # Older event logs could contain out-of-order rows because sequence
    # assignment and appends were separate. Keep sorting for those logs; the
    # current single writer persists rows in sequence order.
    try:
        events.sort(key=lambda e: e.get("sequence", 0) if isinstance(e, dict) else 0)
    except TypeError:
        pass
    return events


def _rebuild_index(path: Path) -> None:
    """Full scan once + atomic idx rewrite (only when file order is sorted).

    Legacy files without a sidecar take one slow read, then get an index
    for every later page. Unsorted legacy files are left alone (slow path
    stays correct for them).
    """
    idx_path = path.parent / _IDX_NAME
    try:
        seqs: list[tuple[int, int]] = []  # (sequence, end_offset)
        with path.open("rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                end = f.tell()
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if isinstance(seq, int) and not isinstance(seq, bool):
                    seqs.append((seq, end))
    except OSError:
        return
    if not seqs:
        return
    if any(b < a for a, b in zip([s for s, _ in seqs], [s for s, _ in seqs][1:])):
        return  # unordered legacy file: keep the correct slow path
    try:
        tmp = idx_path.with_name(_IDX_NAME + ".tmp")
        with tmp.open("wb") as out:
            out.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
            for seq, end in seqs:
                if seq % _IDX_EVERY == 0:
                    out.write(_IDX_STRUCT.pack(seq, end))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, idx_path)
    except OSError:
        pass


def _read_indexed_slice(
    path: Path, after: int, tail: int | None, before: int | None, limit: int | None
) -> dict[str, Any] | None:
    """O(page) paged read via ``events.idx``; None when the index is unusable.

    Runs off the event loop (blocking file I/O). Snapshots the file size
    at entry so a concurrently appending writer cannot corrupt the read.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return _empty_page()
    if size == 0:
        return _empty_page()
    recs = _load_index(path.parent / _IDX_NAME, size)
    if recs is None:
        return None
    oldest = _parse_first_seq(path)
    latest = _parse_last_seq(path, size)
    if oldest is None or latest is None or oldest != 1 or latest < oldest:
        # Truncated/rotated or unreadable: the index no longer describes
        # this file — slow path (which also rebuilds when sortable).
        return None
    total = latest - oldest + 1
    if tail is not None:
        want = total if tail <= 0 else min(tail, total)
        start = latest - want + 1
        window = _parse_seq_range(path, _seek_for_seq(recs, start), start, latest + 1, size)
        return _shape_indexed_page(window, oldest, latest, total, after, tail, before, limit)
    if before is not None:
        hi = min(before, latest + 1)
        base_count = max(0, hi - oldest)
        want = base_count if limit is None else min(limit, base_count)
        start = hi - want
        window = _parse_seq_range(path, _seek_for_seq(recs, start), start, hi, size)
        return _shape_indexed_page(window, oldest, latest, base_count, after, tail, before, limit)
    window = _parse_seq_range(path, _seek_for_seq(recs, after + 1), after + 1, latest + 1, size)
    return _shape_indexed_page(window, oldest, latest, len(window), after, tail, before, limit)
