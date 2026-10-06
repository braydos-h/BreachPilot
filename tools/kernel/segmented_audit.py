"""Segmented audit-chain writer and verifier.

The single-file audit helpers and decorators remain in :mod:`tools.kernel.audit`;
that module re-exports this module's public and historical helper names.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

from tools.kernel.append_log import AppendLogWriter

# ---------------------------------------------------------------------------
# P2-08: segmented audit-chain checkpointing
# ---------------------------------------------------------------------------
# ``verify_audit_chain`` (legacy single-file, in tools/exploit_agent/policy.py)
# re-reads + re-hashes the whole ``exploit_audit.jsonl`` at session start, so
# old workspaces pay O(history) on every boot. This section is the opt-in
# segmented layout that keeps O(history) off session start WITHOUT weakening
# the integrity contract:
#
# - ``<stem>-0001.jsonl``, ``<stem>-0002.jsonl``, ... (10k records or 16MB per
#   segment). Each segment opens with a ``header`` envelope carrying
#   ``previous_segment_hash`` (the digest of the previous segment file, or
#   ``GENESIS``) and closes with a ``footer`` carrying ``segment_root_hash``
#   (sha256 over the header + data lines) plus the running record-chain
#   ``tail_hash``.
# - A ``<stem>.checkpoint.json`` records per-segment {digest, mtime_ns, size,
#   root_hash, records, tail_hash}. Startup verifies the active tail fully
#   and checks sealed segments against recorded digests (one streaming hash,
#   no JSON parse) unless mtime/size changed -- then that segment is
#   rescanned. A missing/corrupt checkpoint forces a full rescan.
# - Tamper-evidence comes from the CHAIN LINKS, not just per-segment
#   digests: segment N+1's header pins digest(N), verified against freshly
#   computed digests (never the checkpoint's values), so rewriting a segment
#   AND the checkpoint still breaks the next header. Record-level
#   hash/prev_hash linkage is threaded across segments on full passes, so
#   surgical edits cascade into a mismatch at the next chained row.
# - Rotation is crash-safe: footer line + fsync, then the checkpoint is
#   rewritten atomically (temp + fsync + rename + dir fsync). A crash leaves
#   either a sealed segment the next startup rescans, or a footerless tail
#   that is verified-or-quarantined -- never silently truncated.
# - Segments + checkpoint are 0o600.
#
# ``verify_audit_chain()`` (policy.py) is intentionally untouched and stays
# backward compatible for the legacy single-file layout.

SEGMENT_MAX_RECORDS = 10_000
SEGMENT_MAX_BYTES = 16 * 1024 * 1024
SEGMENT_CHECKPOINT_VERSION = 1
_GENESIS_SEGMENT_HASH = "GENESIS"

_SEGMENT_ENVELOPE_KEY = "segment_record"
_SEGMENT_HEADER = "header"
_SEGMENT_FOOTER = "footer"

_seg_log = logging.getLogger("tools.kernel.audit")


class _SegmentEntry(TypedDict):
    digest: str
    root_hash: str
    records: int
    bytes: int
    tail_hash: str
    mtime_ns: int
    size: int


def audit_segment_path(base_path: Path | str, index: int) -> Path:
    """Path of segment ``index`` (1-based) for a segmented log ``base_path``."""
    base = Path(base_path)
    return base.parent / f"{base.stem}-{index:04d}{base.suffix}"


def audit_checkpoint_path(base_path: Path | str) -> Path:
    """Path of the checkpoint file recording verified segment digests."""
    base = Path(base_path)
    return base.parent / f"{base.stem}.checkpoint.json"


def _segment_index_rx(base: Path) -> "re.Pattern[str]":
    return re.compile(rf"^{re.escape(base.stem)}-(\d{{4}}){re.escape(base.suffix)}$")


def _list_segment_indexes(base_path: Path | str) -> list[int]:
    """Sorted segment indexes present on disk (quarantine files excluded)."""
    base = Path(base_path)
    rx = _segment_index_rx(base)
    try:
        names = [p.name for p in base.parent.glob(f"{base.stem}-*{base.suffix}")]
    except OSError:
        return []
    indexes: list[int] = []
    for name in names:
        match = rx.fullmatch(name)
        if match:
            indexes.append(int(match.group(1)))
    return sorted(indexes)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _split_complete_lines(raw: bytes) -> list[bytes] | None:
    """Split file bytes into complete lines, or None on a partial tail.

    Every complete line ends with ``\\n``; a trailing fragment without one
    means the file was torn mid-write (crash) and must be quarantined, never
    silently truncated.
    """
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        return None
    return raw.split(b"\n")[:-1]


def _parse_envelope(line: bytes, kind: str, index: int) -> tuple[dict[str, Any] | None, str]:
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return None, f"segment {index:04d}: {kind} is not valid JSON: {exc}"
    if not isinstance(obj, dict) or obj.get(_SEGMENT_ENVELOPE_KEY) != kind:
        return None, f"segment {index:04d}: missing {kind} envelope"
    if obj.get("segment") != index:
        return None, f"segment {index:04d}: {kind} names segment {obj.get('segment')!r}"
    return obj, ""


def _verify_chained_objects(objs: list[Any], start_prev: str, label: str) -> tuple[bool, str, str]:
    """Thread record-level hash/prev_hash linkage (mirrors verify_audit_chain).

    Rows carrying ``hash`` are recomputed (canonical JSON excluding ``hash``)
    and linked; rows without ``hash`` are skipped unless they carry a
    mismatched ``prev_hash``. Returns (ok, reason, end_prev).
    """
    running = start_prev
    for pos, obj in enumerate(objs, start=1):
        if not isinstance(obj, dict):
            return False, f"{label}: record {pos} is not a JSON object", running
        rec_hash = obj.get("hash", "")
        if not rec_hash:
            prev_hash = obj.get("prev_hash", "")
            if prev_hash and prev_hash != running:
                return (
                    False,
                    (
                        f"{label}: record {pos} prev_hash mismatch (chain broken, "
                        f"expected {str(running)[:12]!r}, got {str(prev_hash)[:12]!r})"
                    ),
                    running,
                )
            continue
        prev_hash = obj.get("prev_hash", "")
        if prev_hash != running:
            return (
                False,
                (
                    f"{label}: record {pos} prev_hash mismatch (chain broken, "
                    f"expected {str(running)[:12]!r}, got {str(prev_hash)[:12]!r})"
                ),
                running,
            )
        payload = {k: v for k, v in obj.items() if k != "hash"}
        canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=True)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if rec_hash != expected:
            return (
                False,
                (
                    f"{label}: record {pos} hash mismatch (entry tampered with, "
                    f"expected {expected[:12]!r}, got {str(rec_hash)[:12]!r})"
                ),
                running,
            )
        running = str(rec_hash)
    return True, f"{label}: chain ok", running


def _load_checkpoint(base_path: Path | str) -> dict[str, Any] | None:
    """Load the checkpoint payload, or None when missing/corrupt (→ rescan)."""
    path = audit_checkpoint_path(base_path)
    try:
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("version") != SEGMENT_CHECKPOINT_VERSION:
        return None
    segments = raw.get("segments")
    if not isinstance(segments, dict):
        return None
    return raw


def _write_checkpoint_atomically(base_path: Path | str, payload: dict[str, Any]) -> None:
    """Write the checkpoint via temp + fsync + rename + dir fsync (0o600)."""
    path = audit_checkpoint_path(base_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, default=str))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def quarantine_segment(path: Path | str) -> Path:
    """Rename a corrupt tail aside for forensics. Never deletes data."""
    src = Path(path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = src.parent / f"{src.stem}.quarantined-{stamp}{src.suffix}"
    src.rename(dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    _seg_log.warning("quarantined corrupt audit segment %s -> %s", src, dest)
    return dest


def _rescan_sealed_segment(path: Path, index: int, start_prev: str) -> tuple[bool, str, str, str, str]:
    """Full parse of a sealed segment. Returns (ok, reason, root, digest, tail)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return False, f"segment {index:04d}: unreadable: {exc}", "", "", start_prev
    blines = _split_complete_lines(raw)
    if blines is None:
        return False, f"segment {index:04d}: truncated (missing trailing newline)", "", "", start_prev
    if len(blines) < 2:
        return False, f"segment {index:04d}: missing header/footer", "", "", start_prev
    header, reason = _parse_envelope(blines[0], _SEGMENT_HEADER, index)
    if header is None:
        return False, reason, "", "", start_prev
    footer, reason = _parse_envelope(blines[-1], _SEGMENT_FOOTER, index)
    if footer is None:
        return False, reason, "", "", start_prev
    root = hashlib.sha256()
    for line in blines[:-1]:
        root.update(line + b"\n")
    root_hex = root.hexdigest()
    if footer.get("segment_root_hash") != root_hex:
        return False, f"segment {index:04d}: root hash mismatch (content tampered)", "", "", start_prev
    data = blines[1:-1]
    if footer.get("records") != len(data):
        return False, f"segment {index:04d}: record count mismatch (truncated/spliced)", "", "", start_prev
    objs: list[Any] = []
    for pos, line in enumerate(data, start=1):
        try:
            objs.append(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            return False, f"segment {index:04d}: record {pos} is not valid JSON: {exc}", "", "", start_prev
    ok, reason, tail = _verify_chained_objects(objs, start_prev, f"segment {index:04d}")
    if not ok:
        return False, reason, "", "", start_prev
    digest = hashlib.sha256(raw).hexdigest()
    return True, f"segment {index:04d}: rescanned ({len(data)} records)", root_hex, digest, tail


def verify_segmented_chain(base_path: Path | str) -> tuple[bool, str]:
    """Verify a segmented audit log with O(tail) startup cost.

    Sealed segments whose mtime/size match the checkpoint are checked by a
    single streaming digest (no JSON parse); any metadata change, checkpoint
    mismatch, or missing checkpoint triggers a full rescan of that segment.
    The active tail is always fully parsed. Cross-segment links use freshly
    computed digests -- never checkpoint values -- so rewriting a segment
    AND the checkpoint still breaks the next header. Read-only: never
    quarantines or mutates; the writer does that at startup.
    """
    base = Path(base_path)
    indexes = _list_segment_indexes(base)
    if not indexes:
        return True, "no segments"
    if indexes != list(range(1, len(indexes) + 1)):
        return False, f"segment gap: found {indexes}"
    checkpoint = _load_checkpoint(base)
    entries: dict[str, Any] = checkpoint.get("segments", {}) if checkpoint else {}
    if not isinstance(entries, dict):
        entries = {}
    full_rescan = checkpoint is None
    try:
        fresh = {i: _sha256_file(audit_segment_path(base, i)) for i in indexes}
    except OSError as exc:
        return False, f"segment unreadable: {exc}"
    # Cross-segment links first (fresh digests only).
    last = indexes[-1]
    for i in indexes:
        seg_i = audit_segment_path(base, i)
        try:
            raw_i = seg_i.read_bytes()
        except OSError as exc:
            return False, f"segment {i:04d}: unreadable: {exc}"
        if not raw_i:
            if i != last:
                return False, f"segment {i:04d}: empty (missing header)"
            continue  # Empty active tail: no header to link yet; checked below.
        header, reason = _parse_envelope(raw_i.split(b"\n")[0], _SEGMENT_HEADER, i)
        if header is None:
            return False, reason
        expected_prev = _GENESIS_SEGMENT_HASH if i == 1 else fresh[i - 1]
        if header.get("previous_segment_hash") != expected_prev:
            return False, (
                f"segment {i:04d}: previous_segment_hash mismatch (chain broken; "
                "segment rewrite detected even if the checkpoint was updated)"
            )
    # Sealed content: fast digest path or full rescan.
    running = ""
    fast = 0
    rescanned = 0
    try:
        last_blob = audit_segment_path(base, last).read_bytes().rstrip(b"\n").split(b"\n")[-1]
    except OSError as exc:
        return False, f"segment {last:04d}: unreadable: {exc}"
    last_sealed = False
    try:
        last_footer = json.loads(last_blob.decode("utf-8"))
        last_sealed = isinstance(last_footer, dict) and last_footer.get(_SEGMENT_ENVELOPE_KEY) == _SEGMENT_FOOTER
    except (UnicodeDecodeError, ValueError):
        last_sealed = False
    sealed = indexes if last_sealed else indexes[:-1]
    for i in sealed:
        seg = audit_segment_path(base, i)
        try:
            stat = seg.stat()
        except OSError as exc:
            return False, f"segment {i:04d}: unreadable: {exc}"
        entry = entries.get(str(i))
        use_fast = (
            checkpoint is not None
            and isinstance(entry, dict)
            and entry.get("mtime_ns") == stat.st_mtime_ns
            and entry.get("size") == stat.st_size
            and entry.get("digest") == fresh[i]
        )
        if use_fast and isinstance(entry, dict):
            # Digest covers the footer, so the recorded tail_hash is trusted.
            running = str(entry.get("tail_hash", ""))
            fast += 1
            continue
        ok, reason, _root, _digest, tail = _rescan_sealed_segment(seg, i, running)
        if not ok:
            return False, reason
        running = tail
        rescanned += 1
    if last_sealed:
        tail_records = 0
    else:
        ok, reason, running, tail_records = _verify_tail_segment(base, last, running)
        if not ok:
            return False, reason
    mode = "full rescan (no checkpoint)" if full_rescan else f"fast-path {fast}, rescanned {rescanned}"
    return (
        True,
        f"segments ok ({len(sealed)} sealed [{mode}], tail {tail_records} records across {len(indexes)} segments)",
    )


def _verify_tail_segment(base: Path, index: int, start_prev: str) -> tuple[bool, str, str, int]:
    """Fully parse the active (footerless) tail. Returns (ok, reason, tail, records)."""
    seg = audit_segment_path(base, index)
    try:
        raw = seg.read_bytes()
    except OSError as exc:
        return False, f"segment {index:04d}: unreadable: {exc}", start_prev, 0
    if not raw:
        return True, f"segment {index:04d}: empty tail", start_prev, 0
    blines = _split_complete_lines(raw)
    if blines is None:
        return False, f"segment {index:04d}: partial tail (torn write; quarantine it)", start_prev, 0
    header, reason = _parse_envelope(blines[0], _SEGMENT_HEADER, index)
    if header is None:
        return False, reason, start_prev, 0
    objs: list[Any] = []
    for pos, line in enumerate(blines[1:], start=1):
        try:
            objs.append(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            return False, f"segment {index:04d}: tail record {pos} is not valid JSON: {exc}", start_prev, 0
    ok, reason, tail = _verify_chained_objects(objs, start_prev, f"segment {index:04d} tail")
    if not ok:
        return False, reason, start_prev, 0
    return True, reason, tail, len(objs)


class SegmentedAuditWriter:
    """Crash-safe segmented append-only log (P2-08 writer side).

    Data lines pass through unchanged (schemas untouched); each segment is
    wrapped in header/footer envelopes and sealed by rotation at
    ``max_records`` or ``max_bytes``. The active segment is written through
    an :class:`AppendLogWriter` (single FD, 0o600). Startup adopts the tail
    after envelope/JSON/link checks and quarantines a partial/corrupt tail
    (rename aside, never silent truncation). One owner per base path per
    process: rotation is not safe under two live writers on one base.
    """

    def __init__(
        self,
        base_path: Path | str,
        *,
        max_records: int = SEGMENT_MAX_RECORDS,
        max_bytes: int = SEGMENT_MAX_BYTES,
        durability: str = "balanced",
    ) -> None:
        self._base = Path(base_path)
        self._max_records = max(1, int(max_records))
        self._max_bytes = max(1024, int(max_bytes))
        self._durability = durability
        self._lock = threading.Lock()
        self._base.parent.mkdir(parents=True, exist_ok=True)
        self._records = 0
        self._bytes = 0
        self._root = hashlib.sha256()
        self._last_hash = ""
        self._fresh_header: str | None = None
        indexes = _list_segment_indexes(self._base)
        self._active_index = self._adopt_or_roll(indexes)
        self._writer = AppendLogWriter(audit_segment_path(self._base, self._active_index), durability=durability)
        if self._fresh_header is not None:
            header_line = self._fresh_header
            self._fresh_header = None
            self._writer.append(header_line)
            self._writer.checkpoint()
            self._root.update(header_line.encode("utf-8"))
            self._bytes += len(header_line.encode("utf-8"))

    def _reset_state(self) -> None:
        self._records = 0
        self._bytes = 0
        self._root = hashlib.sha256()
        self._last_hash = ""
        self._fresh_header = None

    def _adopt_or_roll(self, indexes: list[int]) -> int:
        """Adopt the tail segment (quarantining corruption) or roll a new one."""
        self._reset_state()
        if not indexes:
            self._fresh_header = self._header_line(1, _GENESIS_SEGMENT_HASH)
            return 1
        last = indexes[-1]
        seg = audit_segment_path(self._base, last)
        try:
            raw = seg.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"segment {last:04d}: unreadable: {exc}") from exc
        expected_prev = _GENESIS_SEGMENT_HASH if last == 1 else _sha256_file(audit_segment_path(self._base, last - 1))

        def _fresh(index: int, prev: str) -> int:
            self._reset_state()
            self._fresh_header = self._header_line(index, prev)
            return index

        blines = _split_complete_lines(raw)
        if blines is None:
            # Torn tail (crash mid-write): quarantine, reuse the index.
            quarantine_segment(seg)
            return _fresh(last, expected_prev)
        if not blines:
            # Empty file (crash before the header): adopt as fresh.
            return _fresh(last, expected_prev)
        header, _ = _parse_envelope(blines[0], _SEGMENT_HEADER, last)
        if header is None or header.get("previous_segment_hash") != expected_prev:
            quarantine_segment(seg)
            return _fresh(last, expected_prev)
        data = blines[1:]
        if data:
            try:
                maybe_footer = json.loads(data[-1].decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            if isinstance(maybe_footer, dict) and maybe_footer.get(_SEGMENT_ENVELOPE_KEY) == _SEGMENT_FOOTER:
                # Sealed but never rolled (crash between seal and roll).
                return _fresh(last + 1, _sha256_file(seg))
        # Adopt the tail: envelope + JSON validity only (cheap); the
        # authoritative record-chain check is verify_segmented_chain at
        # session start. Adoption continues from observed content so new rows
        # can never fork from what is on disk.
        self._root.update(blines[0] + b"\n")
        self._bytes += len(blines[0]) + 1
        for line in data:
            try:
                obj = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            if not isinstance(obj, dict):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            self._root.update(line + b"\n")
            self._bytes += len(line) + 1
            self._records += 1
            if obj.get("hash"):
                self._last_hash = str(obj["hash"])
        return last

    def _header_line(self, index: int, previous: str) -> str:
        header = {
            _SEGMENT_ENVELOPE_KEY: _SEGMENT_HEADER,
            "segment": index,
            "previous_segment_hash": previous,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(header, sort_keys=True) + "\n"

    @property
    def active_index(self) -> int:
        return self._active_index

    @property
    def last_hash(self) -> str:
        """Last observed chained ``hash`` (adoption point for new rows)."""
        with self._lock:
            return self._last_hash

    def append(self, line: str) -> None:
        """Append data line(s), rotating first when the segment is full.

        Lines must be JSON objects (the envelope/rescan/chain machinery
        requires it); invalid input raises ``ValueError`` before anything is
        written, so corruption surfaces at the call site instead of as a
        quarantined tail at the next startup.
        """
        if not line.endswith("\n"):
            line += "\n"
        objs: list[dict[str, Any]] = []
        for part in line.split("\n")[:-1]:
            try:
                obj = json.loads(part)
            except ValueError as exc:
                raise ValueError(f"segmented audit log requires JSON object lines: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError("segmented audit log requires JSON object lines")
            if obj.get(_SEGMENT_ENVELOPE_KEY) in (_SEGMENT_HEADER, _SEGMENT_FOOTER):
                # Envelope-shaped data would confuse seal detection (only
                # blines[0]/blines[-1] are parsed as envelopes).
                raise ValueError("segmented audit log data lines must not use the 'segment_record' key")
            objs.append(obj)
        if not objs:
            raise ValueError("segmented audit log requires a non-empty line")
        encoded = line.encode("utf-8")
        with self._lock:
            if self._records >= self._max_records or self._bytes + len(encoded) > self._max_bytes:
                self._rotate_locked()
            self._writer.append(line)
            self._root.update(encoded)
            self._bytes += len(encoded)
            self._records += len(objs)
            for obj in objs:
                if obj.get("hash"):
                    self._last_hash = str(obj["hash"])

    def _rotate_locked(self) -> None:
        footer = {
            _SEGMENT_ENVELOPE_KEY: _SEGMENT_FOOTER,
            "segment": self._active_index,
            "segment_root_hash": self._root.hexdigest(),
            "records": self._records,
            "bytes": self._bytes,
            "tail_hash": self._last_hash,
        }
        footer_line = json.dumps(footer, sort_keys=True) + "\n"
        footer_bytes = footer_line.encode("utf-8")
        self._writer.append(footer_line)
        self._writer.checkpoint()
        self._writer.close()
        digest = self._root.copy()
        digest.update(footer_bytes)
        digest_hex = digest.hexdigest()
        stat = audit_segment_path(self._base, self._active_index).stat()
        checkpoint = _load_checkpoint(self._base) or {"version": SEGMENT_CHECKPOINT_VERSION, "segments": {}}
        segments = checkpoint.get("segments")
        if not isinstance(segments, dict):
            segments = {}
            checkpoint["segments"] = segments
        segments[str(self._active_index)] = _SegmentEntry(
            digest=digest_hex,
            root_hash=self._root.hexdigest(),
            records=self._records,
            bytes=self._bytes,
            tail_hash=self._last_hash,
            mtime_ns=stat.st_mtime_ns,
            size=stat.st_size,
        )
        new_index = self._active_index + 1
        checkpoint["active"] = new_index
        writer = AppendLogWriter(audit_segment_path(self._base, new_index), durability=self._durability)
        header_line = self._header_line(new_index, digest_hex)
        writer.append(header_line)
        writer.checkpoint()
        _write_checkpoint_atomically(self._base, checkpoint)
        self._writer = writer
        self._active_index = new_index
        self._root = hashlib.sha256(header_line.encode("utf-8"))
        self._bytes = len(header_line.encode("utf-8"))
        self._records = 0

    def checkpoint(self) -> None:
        """fsync the active tail."""
        with self._lock:
            self._writer.checkpoint()

    def close(self) -> None:
        """fsync the tail, record the checkpoint, close the FD. Idempotent."""
        with self._lock:
            if self._writer.closed:
                return
            self._writer.checkpoint()
            checkpoint = _load_checkpoint(self._base) or {"version": SEGMENT_CHECKPOINT_VERSION, "segments": {}}
            checkpoint["active"] = self._active_index
            _write_checkpoint_atomically(self._base, checkpoint)
            self._writer.close()
