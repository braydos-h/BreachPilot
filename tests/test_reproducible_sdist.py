"""Checks that sdist normalization preserves payloads and removes build-time metadata."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scripts.normalize_sdist import _MAX_GZIP_MTIME, _source_date_epoch, normalize_sdist

EPOCH = 1_700_000_000
ROOT = "breachpilot-0.68.4"


def _write_sdist(path: Path, *, reverse: bool, timestamp: int, gzip_name: str) -> None:
    entries: list[tuple[str, bytes, int, str | None]] = [
        (ROOT, b"", 0o700, "dir"),
        (f"{ROOT}/README.md", b"package documentation\n", 0o600, None),
        (f"{ROOT}/tools", b"", 0o700, "dir"),
        (f"{ROOT}/tools/run.sh", b"#!/bin/sh\nexit 0\n", 0o755, None),
        (f"{ROOT}/docs", b"", 0o700, "dir"),
        (f"{ROOT}/docs/readme-link", b"", 0o777, "../README.md"),
    ]
    if reverse:
        entries.reverse()

    with path.open("wb") as raw:
        with gzip.GzipFile(filename=gzip_name, mode="wb", fileobj=raw, mtime=timestamp) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, content, mode, entry_type in entries:
                    info = tarfile.TarInfo(name)
                    info.mode = mode
                    info.uid = 123
                    info.gid = 456
                    info.uname = "builder"
                    info.gname = "builders"
                    info.mtime = timestamp
                    info.pax_headers = {"atime": str(timestamp), "ctime": str(timestamp)}
                    if entry_type == "dir":
                        info.type = tarfile.DIRTYPE
                    elif entry_type is None:
                        info.type = tarfile.REGTYPE
                        info.size = len(content)
                    else:
                        info.type = tarfile.SYMTYPE
                        info.linkname = entry_type
                    archive.addfile(info, io.BytesIO(content) if entry_type is None else None)


def test_sdist_normalization_is_independent_of_order_and_build_timestamps(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, reverse=False, timestamp=1_700_000_001, gzip_name="first.tar")
    _write_sdist(second, reverse=True, timestamp=1_800_000_001, gzip_name="second.tar")

    normalize_sdist(first, EPOCH)
    normalize_sdist(second, EPOCH)

    assert first.read_bytes() == second.read_bytes()
    normalized_bytes = first.read_bytes()
    normalize_sdist(first, EPOCH)
    assert first.read_bytes() == normalized_bytes
    with gzip.open(first, "rb") as compressed:
        compressed.read(1)
        assert compressed.mtime == EPOCH
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == [
            ROOT,
            f"{ROOT}/README.md",
            f"{ROOT}/docs",
            f"{ROOT}/tools",
            f"{ROOT}/docs/readme-link",
            f"{ROOT}/tools/run.sh",
        ]
        by_name = {member.name: member for member in members}
        assert all(member.mtime == EPOCH for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert all(member.uname == "" and member.gname == "" for member in members)
        assert by_name[f"{ROOT}/README.md"].mode == 0o644
        assert by_name[f"{ROOT}/tools/run.sh"].mode == 0o755
        assert by_name[f"{ROOT}/docs/readme-link"].linkname == "../README.md"
        assert archive.extractfile(by_name[f"{ROOT}/README.md"]).read() == b"package documentation\n"


@pytest.mark.parametrize("member_name", [f"{ROOT}/../../outside.txt", "C:/outside.txt"])
def test_sdist_normalization_rejects_unsafe_member_names(tmp_path: Path, member_name: str) -> None:
    archive_path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        info = tarfile.TarInfo(member_name)
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(ValueError, match="Unsafe source-distribution member path"):
        normalize_sdist(archive_path, EPOCH)


def test_sdist_normalization_rejects_symlinks_outside_archive_root(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe-link.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        root = tarfile.TarInfo(ROOT)
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        link = tarfile.TarInfo(f"{ROOT}/outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(ValueError, match="escapes archive root"):
        normalize_sdist(archive_path, EPOCH)


def test_sdist_normalization_rejects_epochs_outside_gzip_timestamp_range(tmp_path: Path) -> None:
    archive_path = tmp_path / "epoch-boundary.tar.gz"
    _write_sdist(archive_path, reverse=False, timestamp=EPOCH, gzip_name="epoch-boundary.tar")
    original_bytes = archive_path.read_bytes()

    with pytest.raises(ValueError, match="gzip timestamp field range"):
        normalize_sdist(archive_path, _MAX_GZIP_MTIME + 1)

    assert archive_path.read_bytes() == original_bytes


def test_source_date_epoch_parser_rejects_value_above_gzip_timestamp_range() -> None:
    assert _source_date_epoch(str(_MAX_GZIP_MTIME)) == _MAX_GZIP_MTIME

    with pytest.raises(ValueError, match="gzip timestamp field range"):
        _source_date_epoch(str(_MAX_GZIP_MTIME + 1))
