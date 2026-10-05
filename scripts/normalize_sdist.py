"""Normalize a Python source distribution tarball for repeatable builds."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Sequence

_MAX_GZIP_MTIME = (1 << 32) - 1
_SOURCE_DATE_EPOCH_ERROR = (
    f"SOURCE_DATE_EPOCH must be an integer from 0 through {_MAX_GZIP_MTIME} (the gzip timestamp field range)"
)


def _validate_member_name(name: str, *, is_directory: bool) -> str:
    if is_directory:
        name = name.rstrip("/")
    path = PurePosixPath(name)
    parts = name.split("/")
    if (
        not name
        or path.is_absolute()
        or (len(name) >= 2 and name[0].isalpha() and name[1] == ":")
        or "\x00" in name
        or "\\" in name
        or not parts
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ValueError(f"Unsafe source-distribution member path: {name!r}")
    return name


def _validate_symlink_target(member_name: str, linkname: str) -> None:
    target = PurePosixPath(linkname)
    if (
        not linkname
        or target.is_absolute()
        or (len(linkname) >= 2 and linkname[0].isalpha() and linkname[1] == ":")
        or "\x00" in linkname
        or "\\" in linkname
    ):
        raise ValueError(f"Unsafe source-distribution symlink: {member_name!r} -> {linkname!r}")

    resolved = list(PurePosixPath(member_name).parent.parts)
    root = resolved[0] if resolved else None
    for part in target.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(resolved) <= 1:
                raise ValueError(f"Source-distribution symlink escapes archive root: {member_name!r} -> {linkname!r}")
            resolved.pop()
        else:
            resolved.append(part)
    if root is not None and (not resolved or resolved[0] != root):
        raise ValueError(f"Source-distribution symlink escapes archive root: {member_name!r} -> {linkname!r}")


def _normalized_tar_info(member: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(member.name.rstrip("/") if member.isdir() else member.name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.pax_headers = {}

    if member.isdir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.size = 0
    elif member.isfile():
        info.type = tarfile.REGTYPE
        info.mode = 0o755 if member.mode & 0o111 else 0o644
        info.size = member.size
    elif member.issym():
        _validate_symlink_target(member.name, member.linkname)
        info.type = tarfile.SYMTYPE
        info.mode = 0o777
        info.linkname = member.linkname
        info.size = 0
    else:
        raise ValueError(f"Unsupported source-distribution member type: {member.name!r}")
    return info


def normalize_sdist(distribution: Path, epoch: int) -> None:
    """Rewrite an sdist with stable ordering, ownership, modes, and timestamps."""
    distribution = Path(distribution)
    if distribution.is_symlink() or not distribution.is_file():
        raise ValueError(f"Expected a regular source-distribution archive: {distribution}")
    if not 0 <= epoch <= _MAX_GZIP_MTIME:
        raise ValueError(_SOURCE_DATE_EPOCH_ERROR)

    try:
        with tarfile.open(distribution, mode="r:gz") as source:
            members = source.getmembers()
            names: set[str] = set()
            top_level_names: set[str] = set()
            for member in members:
                member.name = _validate_member_name(member.name, is_directory=member.isdir())
                if member.name in names:
                    raise ValueError(f"Duplicate source-distribution member: {member.name!r}")
                names.add(member.name)
                top_level_names.add(PurePosixPath(member.name).parts[0])
                if member.issym():
                    _validate_symlink_target(member.name, member.linkname)
            if len(top_level_names) != 1:
                raise ValueError("Source distribution must contain a single top-level package directory")
            top_level_name = next(iter(top_level_names), "")
            root_member = next((member for member in members if member.name == top_level_name), None)
            if root_member is None or not root_member.isdir():
                raise ValueError("Source distribution must contain its top-level package directory")
            ordered_members = sorted(
                members,
                key=lambda member: (len(PurePosixPath(member.name).parts), member.name),
            )

            raw_tar = io.BytesIO()
            with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.PAX_FORMAT) as normalized:
                for member in ordered_members:
                    info = _normalized_tar_info(member, epoch)
                    if member.isfile():
                        content = source.extractfile(member)
                        if content is None:
                            raise ValueError(f"Could not read source-distribution member: {member.name!r}")
                        with content:
                            normalized.addfile(info, content)
                    else:
                        normalized.addfile(info)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"Could not read source-distribution archive {distribution}: {exc}") from exc

    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=epoch, compresslevel=9) as output:
        output.write(raw_tar.getbuffer())

    original_mode = stat.S_IMODE(distribution.stat().st_mode)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{distribution.name}.", suffix=".tmp", dir=distribution.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as output:
            output.write(compressed.getbuffer())
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, distribution)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _source_date_epoch(value: str | None) -> int:
    raw = value if value is not None else os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raise ValueError("Set SOURCE_DATE_EPOCH to the source commit timestamp before normalizing distributions")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError(_SOURCE_DATE_EPOCH_ERROR) from exc
    if not 0 <= epoch <= _MAX_GZIP_MTIME:
        raise ValueError(_SOURCE_DATE_EPOCH_ERROR)
    return epoch


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", type=Path, nargs="+", help="Python source distribution .tar.gz files")
    parser.add_argument("--source-date-epoch", help="fixed Unix timestamp (defaults to SOURCE_DATE_EPOCH)")
    args = parser.parse_args(argv)
    epoch = _source_date_epoch(args.source_date_epoch)
    for distribution in args.distributions:
        normalize_sdist(distribution, epoch)
        print(f"Normalized source distribution: {distribution}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
