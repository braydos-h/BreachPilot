"""Reject generated Python bytecode in source and wheel distributions."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Sequence


def _archive_members(distribution: Path) -> list[str]:
    if zipfile.is_zipfile(distribution):
        with zipfile.ZipFile(distribution) as archive:
            return archive.namelist()
    if tarfile.is_tarfile(distribution):
        with tarfile.open(distribution) as archive:
            return archive.getnames()
    raise ValueError(f"Unsupported Python distribution archive: {distribution}")


def _is_generated_bytecode(member: str) -> bool:
    path = PurePosixPath(member)
    return "__pycache__" in path.parts or path.suffix.lower() in {".pyc", ".pyo"}


def verify_distributions(distributions: Sequence[Path]) -> None:
    for distribution in distributions:
        members = _archive_members(distribution)
        bytecode = [member for member in members if _is_generated_bytecode(member)]
        if bytecode:
            paths = ", ".join(bytecode[:10])
            remainder = len(bytecode) - min(len(bytecode), 10)
            suffix = f" (and {remainder} more)" if remainder else ""
            raise ValueError(f"Generated Python bytecode found in {distribution}: {paths}{suffix}")
        print(f"Verified no generated Python bytecode in {distribution}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", type=Path, nargs="+", help="sdist and wheel archives to inspect")
    args = parser.parse_args(argv)
    verify_distributions(args.distributions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
