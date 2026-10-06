"""Validate that requirements.txt matches BreachPilot's declared install ranges."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def _requirement_key(raw: str) -> tuple[str, tuple[str, ...], str, str]:
    requirement = Requirement(raw)
    specifiers = tuple(sorted(str(specifier) for specifier in requirement.specifier))
    marker = str(requirement.marker) if requirement.marker is not None else ""
    return canonicalize_name(requirement.name), specifiers, marker, requirement.url or ""


def check_requirements_sync(pyproject_path: Path, requirements_path: Path) -> list[str]:
    """Return declaration mismatches; the browser extra is intentionally optional."""
    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    declared = [*project["project"].get("dependencies", [])]
    optional = project["project"].get("optional-dependencies", {})
    for extra in ("ollama", "dev"):
        declared.extend(optional.get(extra, []))

    expected: dict[str, tuple[str, tuple[str, ...], str, str]] = {}
    findings: list[str] = []
    for raw in declared:
        key = _requirement_key(raw)
        name = key[0]
        previous = expected.get(name)
        if previous is not None and previous != key:
            findings.append(f"pyproject.toml declares conflicting ranges for {name}: {previous} vs {key}")
        expected[name] = key

    actual: dict[str, tuple[str, tuple[str, ...], str, str]] = {}
    for line_number, line in enumerate(requirements_path.read_text(encoding="utf-8").splitlines(), 1):
        raw = line.partition("#")[0].strip()
        if not raw:
            continue
        try:
            key = _requirement_key(raw)
        except Exception as exc:  # noqa: BLE001 -- report a useful line-specific config error
            findings.append(f"requirements.txt:{line_number}: invalid requirement {raw!r}: {exc}")
            continue
        name = key[0]
        if name in actual:
            findings.append(f"requirements.txt:{line_number}: duplicate declaration for {name}")
        actual[name] = key

    for name in sorted(expected.keys() - actual.keys()):
        findings.append(f"requirements.txt is missing {name} declared by pyproject.toml")
    for name in sorted(actual.keys() - expected.keys()):
        findings.append(f"requirements.txt declares {name}, which is not in core/ollama/dev extras")
    for name in sorted(expected.keys() & actual.keys()):
        if expected[name] != actual[name]:
            findings.append(f"requirements.txt range for {name} does not match pyproject.toml")
    return findings


def main() -> int:
    findings = check_requirements_sync(Path("pyproject.toml"), Path("requirements.txt"))
    if findings:
        print("ERROR: requirements.txt and pyproject.toml drift:")
        print("\n".join(findings))
        return 1
    print("Requirements sync: names, markers, and version ranges match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
