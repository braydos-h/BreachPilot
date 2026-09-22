"""God-file maintainability budget: fail CI on NEW oversized modules.

Policy (see task spec — OR thresholds, not AND):

- Any non-grandfathered Python file under ``tools/`` or the repo root
  exceeding EITHER ~1000 LOC OR 72kB fails the gate. Split the module
  along logical responsibilities instead — never to satisfy the metric
  alone (no arbitrary splits of cohesive modules).
- Files already over the budget when the gate landed are explicitly
  grandfathered below with their baselined size. Growth of a grandfathered
  file is tracked against ``god-file-baseline.txt`` and reported as a CI
  ``::warning::`` annotation (visible, non-blocking); shrinking one is
  celebrated silently. Refresh with ``--update`` after an extraction.

Scope is production code (``tools/`` + root ``*.py``). ``tests/`` grows
with coverage by design, ``legacy/`` is frozen, and ``skills/`` vendors
standalone agent scripts — none are gated.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "god-file-baseline.txt"

LOC_LIMIT = 1000
BYTES_LIMIT = 600 * 120  # 72kB — independent of the LOC limit (OR, not AND)

# Explicitly documented grandfather list: every file already over budget when
# the OR-gate landed. Do NOT add new files here to dodge the gate — extract a
# logical submodule instead. Removing entries as files shrink below budget is
# encouraged.
GRANDFATHERED = frozenset(
    {
        "tools/exploit_agent/runner/_impl.py",
        "tools/api/routes/system.py",
        "tools/eval_harness.py",
        "tools/enhanced_reporting.py",
        "tools/web_researcher.py",
        "tools/attack_modules/modules/ics_iot.py",
        "tools/browser/playwright_backend.py",
        "tools/providers/opencode_go_provider.py",
        "tools/attack_ui.py",
        "tools/mcp_tools/domain.py",
        "tools/recon/enumerator.py",
        "tools/persistent_session_manager.py",
        "tools/mcp_tools/metasploit.py",
        "tools/metasploit_bridge.py",
        "tools/mcp_tools/modules/web.py",
        "outcome_judge.py",
        "tools/sandbox/remediation.py",
        "tools/doctor.py",
        "tools/api/routes/runs.py",
    }
)


def _measure(path: pathlib.Path) -> tuple[int, int]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0, 0
    return len(text.splitlines()), path.stat().st_size


def _candidates() -> list[pathlib.Path]:
    paths = list((REPO_ROOT / "tools").rglob("*.py"))
    paths.extend(p for p in REPO_ROOT.glob("*.py") if p.is_file())
    return sorted({p for p in paths if "__pycache__" not in p.parts})


def load_baseline() -> dict[str, tuple[int, int]]:
    baseline: dict[str, tuple[int, int]] = {}
    if not BASELINE_PATH.exists():
        return baseline
    for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        baseline[parts[0]] = (int(parts[1]), int(parts[2]))
    return baseline


def classify_growth(old: tuple[int, int], new: tuple[int, int]) -> str | None:
    """Classify grandfathered-file drift as None (silent), "warn", or "fail".

    Small drift warns (a one-line fix must not fail CI); growth past
    tolerance fails so the budget has teeth:

    - LOC growth beyond ``max(20, 10% of baseline LOC)`` fails.
    - Bytes growth beyond ``max(4096, 25% of baseline bytes)`` fails.

    Anything else that grew warns; shrinks and ties are silent.
    """
    old_loc, old_size = old
    new_loc, new_size = new
    loc_delta = new_loc - old_loc
    size_delta = new_size - old_size
    if loc_delta > max(20, old_loc // 10) or size_delta > max(4096, old_size // 4):
        return "fail"
    if loc_delta > 0 or size_delta > 0:
        return "warn"
    return None


def write_baseline(entries: dict[str, tuple[int, int]]) -> None:
    lines = [
        "# God-file baseline — see scripts/god_file_budget.py.",
        "# Grandfathered files only: `path loc bytes`. Generated with --update.",
        "# Growth vs this baseline is reported as a CI warning annotation.",
    ]
    lines.extend(f"{path} {loc} {size}" for path, (loc, size) in sorted(entries.items()))
    BASELINE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    baseline = load_baseline()
    current: dict[str, tuple[int, int]] = {}
    violations: list[str] = []
    for path in _candidates():
        rel = path.relative_to(REPO_ROOT).as_posix()
        loc, size = _measure(path)
        if rel in GRANDFATHERED:
            current[rel] = (loc, size)
            continue
        reasons = []
        if loc > LOC_LIMIT:
            reasons.append(f"{loc} LOC > {LOC_LIMIT}")
        if size >= BYTES_LIMIT:
            reasons.append(f"{size} B >= {BYTES_LIMIT}")
        if reasons:
            violations.append(f"{rel} ({'; '.join(reasons)})")
    if "--update" in argv:
        write_baseline(current)
        print(f"god-file baseline rewritten: {len(current)} grandfathered files")
        return 0
    # Grandfathered growth tracking: small drift keeps the warning annotation
    # (a one-line fix to a god-file must not fail CI); growth past the
    # classify_growth tolerance fails the gate. Extract a logical submodule
    # to shrink one, then --update the baseline.
    for rel in sorted(current):
        loc, size = current[rel]
        old_loc, old_size = baseline.get(rel, (loc, size))
        verdict = classify_growth((old_loc, old_size), (loc, size))
        if verdict == "fail":
            print(
                f"::error file={rel},line=1::grandfathered god-file grew significantly "
                f"({old_loc} LOC/{old_size} B -> {loc} LOC/{size} B). "
                "Extract a logical submodule instead of growing it further."
            )
            violations.append(
                f"{rel} grew significantly ({old_loc} LOC/{old_size} B -> {loc} LOC/{size} B)"
            )
        elif verdict == "warn":
            print(
                f"::warning file={rel},line=1::grandfathered god-file grew "
                f"({old_loc} LOC/{old_size} B -> {loc} LOC/{size} B). "
                "Extract a logical submodule instead of growing it further."
            )
        elif (loc, size) != (old_loc, old_size):
            print(f"grandfathered {rel} shrank ({old_loc} LOC -> {loc} LOC) — nice.")
    if violations:
        print("god-file budget FAILED:")
        for violation in violations:
            print(f"  - {violation}")
        print("Extract logical responsibilities into submodules; do not split cohesively just to meter-dodge.")
        return 1
    print(f"god-file budget passed: {len(current)} grandfathered files tracked, no new violations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
