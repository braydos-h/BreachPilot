"""God-file budget: significant grandfathered growth must fail, not warn.

Small drift keeps the warning annotation (a one-line fix to a god-file must
not fail CI); growth past the tolerance fails the gate so the budget has
teeth. Graduated files (under both thresholds) must leave the grandfather
list instead of lingering in the baseline.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    name = "god_file_budget_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "god_file_budget.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_classify_growth_no_change_is_silent():
    mod = _load()
    assert mod.classify_growth((1000, 50000), (1000, 50000)) is None
    assert mod.classify_growth((1000, 50000), (990, 49000)) is None


def test_classify_growth_small_drift_warns():
    mod = _load()
    assert mod.classify_growth((2637, 132994), (2650, 134000)) == "warn"


def test_classify_growth_large_loc_fails():
    mod = _load()
    assert mod.classify_growth((1000, 50000), (1200, 51000)) == "fail"


def test_classify_growth_large_bytes_fails():
    mod = _load()
    assert mod.classify_growth((1000, 50000), (1005, 90000)) == "fail"


def test_no_graduated_files_remain_grandfathered():
    """Every grandfathered file must exist and still be over budget.

    main.py was split (p2-03) below both thresholds and
    tools/api/routes/system.py was split into a package (p2-02) — both must
    graduate out of GRANDFATHERED + god-file-baseline.txt instead of
    lingering as dead config.
    """
    mod = _load()
    stale: list[str] = []
    for rel in sorted(mod.GRANDFATHERED):
        path = REPO / rel
        if not path.is_file():
            stale.append(f"{rel} (deleted — drop from GRANDFATHERED)")
            continue
        loc, size = mod._measure(path)
        if loc <= mod.LOC_LIMIT and size < mod.BYTES_LIMIT:
            stale.append(f"{rel} ({loc} LOC, {size} B — below budget, graduate it)")
    assert not stale, f"stale grandfather entries: {stale}"
