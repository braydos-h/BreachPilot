"""TODO 008: retry interaction documented + tested (no unbounded multiplication)."""

from __future__ import annotations

from tools.campaign.state import RetryEngine


def test_retry_engine_bounded():
    # Outer campaign cycles x inner task retries x model retries must be bounded.
    # RetryEngine caps per-module attempts; campaign max_cycles caps outer loops.
    assert RetryEngine.should_retry("SQLInjection", "timeout", 0, 3) is True
    assert RetryEngine.should_retry("SQLInjection", "timeout", 3, 3) is False
    assert RetryEngine.should_retry("SQLInjection", "timeout", 10, 3) is False
    # Permanent classes never retry (scope-blocked, false-positive).
    assert RetryEngine.should_retry("SQLInjection", "scope-blocked: denied", 0, 3) is False


def test_ownership_single_source():
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docs" / "architecture.md").read_text(encoding="utf-8")
    assert "Orchestration ownership (campaign > worker > swarm)" in text
    assert "No 5th orchestration layer" in text


def test_legacy_shim_warns_with_canonical_target():
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, "-W", "always", "-c", "import agent_loop"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "legacy" in proc.stderr.lower() or "deprecat" in proc.stderr.lower()
