"""TODO 020: generated source-map exists and CI enforces freshness."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_source_map_generated_and_fresh():
    import subprocess
    import sys

    assert (REPO / "docs" / "generated" / "source-map.md").exists()
    proc = subprocess.run(
        [sys.executable, "scripts/generate_source_map.py", "--check"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"source-map drift:\n{proc.stdout}\n{proc.stderr}"


def test_every_root_shim_has_row():
    text = (REPO / "docs" / "generated" / "source-map.md").read_text(encoding="utf-8")
    for shim in ("agent_loop", "legacy.agent_loop", "remove in 0.71"):
        assert shim in text
