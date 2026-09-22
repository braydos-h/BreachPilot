"""MCP exploit-server boot must stay lazy.

Importing ``mcp_exploit_server`` (what every test does) must not eagerly pull
the heavy research/recon chains (``tools.web_researcher``,
``tools.exploit_search``, ``tools.cve_lookup``) into ``sys.modules`` — those
are only needed inside ``main()`` via the ``tools.mcp_shared`` builders, which
already lazy-import them. Eager imports inflate the 30s MCP boot budget and
every test's import time.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_mcp_exploit_server_import_stays_lazy():
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, mcp_exploit_server; "
            "heavy = [m for m in sys.modules if m in "
            '("tools.web_researcher", "tools.exploit_search", "tools.cve_lookup")]; '
            "print(','.join(sorted(heavy))); "
            "assert not heavy, f'eager heavy imports: {heavy}'",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"lazy-import probe failed: {proc.stderr[-2000:]}"


def test_create_mcp_server_still_importable():
    from mcp_exploit_server import create_mcp_server

    assert callable(create_mcp_server)
