"""TODO 024: supply-chain artifacts wired (pins, SBOM/Trivy, digests)."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_actions_sha_pinned():
    offender: list[str] = []
    for yml in (REPO / ".github" / "workflows").glob("*.yml"):
        for i, line in enumerate(yml.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", line)
            if not m:
                continue
            ref = m.group(2)
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            # Allow local/.docker actions.
            if m.group(1).startswith(("./", "docker/")):
                continue
            offender.append(f"{yml.name}:{i}:{line.strip()}")
    assert not offender, "unpinned actions:\n" + "\n".join(offender)


def test_release_workflow_publishes_supply_chain():
    text = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for needle in (
        "sbom-python.json",
        "sbom-webui.json",
        "sbom-sandbox.json",
        "trivy",
        "attest-build-provenance",
        "install-",
    ):
        assert needle in text, f"release.yml missing {needle}"
    assert "worker-digests.txt" in text or "worker-digests" in text


def test_release_docs_link_evidence():
    text = (REPO / "docs" / "release.md").read_text(encoding="utf-8")
    assert "branch-rules.json" in text
    assert "worker-digests" in text
    assert "green HEAD" in text or "green head" in text.lower()
