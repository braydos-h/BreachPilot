"""Tests for the docs-truth guard (scripts/docs_truth_audit.py).

Covers the GitHub-slug rules the guard depends on (code-span headings,
underscores, duplicate `-1`/`-2` suffixes), code-fence/span blindness, and
the tmp-repo link matrix (good file/anchor pass; dead file/anchor fail).
The versions check runs against the real repo (read-only): the three
packaging locations must agree and no stale installer pins/old-branding
claims may remain in the scanned docs. Negative cases (stale pin, desync)
run against tmp repos via monkeypatched scan_files/read_version.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load():
    path = Path(__file__).resolve().parent.parent / "scripts" / "docs_truth_audit.py"
    spec = importlib.util.spec_from_file_location("docs_truth_audit", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    ("heading", "expected"),
    [
        ("GET /health", "get-health"),
        ("`GET /health`", "get-health"),
        ("MCP_HTTP_TOKEN mismatch", "mcp_http_token-mismatch"),
        ("Safety model", "safety-model"),
        ("Run `foo` now!", "run-foo-now"),
    ],
)
def test_github_slug(heading: str, expected: str):
    mod = _load()
    assert mod.github_slug(heading) == expected


def test_file_anchors_duplicate_and_explicit(tmp_path: Path):
    mod = _load()
    doc = tmp_path / "doc.md"
    doc.write_text(
        '# Title\n\n## Repro\n\ntext\n\n## Repro\n\nmore\n\n<a name="custom-anchor"></a>\n',
        encoding="utf-8",
    )
    anchors = mod.file_anchors(doc)
    assert "title" in anchors
    assert "repro" in anchors
    assert "repro-1" in anchors  # GitHub duplicate suffix
    assert "custom-anchor" in anchors


def test_iter_links_ignores_code(tmp_path: Path):
    mod = _load()
    doc = tmp_path / "doc.md"
    doc.write_text(
        "# Doc\n\n```md\n[Fake](./missing.md)\n```\n\nReal: [Other](./other.md) and `[Code](./nope.md)`.\n",
        encoding="utf-8",
    )
    targets = [target for _, target in mod.iter_links(doc)]
    assert "./other.md" in targets
    assert "./missing.md" not in targets
    assert "./nope.md" not in targets


def test_check_links_tmp_repo(tmp_path: Path, monkeypatch):
    mod = _load()
    (tmp_path / "other.md").write_text("# Other\n\n## Health Check\n", encoding="utf-8")
    good = tmp_path / "good.md"
    good.write_text("# Good\n\n[O](./other.md) [A](./other.md#health-check)\n", encoding="utf-8")
    monkeypatch.setattr(mod, "scan_files", lambda: [good])
    assert mod.check_links() == []

    bad_file = tmp_path / "bad_file.md"
    bad_file.write_text("# Bad\n\n[Gone](./gone.md)\n", encoding="utf-8")
    monkeypatch.setattr(mod, "scan_files", lambda: [bad_file])
    problems = mod.check_links()
    assert any("missing file" in problem for problem in problems)

    bad_anchor = tmp_path / "bad_anchor.md"
    bad_anchor.write_text("# Bad\n\n[Nope](./other.md#no-such-heading)\n", encoding="utf-8")
    monkeypatch.setattr(mod, "scan_files", lambda: [bad_anchor])
    problems = mod.check_links()
    assert any("missing anchor" in problem for problem in problems)


def test_check_versions_real_repo():
    mod = _load()
    assert mod.check_versions() == []


def test_check_versions_stale_installer_pin(tmp_path: Path, monkeypatch):
    """A README installer pin != pyproject version fails with file:line."""
    import tomllib

    mod = _load()
    repo = Path(__file__).resolve().parent.parent
    current = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    stale = "0.0.0" if str(current) != "0.0.0" else "0.0.1"
    doc = tmp_path / "README.md"
    doc.write_text(
        f"# Doc\n\n```bash\ncurl -fsSLO https://github.com/o/r/releases/download/v{stale}/install-v{stale}.sh\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "scan_files", lambda: [doc])
    problems = mod.check_versions()
    assert problems, "stale installer pin must fail"
    assert any(str(doc) in p and ":4:" in p and f"v{stale}" in p for p in problems), problems


def test_check_versions_desync_reported(monkeypatch):
    """main.py __version__ != pyproject version is reported as a mismatch."""
    mod = _load()
    real_read_version = mod.read_version
    monkeypatch.setattr(mod, "scan_files", lambda: [])

    def _desynced(path):
        if path.name == "main.py":
            return "9.9.9-desync"
        return real_read_version(path)

    monkeypatch.setattr(mod, "read_version", _desynced)
    problems = mod.check_versions()
    assert any("version mismatch" in p and "9.9.9-desync" in p for p in problems), problems
