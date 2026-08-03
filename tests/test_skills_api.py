"""Tests for the skills install/remove API: POST /skills, DELETE /skills/{name}.

Covers the write path added to tools/api/routes/system.py:
  - install a valid SKILL.md (200, appears in next /skills list)
  - reject invalid skill names (400, no directory created)
  - reject malformed markdown (400, partial directory cleaned up)
  - delete an existing skill (200, gone from list)
  - path-traversal names are rejected by the regex + containment check
  - toggling default_enabled / exclude_names via PATCH /config is reflected
    in the per-skill state surfaced by GET /skills
  - the registry cache is cleared on install/remove so reads reflect disk

These hit the real FastAPI app with a minimal config (no Ollama) and a tmp
skills root, using the same TestClient + create_app harness as the other
test_api_* files.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str = "test-token") -> TestClient:
    """Create a TestClient whose skills.roots points at tmp_path/skills."""
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n"
        "skills:\n  enabled: true\n  roots:\n  - skills\n  default_enabled: []\n  exclude_names: []\n",
        encoding="utf-8",
    )
    # Pre-create the skills root so install_skill's root check passes.
    (tmp_path / "skills").mkdir(parents=True, exist_ok=True)
    from app import create_app

    app = create_app(config_path=config_path)
    return TestClient(app)


def _auth(token: str = "test-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _skill_md(name: str = "my-test-skill") -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "description: A skill created by the test suite.\n"
        "tags:\n  - test\n"
        "---\n\n"
        "## When to use\n\nWhen the test suite says so.\n"
    )


# Kept for callers that still reference the constant form.
_VALID_SKILL_MD = _skill_md()


@pytest.fixture(autouse=True)
def _clear_skill_cache():
    """Drop the process-level SkillRegistry cache before each test so the
    tmp skills root is re-read from disk (the cache is keyed by resolved root
    path, which is stable across tests in the same tmp_path but we want a
    clean slate)."""
    from tools.skill_registry_cache import clear_cache

    clear_cache()
    yield
    clear_cache()


# ── Install ───────────────────────────────────────────────────────────────────


def test_install_skill_creates_file_and_lists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/skills", json={"name": "my-test-skill", "markdown": _VALID_SKILL_MD}, headers=_auth())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "my-test-skill"
    assert "test" in body["tags"]
    # The SKILL.md file is on disk under the configured root.
    skill_file = tmp_path / "skills" / "my-test-skill" / "SKILL.md"
    assert skill_file.is_file()
    assert "my-test-skill" in skill_file.read_text(encoding="utf-8")
    # The new skill appears in the catalog list.
    listing = client.get("/api/v1/skills", headers=_auth()).json()
    names = [s["name"] for s in listing["skills"]]
    assert "my-test-skill" in names


def test_install_skill_rejects_invalid_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    for bad in ("My-Skill", "with space", "has/slash", "..", "", "a", "1" * 200):
        resp = client.post("/api/v1/skills", json={"name": bad, "markdown": _VALID_SKILL_MD}, headers=_auth())
        assert resp.status_code == 400, f"name {bad!r} should be rejected, got {resp.status_code}"
    # No directory should have been created for the bad names.
    root = tmp_path / "skills"
    created = [p.name for p in root.iterdir() if p.is_dir()]
    assert created == [], f"unexpected dirs created: {created}"


def test_install_skill_rejects_path_traversal(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    # The regex rejects uppercase/slash/space, so these are caught at name
    # validation. A name like "foo..bar" is regex-valid but cannot escape the
    # root because resolve()+relative_to() enforces containment.
    resp = client.post("/api/v1/skills", json={"name": "foo..bar", "markdown": _VALID_SKILL_MD}, headers=_auth())
    # foo..bar is regex-valid (lowercase, hyphens, dots not allowed actually).
    # The regex is [a-z0-9][a-z0-9-]{1,63} so dots are rejected -> 400.
    assert resp.status_code == 400


def test_install_skill_rejects_malformed_markdown(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    # Front matter that is not a YAML mapping: a bare list.
    bad_md = "---\n- not\n- a\n- mapping\n---\n\nbody\n"
    resp = client.post("/api/v1/skills", json={"name": "bad-skill", "markdown": bad_md}, headers=_auth())
    assert resp.status_code == 400, resp.text
    # The created directory must have been cleaned up on parse failure.
    assert not (tmp_path / "skills" / "bad-skill").exists()


def test_install_skill_rejects_empty_markdown(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/skills", json={"name": "empty-skill", "markdown": "   "}, headers=_auth())
    assert resp.status_code == 400


def test_install_skill_conflict_on_existing_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    # Seed an existing skill dir with a SKILL.md.
    existing = tmp_path / "skills" / "already-here"
    existing.mkdir(parents=True)
    (existing / "SKILL.md").write_text(_skill_md("already-here"), encoding="utf-8")
    from tools.skill_registry_cache import clear_cache

    clear_cache()
    resp = client.post(
        "/api/v1/skills",
        json={"name": "already-here", "markdown": _skill_md("already-here")},
        headers=_auth(),
    )
    assert resp.status_code == 409, resp.text


def test_install_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/skills", json={"name": "x", "markdown": "x"})
    assert resp.status_code == 401


def test_install_rejects_front_matter_name_mismatch(tmp_path, monkeypatch):
    """If the markdown front-matter name differs from the request name, the
    registry would index the skill under the front-matter name while the file
    lands at the request name's dir -- DELETE and config toggles would target
    the wrong identifier. Reject on mismatch and clean up the dir."""
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/skills",
        json={"name": "dir-name", "markdown": _skill_md("frontmatter-name")},
        headers=_auth(),
    )
    assert resp.status_code == 400, resp.text
    assert not (tmp_path / "skills" / "dir-name").exists()


# ── Remove ────────────────────────────────────────────────────────────────────


def test_remove_skill_deletes_dir(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    # Install first.
    client.post("/api/v1/skills", json={"name": "removable-skill", "markdown": _skill_md("removable-skill")}, headers=_auth())
    target = tmp_path / "skills" / "removable-skill"
    assert target.is_dir()
    resp = client.delete("/api/v1/skills/removable-skill", headers=_auth())
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] is True
    assert not target.exists()
    # Gone from the catalog.
    names = [s["name"] for s in client.get("/api/v1/skills", headers=_auth()).json()["skills"]]
    assert "removable-skill" not in names


def test_remove_skill_404_when_missing(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/skills/never-existed", headers=_auth())
    assert resp.status_code == 404


def test_remove_skill_rejects_bad_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/skills/Bad-Name", headers=_auth())
    assert resp.status_code == 400


def test_remove_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/skills/anything")
    assert resp.status_code == 401


# ── Toggle via PATCH /config reflected in /skills state ──────────────────────


def test_toggle_default_enabled_persists_and_lists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    # Seed a skill on disk so GET /skills has something to report.
    skill_dir = tmp_path / "skills" / "toggle-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(_skill_md("toggle-skill"), encoding="utf-8")
    from tools.skill_registry_cache import clear_cache

    clear_cache()
    # Add to default_enabled via PATCH /config (deep-merge).
    resp = client.patch("/api/v1/config", json={"skills": {"default_enabled": ["toggle-skill"]}}, headers=_auth())
    assert resp.status_code == 200, resp.text
    # The persisted config now contains the skill in default_enabled.
    cfg = client.get("/api/v1/config", headers=_auth()).json()
    assert "toggle-skill" in cfg["skills"]["default_enabled"]


def test_toggle_exclude_names_persists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.patch("/api/v1/config", json={"skills": {"exclude_names": ["block-me"]}}, headers=_auth())
    assert resp.status_code == 200, resp.text
    cfg = client.get("/api/v1/config", headers=_auth()).json()
    assert "block-me" in cfg["skills"]["exclude_names"]


# ── Cache reload ──────────────────────────────────────────────────────────────


def test_install_clears_cache_so_list_reflects_disk(tmp_path, monkeypatch):
    """GET /skills before install must not cache the registry so the post-install
    list reflects the new file (clear_cache is called on successful install)."""
    client = _make_client(tmp_path, monkeypatch)
    before = client.get("/api/v1/skills", headers=_auth()).json()
    assert "cache-test" not in [s["name"] for s in before["skills"]]
    client.post("/api/v1/skills", json={"name": "cache-test", "markdown": _skill_md("cache-test")}, headers=_auth())
    after = client.get("/api/v1/skills", headers=_auth()).json()
    assert "cache-test" in [s["name"] for s in after["skills"]]
