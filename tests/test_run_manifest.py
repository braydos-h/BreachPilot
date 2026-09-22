"""TODO 007 / p2-06: manifest build->update->finalize + hardened validate/import."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tools.kernel.run_manifest import (
    MANIFEST_FILENAME,
    build_manifest,
    export_run_bundle,
    finalize_manifest,
    import_run_bundle,
    manifest_file_hash,
    read_manifest,
    update_manifest,
    validate_manifest,
    validate_manifest_file,
    write_manifest,
)


def _seed_run(reports: Path, run_id: str = "run1") -> Path:
    run_dir = reports / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "activity.jsonl").write_text("{}\n", encoding="utf-8")
    (run_dir / "decision_log.jsonl").write_text("{}\n", encoding="utf-8")
    return run_dir


def test_manifest_write_read_validate(tmp_path):
    reports = tmp_path / "reports"
    _seed_run(reports, "run1")
    m = build_manifest(
        run_id="run1",
        reports_dir=reports,
        config={"sandbox": {"enabled": True}},
        eval_provenance={"config_hash": "abc", "prompt_hash": "def"},
    )
    assert m.config_hash == "abc"
    out = write_manifest(reports, m)
    assert out.name == MANIFEST_FILENAME
    back = read_manifest(out)
    assert back.run_id == "run1"
    # build_manifest is write-once (may list not-yet-written candidates);
    # after an update refresh the manifest validates clean.
    refreshed = update_manifest(reports / "run1")
    assert refreshed.finished_at != ""
    assert validate_manifest(refreshed) == []
    assert validate_manifest_file(out) == []


def test_manifest_finding_evidence_traceable(tmp_path):
    reports = tmp_path / "reports"
    _seed_run(reports, "r2")
    m = build_manifest(run_id="r2", reports_dir=reports)
    write_manifest(reports, m)
    m = update_manifest(reports / "r2")
    m.evidence_index = ["reports/r2/activity.jsonl"]
    m.findings = [{"id": "f1", "evidence_refs": ["reports/r2/activity.jsonl"]}]
    assert validate_manifest(m) == []
    m.findings = [{"id": "f2", "evidence_refs": ["missing/artifact.json"]}]
    problems = validate_manifest(m)
    assert any("f2" in p for p in problems)


def test_build_update_finalize_refreshes(tmp_path):
    reports = tmp_path / "reports"
    run_dir = _seed_run(reports, "run3")
    m = build_manifest(run_id="run3", reports_dir=reports)
    assert m.finished_at == ""
    write_manifest(reports, m)
    hash_start = manifest_file_hash(run_dir / MANIFEST_FILENAME)

    # New artifact appears mid-run (loot + campaign state); update picks it up.
    (run_dir / "loot").mkdir(exist_ok=True)
    (run_dir / "loot" / "creds.txt").write_text("x", encoding="utf-8")
    (run_dir / "attack_states.json").write_text("{}", encoding="utf-8")
    updated = update_manifest(run_dir)
    assert updated.finished_at != ""
    assert "loot" in updated.state_stores
    assert "campaign_state" in updated.state_stores
    assert str(run_dir / "loot") in updated.evidence_index
    assert manifest_file_hash(run_dir / MANIFEST_FILENAME) != hash_start

    finalized = finalize_manifest(reports, "run3")
    assert finalized.finished_at != ""
    assert validate_manifest(finalized) == []
    assert validate_manifest_file(run_dir / MANIFEST_FILENAME) == []


def test_finalize_builds_when_missing(tmp_path):
    reports = tmp_path / "reports"
    run_dir = _seed_run(reports, "run4")
    finalized = finalize_manifest(reports, "run4")
    assert finalized.run_id == "run4"
    assert (run_dir / MANIFEST_FILENAME).is_file()


def test_update_requires_existing_manifest(tmp_path):
    with pytest.raises(FileNotFoundError):
        update_manifest(tmp_path / "nope")


def test_stale_ref_fails_validate(tmp_path):
    reports = tmp_path / "reports"
    _seed_run(reports, "run5")
    m = build_manifest(run_id="run5", reports_dir=reports)
    write_manifest(reports, m)
    m = update_manifest(reports / "run5")
    m.state_stores["ghost"] = str(reports / "run5" / "ghost.json")
    problems = validate_manifest(m)
    assert any("ghost" in p for p in problems)


def test_missing_activity_fails_validation(tmp_path):
    reports = tmp_path / "reports"
    run_dir = _seed_run(reports, "run6")
    (run_dir / "activity.jsonl").unlink()
    m = build_manifest(run_id="run6", reports_dir=reports)
    write_manifest(reports, m)
    m = update_manifest(run_dir)
    problems = validate_manifest(m)
    assert any("activity" in p for p in problems)


def test_hash_tamper_fails_validate_file(tmp_path):
    reports = tmp_path / "reports"
    _seed_run(reports, "run7")
    m = build_manifest(run_id="run7", reports_dir=reports)
    write_manifest(reports, m)
    update_manifest(reports / "run7")
    manifest_path = reports / "run7" / MANIFEST_FILENAME
    assert validate_manifest_file(manifest_path) == []
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["run_id"] = "tampered"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_manifest_file(manifest_path) != []


def test_export_import_roundtrip(tmp_path):
    reports = tmp_path / "reports"
    run_dir = _seed_run(reports, "run9")
    m = build_manifest(run_id="run9", reports_dir=reports)
    write_manifest(reports, m)
    update_manifest(run_dir)
    hash_before = manifest_file_hash(run_dir / MANIFEST_FILENAME)
    bundle = export_run_bundle(reports, "run9", tmp_path / "run9.zip")
    assert bundle.exists()
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    run_path = import_run_bundle(bundle, fresh)
    assert run_path == fresh / "run9"
    assert (fresh / "run9" / MANIFEST_FILENAME).exists()
    assert manifest_file_hash(fresh / "run9" / MANIFEST_FILENAME) == hash_before
    assert validate_manifest_file(fresh / "run9" / MANIFEST_FILENAME) == []


def test_import_rejects_traversal(tmp_path):
    bad = tmp_path / "evil.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("runX/" + MANIFEST_FILENAME, '{"version": 1}')
        zf.writestr("../evil.txt", "pwned")
    with pytest.raises(ValueError, match="[Tt]raversal|unsafe|escapes"):
        import_run_bundle(bad, tmp_path / "dest")

    bad_abs = tmp_path / "evil_abs.zip"
    with zipfile.ZipFile(bad_abs, "w") as zf:
        zf.writestr("/abs.txt", "pwned")
    with pytest.raises(ValueError, match="[Tt]raversal|unsafe|escapes|absolute|rejected"):
        import_run_bundle(bad_abs, tmp_path / "dest2")


def test_import_rejects_bad_hash(tmp_path):
    reports = tmp_path / "reports"
    _seed_run(reports, "run10")
    m = build_manifest(run_id="run10", reports_dir=reports)
    write_manifest(reports, m)
    bundle = export_run_bundle(reports, "run10", tmp_path / "run10.zip")
    # Tamper the manifest inside a copy of the bundle.
    tampered = tmp_path / "run10_tampered.zip"
    with zipfile.ZipFile(bundle, "r") as src, zipfile.ZipFile(tampered, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename.endswith(MANIFEST_FILENAME):
                payload = json.loads(data.decode("utf-8"))
                payload["mission_id"] = "tampered"
                data = json.dumps(payload).encode()
            dst.writestr(info.filename, data)
    with pytest.raises(ValueError, match="[Hh]ash|rejected"):
        import_run_bundle(tampered, tmp_path / "dest3")


def test_manifest_indexes_witness_and_workspaces(tmp_path):
    """The manifest must index every fragmented store (witness, swarm + exploit workspaces)."""
    reports = tmp_path / "reports"
    run_dir = _seed_run(reports, "run11")
    (run_dir / "witness.jsonl").write_text("{}\n", encoding="utf-8")
    m = build_manifest(run_id="run11", reports_dir=reports)
    for key in ("witness", "swarm_workspace", "exploit_workspace"):
        assert key in m.state_stores, f"manifest missing store {key!r}"
    write_manifest(reports, m)
    updated = update_manifest(run_dir)
    assert updated.state_stores["witness"] == str(run_dir / "witness.jsonl")
    assert str(run_dir / "witness.jsonl") in updated.evidence_index
