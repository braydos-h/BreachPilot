"""TODO 007: manifest completeness + export/import round-trip."""

from __future__ import annotations

from tools.kernel.run_manifest import (
    MANIFEST_FILENAME,
    build_manifest,
    export_run_bundle,
    import_run_bundle,
    read_manifest,
    validate_manifest,
    write_manifest,
)


def test_manifest_write_read_validate(tmp_path):
    reports = tmp_path / "reports"
    (reports / "run1").mkdir(parents=True)
    (reports / "run1" / "activity.jsonl").write_text("{}\n", encoding="utf-8")
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
    assert validate_manifest(back) == []


def test_manifest_finding_evidence_traceable(tmp_path):
    reports = tmp_path / "reports"
    m = build_manifest(run_id="r2", reports_dir=reports)
    m.evidence_index = ["reports/r2/activity.jsonl"]
    m.findings = [{"id": "f1", "evidence_refs": ["reports/r2/activity.jsonl"]}]
    assert validate_manifest(m) == []
    m.findings = [{"id": "f2", "evidence_refs": ["missing/artifact.json"]}]
    problems = validate_manifest(m)
    assert any("f2" in p for p in problems)


def test_export_import_roundtrip(tmp_path):
    reports = tmp_path / "reports"
    run_dir = reports / "run9"
    run_dir.mkdir(parents=True)
    (run_dir / "activity.jsonl").write_text("{}\n", encoding="utf-8")
    m = build_manifest(run_id="run9", reports_dir=reports)
    write_manifest(reports, m)
    bundle = export_run_bundle(reports, "run9", tmp_path / "run9.zip")
    assert bundle.exists()
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    import_run_bundle(bundle, fresh)
    assert (fresh / "run9" / MANIFEST_FILENAME).exists()
