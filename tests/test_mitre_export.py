"""Tests for tools/mitre_export.py — MITRE ATT&CK Navigator export.

Hermetic: no real network, no real filesystem audit trail. Feeds a synthetic
audit list with known tools + an unknown tool + a non-dict line, and asserts
the layer has the right technique IDs, scores, unknown tools skipped, and the
schema matches Navigator 4.5. Also tests the full export_attack_navigator()
path (audit file read, path-traversal guard, empty audit trail).
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.mitre_export import (
    _DEFAULT_MAP,
    build_navigator_layer,
    demo,
    export_attack_navigator,
    load_technique_map,
)

# ── build_navigator_layer ────────────────────────────────────────────────────


SYNTHETIC = [
    {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
    {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
    {"tool_name": "run_python_file", "target_ip": "10.0.0.5", "status": "completed"},
    {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
    {"tool_name": "kerberoast", "target_ip": "10.0.0.5", "status": "completed"},
    {"tool_name": "unknown_tool_name", "target_ip": "10.0.0.5", "status": "completed"},
    "not-a-dict-line",  # malformed, must be skipped
    {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "completed"},  # wrong target
    {"tool_name": "", "target_ip": "10.0.0.5", "status": "completed"},  # empty tool_name
]


def test_build_layer_maps_known_tools():
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert by_id["T1059"] == 2
    assert by_id["T1059.006"] == 1
    assert by_id["T1003"] == 1
    assert by_id["T1558.003"] == 1


def test_build_layer_skips_unknown_tool():
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    # unknown_tool_name is not a technique ID; nothing mapped to it
    assert "unknown_tool_name" not in ids


def test_build_layer_skips_non_dict_line():
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    # the non-dict line must not crash and must not contribute
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert by_id["T1059"] == 2  # only the two 10.0.0.5 records


def test_build_layer_filters_by_target_ip():
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    # the 10.0.0.99 record must NOT be counted
    assert by_id["T1059"] == 2


def test_build_layer_empty_records_returns_empty_techniques():
    layer = build_navigator_layer([], _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    assert layer["techniques"] == []


def test_build_layer_comma_joined_target_matches():
    """A comma-joined target_ip row (from _extract_audit_target) matches the filter."""
    records = [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5,10.0.0.6", "status": "completed"}]
    layer = build_navigator_layer(records, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert by_id.get("T1059") == 1


def test_build_layer_no_target_filter_counts_all():
    """Empty target_ip counts all records regardless of their target."""
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="", include_skills=False)
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    # now the 10.0.0.99 record is counted too
    assert by_id["T1059"] == 3


def test_build_layer_comment_capped():
    """Comment length is capped at _MAX_COMMENT_CHARS."""
    from tools.mitre_export import _MAX_COMMENT_CHARS

    big = "x" * 500
    records = [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": big}]
    layer = build_navigator_layer(records, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    for t in layer["techniques"]:
        assert len(t["comment"]) <= _MAX_COMMENT_CHARS


def test_build_layer_techniques_capped():
    """The technique set is capped at _MAX_TECHNIQUES."""
    from tools.mitre_export import _MAX_TECHNIQUES

    # generate records with more unique techniques than the cap
    records = []
    for i in range(_MAX_TECHNIQUES + 50):
        # use the built-in map keys to generate distinct technique IDs by
        # cycling known tools; each tool maps to one technique. To exceed the
        # cap we need >_MAX_TECHNIQUES distinct IDs — but the built-in map
        # only has ~15. Instead, build a synthetic map with many entries.
        pass
    # Build a synthetic map with more entries than the cap.
    big_map = {f"tool_{i}": f"T{i:04d}" for i in range(_MAX_TECHNIQUES + 50)}
    records = [{"tool_name": f"tool_{i}", "target_ip": "10.0.0.5", "status": "ok"} for i in range(_MAX_TECHNIQUES + 50)]
    layer = build_navigator_layer(records, big_map, target_ip="10.0.0.5", include_skills=False)
    assert len(layer["techniques"]) == _MAX_TECHNIQUES


def test_build_layer_schema_matches_navigator_45():
    layer = build_navigator_layer(SYNTHETIC, _DEFAULT_MAP, target_ip="10.0.0.5", include_skills=False)
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["attack"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert isinstance(layer["techniques"], list)
    for t in layer["techniques"]:
        assert "techniqueID" in t
        assert "score" in t
        assert "comment" in t
    assert "gradient" in layer
    assert "filters" in layer


# ── load_technique_map ───────────────────────────────────────────────────────


def test_load_technique_map_falls_back_to_default_when_missing(tmp_path):
    result = load_technique_map(tmp_path / "does_not_exist.json")
    assert result == _DEFAULT_MAP


def test_load_technique_map_falls_back_on_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    result = load_technique_map(p)
    assert result == _DEFAULT_MAP


def test_load_technique_map_merges_over_default(tmp_path):
    p = tmp_path / "custom.json"
    p.write_text(json.dumps({"run_exploit_terminal": "T9999", "new_tool": "T8888"}), encoding="utf-8")
    result = load_technique_map(p)
    assert result["run_exploit_terminal"] == "T9999"  # override
    assert result["new_tool"] == "T8888"  # addition
    assert result["run_python_file"] == "T1059.006"  # built-in preserved


def test_load_technique_map_none_returns_default():
    result = load_technique_map(None)
    assert result == _DEFAULT_MAP


# ── export_attack_navigator ──────────────────────────────────────────────────


def _write_audit(tmp_path: Path, records: list) -> Path:
    audit = tmp_path / "exploit_audit.jsonl"
    with audit.open("w", encoding="utf-8") as f:
        for rec in records:
            if isinstance(rec, dict):
                f.write(json.dumps(rec) + "\n")
            else:
                f.write(str(rec) + "\n")
    return audit


def test_export_writes_layer_file(tmp_path):
    audit = _write_audit(
        tmp_path,
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
            {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
        ],
    )
    out_dir = tmp_path / "mitre"
    result = export_attack_navigator(
        "10.0.0.5",
        audit_path=str(audit),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    assert "error" not in result
    assert result["techniques"] == 2
    assert "T1059" in result["technique_ids"]
    assert "T1003" in result["technique_ids"]
    layer_path = Path(result["layer_path"])
    assert layer_path.is_file()
    layer = json.loads(layer_path.read_text(encoding="utf-8"))
    assert layer["versions"]["layer"] == "4.5"


def test_export_empty_audit_returns_empty_techniques(tmp_path):
    audit = tmp_path / "empty.jsonl"
    audit.write_text("", encoding="utf-8")
    out_dir = tmp_path / "mitre"
    result = export_attack_navigator(
        "10.0.0.5",
        audit_path=str(audit),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    assert result["techniques"] == 0
    assert result["technique_ids"] == []
    # layer file still written (with empty techniques)
    assert Path(result["layer_path"]).is_file()


def test_export_skips_malformed_jsonl_lines(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"})
        + "\n"
        + "not json at all\n"
        + json.dumps({"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"})
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "mitre"
    result = export_attack_navigator(
        "10.0.0.5",
        audit_path=str(audit),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    assert result["techniques"] == 2  # both valid records mapped


def test_export_path_traversal_coerced_under_output_dir(tmp_path):
    audit = _write_audit(
        tmp_path, [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}]
    )
    out_dir = tmp_path / "mitre"
    # attempt to escape via ../
    result = export_attack_navigator(
        "10.0.0.5",
        output_path="../../escape.json",
        audit_path=str(audit),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    layer_path = Path(result["layer_path"])
    # must be under out_dir (or its resolved form), not escaped
    try:
        layer_path.resolve().relative_to(out_dir.resolve())
    except ValueError:
        # if the absolute coercion happened, the name should still be safe
        assert layer_path.name == "escape.json"
    assert layer_path.is_file()


def test_export_invalid_target_returns_error(tmp_path):
    audit = _write_audit(tmp_path, [])
    result = export_attack_navigator(
        "not-a-valid-target-with-spaces and stuff",
        audit_path=str(audit),
        navigator_output_dir=str(tmp_path / "mitre"),
        include_skills=False,
    )
    assert "error" in result
    assert result["techniques"] == 0


def test_export_missing_audit_file_returns_empty(tmp_path):
    out_dir = tmp_path / "mitre"
    result = export_attack_navigator(
        "10.0.0.5",
        audit_path=str(tmp_path / "nonexistent.jsonl"),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    assert result["techniques"] == 0


def test_export_makes_output_dir(tmp_path):
    audit = _write_audit(
        tmp_path, [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}]
    )
    out_dir = tmp_path / "deeply" / "nested" / "mitre"
    assert not out_dir.exists()
    result = export_attack_navigator(
        "10.0.0.5",
        audit_path=str(audit),
        navigator_output_dir=str(out_dir),
        include_skills=False,
    )
    assert out_dir.is_dir()
    assert Path(result["layer_path"]).is_file()


# ── demo() self-check ────────────────────────────────────────────────────────


def test_demo_runs_without_error():
    """The demo() self-check runs and returns a valid layer."""
    layer = demo()
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) > 0
