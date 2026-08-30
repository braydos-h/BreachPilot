"""Tests for the XBEN adapter (manifest parsing + provider) and env metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.benchmark.envinfo import collect_environment, config_hash, resolve_model_metadata
from tools.benchmark.events import BenchmarkEventLogger, truncate_output
from tools.benchmark.xben.adapter import XbenProvider
from tools.benchmark.xben.manifest import ManifestError, load_manifest_file, parse_manifest

_VALID = {
    "benchmark_id": "xben-001",
    "name": "SQLi Challenge",
    "description": "A web challenge",
    "target_image": "ghcr.io/xben/xben-001:latest",
    "target_ports": [8080],
    "goal": "initial_access",
    "expected_flags": ["flag{abc}"],
    "oracle": {
        "flags": [
            {
                "id": "f1",
                "description": "flag readable",
                "check": {"type": "http_request", "url": "http://127.0.0.1:8080/"},
            }
        ],
        "host_owned_when": "any",
    },
    "tags": ["web", "sqli"],
    "difficulty": "easy",
    "timeout": 900,
}


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------


def test_parse_manifest_valid():
    sc = parse_manifest(_VALID)
    assert sc.scenario_id == "xben-001"
    assert sc.suite == "xben"
    assert sc.target_image.endswith(":latest")
    assert sc.target_ports == [8080]
    assert sc.tags == ["web", "sqli"]
    assert sc.timeout_seconds == 900
    assert sc.oracle["host_owned_when"] == "any"
    assert len(sc.oracle["flags"]) == 1


def test_parse_manifest_requires_id():
    data = dict(_VALID)
    del data["benchmark_id"]
    with pytest.raises(ManifestError):
        parse_manifest(data)


def test_parse_manifest_requires_oracle_flags():
    data = dict(_VALID, oracle={"flags": []})
    with pytest.raises(ManifestError, match="oracle"):
        parse_manifest(data)


def test_parse_manifest_list_form():
    scenarios = [parse_manifest(d) for d in [_VALID, dict(_VALID, benchmark_id="xben-002")]]
    assert [s.scenario_id for s in scenarios] == ["xben-001", "xben-002"]


def test_load_manifest_file(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(_VALID), encoding="utf-8")
    scenarios = load_manifest_file(path)
    assert len(scenarios) == 1
    assert scenarios[0].source_manifest == str(path)


def test_load_manifest_file_list(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps([_VALID, dict(_VALID, benchmark_id="xben-002")]), encoding="utf-8")
    assert len(load_manifest_file(path)) == 2


def test_load_manifest_file_invalid(tmp_path):
    path = tmp_path / "m.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest_file(path)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


def test_provider_discovers_and_filters(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(_VALID), encoding="utf-8")
    (tmp_path / "b.json").write_text(
        json.dumps(dict(_VALID, benchmark_id="xben-002", tags=["crypto"])), encoding="utf-8"
    )
    (tmp_path / "bad.json").write_text("{ broken", encoding="utf-8")
    provider = XbenProvider(tmp_path)
    scenarios = provider.load_scenarios()
    assert [s.scenario_id for s in scenarios] == ["xben-001", "xben-002"]

    by_id = provider.load_scenarios(scenario_ids=["xben-002"])
    assert [s.scenario_id for s in by_id] == ["xben-002"]
    by_tag = provider.load_scenarios(tags=["crypto"])
    assert [s.scenario_id for s in by_tag] == ["xben-002"]

    desc = provider.describe()
    assert desc["suite_id"] == "xben"
    assert desc["scenarios"] == 2
    assert desc["invalid_manifests"] == 1
    assert "web" in desc["tags"]


def test_provider_empty_dir(tmp_path):
    provider = XbenProvider(tmp_path / "missing")
    assert provider.load_scenarios() == []
    assert provider.describe()["scenarios"] == 0


# ---------------------------------------------------------------------------
# Env metadata
# ---------------------------------------------------------------------------


def test_config_hash_stable_and_sorted():
    a = config_hash({"x": 1, "y": {"b": 2, "a": 1}})
    b = config_hash({"y": {"a": 1, "b": 2}, "x": 1})
    assert a == b
    assert a != config_hash({"x": 2})
    assert config_hash(None) == "unknown"


def test_resolve_model_metadata_alias_resolution():
    config = {"models": {"default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}}}
    meta = resolve_model_metadata(config, "glm")
    assert meta["model_id"] == "glm-5.2:cloud"
    assert meta["model_version"] == "cloud"
    assert meta["model_alias"] == "glm"
    assert meta["model_provider"] in {"ollama", "chatgpt", "unknown"}


def test_resolve_model_metadata_unknown_alias_stays_unknown():
    meta = resolve_model_metadata({"models": {"registry": {}}}, "nope")
    assert meta["model_id"] == "unknown"
    assert meta["model_version"] == "unknown"


def test_collect_environment_honest_unknowns(monkeypatch):
    monkeypatch.setattr("tools.benchmark.envinfo._git", lambda *a, **kw: "")
    monkeypatch.setattr("tools.benchmark.envinfo.docker_image_digest", lambda image: "unknown")
    config = {"models": {"default_alias": "glm"}, "sandbox": {"enabled": False, "image": "x:1"}}
    env = collect_environment(config, model_alias="glm", sandbox_enabled=False, sandbox_required=True)
    assert env.git_sha == "unknown"
    assert env.git_dirty is None  # unknown, not False
    assert env.sandbox_image_digest == "unknown"
    assert env.sandbox_required is True
    assert env.config_hash != "unknown"


# ---------------------------------------------------------------------------
# Event logger
# ---------------------------------------------------------------------------


def test_event_logger_sequence_and_redaction(tmp_path):
    logger = BenchmarkEventLogger(path=tmp_path / "events.jsonl", run_id="r1")
    e1 = logger.log("tool_result", {"command": "curl http://admin:supersecret@host", "output_text": "x" * 5000})
    e2 = logger.log("run_start", {"nested": {"password": "hunter2"}}, trial_id="s1#t0")
    assert e1["sequence"] == 1 and e2["sequence"] == 2
    assert e2["trial_id"] == "s1#t0"
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    stored = json.loads(lines[0])
    assert "supersecret" not in json.dumps(stored)  # URL credentials redacted
    assert stored["payload"]["output_text"].endswith("chars]")
    assert "hunter2" not in lines[1]


def test_truncate_output():
    assert truncate_output("short") == "short"
    long = "a" * 3000
    out = truncate_output(long, limit=100)
    assert out.startswith("a" * 100)
    assert "truncated" in out
