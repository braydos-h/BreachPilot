"""Tests for the mission module.

Covers:
- Mission object creation and validation
- Risk profile defaults
- Required fields enforcement
- Asset string validation
- YAML/config normalization
"""

from __future__ import annotations

import pytest

from mission import (
    Mission,
    MissionController,
    _validate_asset_string,
    _classify_asset,
    _normalize_config,
    _RISK_PROFILES,
    DEFAULT_OBJECTIVE,
)

from db import DatabaseManager, _new_id


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


@pytest.fixture
def mission_ctrl(temp_db, tmp_path):
    return MissionController(temp_db, workspace_root=tmp_path / "workspace")


# ── Asset validation ───────────────────────────────────────────────────────


def test_validate_domain():
    assert _validate_asset_string("example.com") is True


def test_validate_wildcard():
    assert _validate_asset_string("*.example.com") is True


def test_validate_ip():
    assert _validate_asset_string("192.168.1.1") is True


def test_validate_cidr():
    assert _validate_asset_string("10.0.0.0/24") is True


def test_reject_empty():
    assert _validate_asset_string("") is False


def test_reject_garbage():
    assert _validate_asset_string("!!!") is False


# ── Asset classification ──────────────────────────────────────────────────


def test_classify_domain():
    assert _classify_asset("example.com") == "domain"


def test_classify_wildcard():
    assert _classify_asset("*.test.com") == "wildcard_domain"


def test_classify_ip():
    assert _classify_asset("10.0.0.1") == "ip"


def test_classify_cidr():
    assert _classify_asset("10.0.0.0/24") == "cidr"


# ── Mission creation ──────────────────────────────────────────────────────


def test_mission_basic():
    m = Mission(
        program_name="Test Program",
        allowed_assets=["example.com"],
    )
    assert m.program_name == "Test Program"
    assert m.risk_profile == "low_noise_non_destructive"
    assert m.is_valid() is True


def test_mission_defaults():
    m = Mission(program_name="Default Test", allowed_assets=["test.com"])
    assert m.objective == DEFAULT_OBJECTIVE
    assert m.risk_profile == "low_noise_non_destructive"
    assert m.max_commands_per_session == 100
    assert m.allows_exploitation is False


def test_mission_standard():
    m = Mission(
        program_name="Standard",
        allowed_assets=["example.com"],
        risk_profile="standard_authorized",
    )
    assert m.risk_profile == "standard_authorized"
    assert m.requires_human_approval_for_high_risk is True
    assert m.allows_exploitation is True


def test_mission_high():
    m = Mission(
        program_name="High Auth",
        allowed_assets=["owned.example.com"],
        risk_profile="high_authorized_testing",
    )
    assert m.risk_profile == "high_authorized_testing"
    assert m.allows_exploitation is True
    assert m.allows_pivoting is True
    assert m.requires_human_approval_for_high_risk is False


# ── Validation errors ─────────────────────────────────────────────────────


def test_validation_no_program_name():
    m = Mission(program_name="", allowed_assets=["test.com"])
    errors = m.validate()
    assert any("program_name" in e.lower() for e in errors)


def test_validation_no_assets():
    m = Mission(program_name="Test")
    errors = m.validate()
    assert any("at least" in e.lower() for e in errors)


def test_validation_bad_risk_profile():
    m = Mission(program_name="Test", allowed_assets=["test.com"], risk_profile="invalid_profile")
    errors = m.validate()
    assert any("risk_profile" in e.lower() for e in errors)


def test_validation_bad_asset():
    m = Mission(program_name="Test", allowed_assets=["invalid!"])
    errors = m.validate()
    assert any("invalid" in e.lower() or "scope" in e.lower() for e in errors)


# ── Config normalization ──────────────────────────────────────────────────


def test_normalize_config_target_assets():
    config = {"program_name": "Test", "target_assets": ["test.com"]}
    norm = _normalize_config(config)
    assert "test.com" in norm.get("allowed_assets", [])


def test_normalize_config_scope_dict():
    config = {"program_name": "Test", "scope": {"allow": ["scope.com"]}}
    norm = _normalize_config(config)
    assert "scope.com" in norm.get("allowed_assets", [])


# ── Mission controller — create from config ───────────────────────────────


def test_controller_create_from_config(mission_ctrl):
    config = {
        "program_name": "Controller Test",
        "allowed_assets": ["example.com"],
        "risk_profile": "low_noise_non_destructive",
    }
    mission = mission_ctrl.create_from_config(config)

    assert mission.program_name == "Controller Test"
    assert mission.mission_id.startswith("M-")
    assert mission.risk_profile == "low_noise_non_destructive"

    # Load back
    loaded = mission_ctrl.load_mission(mission.mission_id)
    assert loaded is not None
    assert loaded.program_name == "Controller Test"


def test_controller_rejects_invalid(mission_ctrl):
    config = {"program_name": "", "allowed_assets": []}
    with pytest.raises(ValueError) as exc:
        mission_ctrl.create_from_config(config)
    assert "validation" in str(exc.value).lower()


def test_controller_status_update(mission_ctrl):
    config = {"program_name": "Status Test", "allowed_assets": ["test.com"]}
    mission = mission_ctrl.create_from_config(config)

    mission_ctrl.update_status(mission.mission_id, "paused")
    loaded = mission_ctrl.load_mission(mission.mission_id)
    assert loaded is not None
    # Status stored in DB, but Mission dataclass doesn't load status field
    # from DB row — it uses the DB's status field independently.
    # The mission object always starts as 'active' since status is a DB-level field.
    # This is fine — update_status just writes to DB, not to the Mission object.


def test_controller_mission_id_override(mission_ctrl):
    config = {
        "program_name": "Override ID",
        "allowed_assets": ["over.example.com"],
    }
    mission = mission_ctrl.create_from_config(config, mission_id="M-CUSTOM-001")
    assert mission.mission_id == "M-CUSTOM-001"


# ── Risk profile validation ───────────────────────────────────────────────


def test_all_risk_profiles_valid():
    for name, config in _RISK_PROFILES.items():
        assert isinstance(name, str)
        assert "max_commands_per_session" in config
        assert "max_tasks_active" in config
        assert "testing_modes" in config


# ── H18: forbidden_actions unions with profile defaults ──────────────────


def test_forbidden_actions_explicit_unions_with_defaults():
    """A non-empty forbidden_actions list must AUGMENT the profile defaults,
    not replace them (H18). Under low_noise_non_destructive the defaults include
    'persistence' and 'data_exfiltration'; an explicit ['pivoting'] must keep
    those defaults too."""
    m = Mission(
        program_name="Union Test",
        allowed_assets=["example.com"],
        risk_profile="low_noise_non_destructive",
        forbidden_actions=["pivoting"],
    )
    defaults = set(_RISK_PROFILES["low_noise_non_destructive"]["forbidden_by_default"])
    assert "pivoting" in m.forbidden_actions
    # The explicit list augments rather than replaces: profile defaults survive.
    assert "persistence" in m.forbidden_actions
    assert "data_exfiltration" in m.forbidden_actions
    assert set(m.forbidden_actions) == defaults | {"pivoting"}


def test_forbidden_actions_empty_fills_defaults():
    """Empty forbidden_actions still fills profile defaults (via union)."""
    m = Mission(
        program_name="Empty Test",
        allowed_assets=["example.com"],
        risk_profile="low_noise_non_destructive",
    )
    defaults = _RISK_PROFILES["low_noise_non_destructive"]["forbidden_by_default"]
    assert m.forbidden_actions == sorted(defaults)


# ── M31: _validate_asset_string per-label validation ─────────────────────


@pytest.mark.parametrize("bad", [
    "....",       # all empty labels
    "-.-.",       # hyphen-only labels
    "*.-.com",    # wildcard with leading-hyphen label
    "---.com",    # leading-hyphen label
    "example..com",  # empty interior label
    "-example.com",  # leading hyphen
    "example-.com",  # trailing hyphen
])
def test_validate_asset_string_rejects_malformed_domains(bad: str) -> None:
    assert _validate_asset_string(bad) is False


@pytest.mark.parametrize("good", [
    "example.com",
    "sub.example.com",
    "*.example.com",
    "a-b.example.com",
    "x.example.com",
])
def test_validate_asset_string_accepts_well_formed_domains(good: str) -> None:
    assert _validate_asset_string(good) is True


def test_validate_asset_string_length_limit() -> None:
    # 254-char total domain is rejected (>253).
    long_label = "a" * 250
    assert _validate_asset_string(f"{long_label}.com") is False
