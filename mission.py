"""Mission controller for authorized bug bounty / security research.

Accepts structured mission objects, normalizes vague user input,
initializes database state, workspace, evidence directory, audit log.
Rejects or pauses unsafe missions.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from db import DatabaseManager, _new_id, _now_iso

# ── Risk profile definitions ───────────────────────────────────────────────

_RISK_PROFILES = {
    "low_noise_non_destructive": {
        "max_commands_per_session": 100,
        "max_tasks_active": 20,
        "default_rate_limit_rps": 2,
        "requires_human_approval_for_high_risk": True,
        "allows_exploitation": False,
        "allows_pivoting": False,
        "allows_credential_testing": False,
        "forbidden_by_default": [
            "denial_of_service", "destructive_exploit", "credential_theft",
            "social_engineering", "physical_attack", "persistence", "malware",
            "uncontrolled_fuzzing", "data_exfiltration", "pivoting",
        ],
        "testing_modes": ["recon", "analysis"],
        "description": "Safe reconnaissance and analysis only. No exploitation.",
    },
    "standard_authorized": {
        "max_commands_per_session": 200,
        "max_tasks_active": 50,
        "default_rate_limit_rps": 2,
        "requires_human_approval_for_high_risk": True,
        "allows_exploitation": True,
        "allows_pivoting": False,
        "allows_credential_testing": True,
        "forbidden_by_default": [
            "denial_of_service", "destructive_exploit", "credential_theft",
            "social_engineering", "physical_attack", "persistence", "malware",
            "uncontrolled_fuzzing", "data_exfiltration",
        ],
        "testing_modes": ["recon", "analysis", "test", "validate"],
        "description": "Standard authorized bug bounty testing with guardrails.",
    },
    "high_authorized_testing": {
        "max_commands_per_session": 500,
        "max_tasks_active": 100,
        "default_rate_limit_rps": 3,
        "requires_human_approval_for_high_risk": False,
        "allows_exploitation": True,
        "allows_pivoting": True,
        "allows_credential_testing": True,
        "forbidden_by_default": [
            "denial_of_service", "physical_attack", "social_engineering",
            "uncontrolled_fuzzing",
        ],
        "testing_modes": ["recon", "analysis", "test", "validate", "exploit", "report"],
        "description": "Full authorized testing including exploitation on owned infrastructure.",
    },
}

# ── Default mission template ───────────────────────────────────────────────

DEFAULT_OBJECTIVE = (
    "Find valid, in-scope, non-destructive, reproducible vulnerabilities with evidence."
)

_MISSION_KEYS = frozenset({
    "id", "program_name", "target_assets", "allowed_assets", "disallowed_assets",
    "forbidden_actions", "rate_limits", "objective", "risk_profile",
    "testing_modes", "accounts", "notes",
})


# ── Mission data class ─────────────────────────────────────────────────────

@dataclass
class Mission:
    """Authorized security research mission with full scope definition."""

    # Program identification
    program_name: str = ""
    objective: str = DEFAULT_OBJECTIVE
    mission_id: str = ""

    # Scope
    target_assets: list[str] = field(default_factory=list)
    allowed_assets: list[str] = field(default_factory=list)
    disallowed_assets: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    rate_limits: dict[str, Any] = field(default_factory=dict)

    # Mode
    risk_profile: str = "low_noise_non_destructive"
    testing_modes: list[str] = field(default_factory=list)
    accounts: list[dict[str, str]] = field(default_factory=list)
    notes: str = ""

    # Runtime state (not persisted in DB schema as separate columns)
    _profile_config: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._profile_config = _RISK_PROFILES.get(
            self.risk_profile, _RISK_PROFILES["low_noise_non_destructive"]
        )
        if not self.mission_id:
            self.mission_id = _new_id("M")
        if not self.testing_modes:
            self.testing_modes = self._profile_config.get("testing_modes", ["recon", "analysis"])
        # An explicit forbidden_actions list AUGMENTS the profile defaults rather
        # than replacing them (H18). The empty-list case still fills defaults via
        # the union with the profile's forbidden_by_default set.
        self.forbidden_actions = sorted(
            set(self.forbidden_actions)
            | set(self._profile_config.get("forbidden_by_default", []))
        )

    # ── Properties ──

    @property
    def allows_exploitation(self) -> bool:
        return bool(self._profile_config.get("allows_exploitation", False))

    @property
    def allows_pivoting(self) -> bool:
        return bool(self._profile_config.get("allows_pivoting", False))

    @property
    def requires_human_approval_for_high_risk(self) -> bool:
        return bool(self._profile_config.get("requires_human_approval_for_high_risk", True))

    @property
    def max_commands_per_session(self) -> int:
        return int(self._profile_config.get("max_commands_per_session", 100))

    @property
    def max_tasks_active(self) -> int:
        return int(self._profile_config.get("max_tasks_active", 20))

    @property
    def default_rate_limit_rps(self) -> float:
        return float(self._profile_config.get("default_rate_limit_rps", 2.0))

    # ── Serialization ──

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.mission_id,
            "program_name": self.program_name,
            "objective": self.objective,
            "target_assets": self.target_assets,
            "allowed_assets": self.allowed_assets,
            "disallowed_assets": self.disallowed_assets,
            "forbidden_actions": self.forbidden_actions,
            "rate_limits": self.rate_limits,
            "risk_profile": self.risk_profile,
            "testing_modes": self.testing_modes,
            "accounts": self.accounts,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Mission:
        return cls(
            mission_id=str(data.get("id", data.get("mission_id", ""))),
            program_name=str(data.get("program_name", "")),
            objective=str(data.get("objective", DEFAULT_OBJECTIVE)),
            target_assets=data.get("target_assets", []),
            allowed_assets=data.get("allowed_assets", []),
            disallowed_assets=data.get("disallowed_assets", []),
            forbidden_actions=data.get("forbidden_actions", []),
            rate_limits=data.get("rate_limits", {}),
            risk_profile=str(data.get("risk_profile", "low_noise_non_destructive")),
            testing_modes=data.get("testing_modes", []),
            accounts=data.get("accounts", []),
            notes=str(data.get("notes", "")),
        )

    @classmethod
    def from_yaml_or_dict(cls, source: dict[str, Any]) -> Mission:
        """Normalized constructor from YAML config or dict."""
        return cls.from_dict(source)

    # ── Validation ──

    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty list = valid."""
        errors: list[str] = []

        if not self.program_name.strip():
            errors.append("program_name is required.")
        if self.risk_profile not in _RISK_PROFILES:
            errors.append(
                f"Unknown risk_profile '{self.risk_profile}'. "
                f"Valid: {list(_RISK_PROFILES)}."
            )

        if not self.target_assets and not self.allowed_assets:
            errors.append(
                "At least one of target_assets or allowed_assets must be specified."
            )

        for asset in self.allowed_assets:
            if not _validate_asset_string(asset):
                msg = (
                    f"Invalid scope entry '{asset}': must be a domain, wildcard domain "
                    f"('*.example.com'), IP, or CIDR."
                )
                errors.append(msg)

        for asset in self.disallowed_assets:
            if not _validate_asset_string(asset):
                errors.append(f"Invalid disallowed asset '{asset}': bad format.")

        for action in self.forbidden_actions:
            if not isinstance(action, str) or not action.strip():
                errors.append("forbidden_actions must be non-empty strings.")

        for mode in self.testing_modes:
            if mode not in ("recon", "analysis", "test", "validate", "exploit", "report"):
                errors.append(f"Invalid testing_mode '{mode}'.")

        return errors

    def is_valid(self) -> bool:
        return len(self.validate()) == 0


# ── Asset validation helper ────────────────────────────────────────────────

# Per-DNS-label validation: labels may contain letters, digits, hyphens but
# must not start or end with a hyphen (M31). Rejects empty labels ("…."),
# leading/trailing-hyphen labels ("-.-."), and "*.-.com".
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")


def _validate_domain_labels(domain: str) -> bool:
    """Validate a dotted domain string by checking every label."""
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    if not labels:
        return False
    for label in labels:
        if not label or not _LABEL_RE.match(label):
            return False
    return True


def _validate_asset_string(value: str) -> bool:
    """Check that an asset string looks like a domain, wildcard domain, IP, or CIDR."""
    value = value.strip()
    if not value:
        return False

    # CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    # IP
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    # Wildcard domain: *.example.com
    if value.startswith("*.") and len(value) > 3:
        domain_part = value[2:]
        return _validate_domain_labels(domain_part)

    # Plain domain — requires at least one '.' and valid per-label content.
    if "." in value:
        return _validate_domain_labels(value)

    return False


# ── Mission controller ─────────────────────────────────────────────────────

class MissionController:
    """Creates, validates, and persists missions. Initializes workspace, DB schema, evidence dir."""

    def __init__(
        self,
        db: DatabaseManager,
        workspace_root: Path | None = None,
    ) -> None:
        self._db = db
        self._workspace_root = (
            workspace_root.resolve()
            if workspace_root
            else Path.cwd() / "research_workspace"
        )
        self._active_mission_id: str | None = None

    # ------------------------------------------------------------------
    def create_from_config(
        self,
        config: dict[str, Any],
        *,
        mission_id: str | None = None,
    ) -> Mission:
        """Parse config into a Mission, validate, persist to DB, initialize workspace."""
        # Normalize keys (accept both 'target_assets' and 'allowed_assets' from config)
        normalized = _normalize_config(config)
        mission = Mission.from_dict(normalized)
        if mission_id:
            mission.mission_id = mission_id
        else:
            mission.mission_id = _new_id("M")

        # Validate
        errors = mission.validate()
        if errors:
            msg = "Mission validation failed:\n  " + "\n  ".join(errors)
            raise ValueError(msg)

        # Persist to DB
        with self._db.connection(write=True) as conn:
            self._db.ensure_schema(conn)

            self._db.create_mission(
                conn,
                id=mission.mission_id,
                program_name=mission.program_name,
                objective=mission.objective,
                risk_profile=mission.risk_profile,
                testing_modes=mission.testing_modes,
                target_assets=mission.target_assets,
                allowed_assets=mission.allowed_assets,
                disallowed_assets=mission.disallowed_assets,
                forbidden_actions=mission.forbidden_actions,
                rate_limits=mission.rate_limits,
                accounts=mission.accounts,
                notes=mission.notes,
            )

            # Insert scope rules
            for asset in mission.allowed_assets:
                target_type = _classify_asset(asset)
                self._db.add_scope_rule(
                    conn, mission.mission_id, "allow", target_type, asset,
                )
            for asset in mission.disallowed_assets:
                target_type = _classify_asset(asset)
                self._db.add_scope_rule(
                    conn, mission.mission_id, "deny", target_type, asset,
                )

            # Insert forbidden action rules
            for action in mission.forbidden_actions:
                self._db.add_scope_rule(
                    conn, mission.mission_id, "deny", "action", action,
                    notes="Forbidden action type",
                )

            self._db.log_audit(
                conn,
                mission.mission_id,
                "mission_created",
                f"Mission '{mission.program_name}' created with risk profile '{mission.risk_profile}'.",
            )

        # Initialize workspace directories
        self._init_workspace(mission)

        self._active_mission_id = mission.mission_id
        return mission

    # ------------------------------------------------------------------
    def _init_workspace(self, mission: Mission) -> None:
        """Create workspace directory structure for the mission."""
        base = self._workspace_root / mission.mission_id
        dirs = [
            base,
            base / "evidence",
            base / "evidence" / "raw_output",
            base / "evidence" / "http_responses",
            base / "evidence" / "screenshots",
            base / "evidence" / "notes",
            base / "evidence" / "artifacts",
            base / "reports",
            base / "logs",
            base / "tasks",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def load_mission(self, mission_id: str) -> Mission | None:
        with self._db.connection() as conn:
            cur = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            return _row_to_mission(data)

    # ------------------------------------------------------------------
    def update_status(self, mission_id: str, status: str) -> None:
        valid = {"active", "paused", "completed"}
        if status not in valid:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid}.")
        with self._db.connection(write=True) as conn:
            conn.execute(
                "UPDATE missions SET status=?, updated_at=? WHERE id=?",
                (status, _now_iso(), mission_id),
            )
            self._db.log_audit(conn, mission_id, "status_changed", f"Status → {status}")

    # ------------------------------------------------------------------
    @property
    def active_mission_id(self) -> str | None:
        return self._active_mission_id

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root


# ── Helpers ─────────────────────────────────────────────────────────────────

def _normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    """Accept either the detailed mission schema or config.yaml-style keys."""
    out = dict(config)

    # If config uses 'target_assets' instead of 'allowed_assets', merge them
    target = config.get("target_assets", [])
    if target and not config.get("allowed_assets"):
        out["allowed_assets"] = list(target)

    # If config has 'scope.allow' style, merge
    scope = config.get("scope", {})
    if isinstance(scope, dict):
        if not out.get("allowed_assets") and scope.get("allow"):
            out["allowed_assets"] = list(scope["allow"])
        if not out.get("allowed_assets") and scope.get("allowed_assets"):
            out["allowed_assets"] = list(scope["allowed_assets"])
        if not out.get("disallowed_assets") and scope.get("deny"):
            out["disallowed_assets"] = list(scope["deny"])

    # Coerce testing_modes to list if given
    test_modes = config.get("testing_modes", [])
    if isinstance(test_modes, list) and test_modes:
        out["testing_modes"] = test_modes

    return out


def _classify_asset(asset: str) -> str:
    asset = asset.strip()
    if asset.startswith("*."):
        return "wildcard_domain"
    try:
        ipaddress.ip_address(asset)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(asset, strict=False)
        if "/" in asset:
            return "cidr"
        return "ip"
    except ValueError:
        pass
    if asset.startswith("http://") or asset.startswith("https://"):
        return "url_prefix"
    return "domain"


def _row_to_mission(data: dict[str, Any]) -> Mission:
    return Mission(
        mission_id=str(data.get("id", "")),
        program_name=str(data.get("program_name", "")),
        objective=str(data.get("objective", DEFAULT_OBJECTIVE)),
        target_assets=_json_field(data, "target_assets_json"),
        allowed_assets=_json_field(data, "allowed_assets_json"),
        disallowed_assets=_json_field(data, "disallowed_assets_json"),
        forbidden_actions=_json_field(data, "forbidden_actions_json"),
        rate_limits=_json_field(data, "rate_limits_json") or {},
        risk_profile=str(data.get("risk_profile", "low_noise_non_destructive")),
        testing_modes=_json_field(data, "testing_modes_json"),
        accounts=_json_field(data, "accounts_json"),
        notes=str(data.get("notes", "")),
    )


def _json_field(data: dict[str, Any], key: str, default: Any = None) -> Any:
    raw = data.get(key, "")
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    if default is None:
        return [] if key.endswith("_json") else {}
    return default
