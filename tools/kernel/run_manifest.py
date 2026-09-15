"""Unified Run Manifest (TODO 007): single index over fragmented state.

State lives in research.db, api_runtime.db, attack_states.json,
swarm_state.json, exploit_audit.jsonl, decision_log.jsonl, loot/,
campaign state, reports/<run_id>/. The manifest is the authoritative index:
run_id, mission_id, timestamps, config/model/sandbox identity (reusing
RunProvenance fields), store paths, decision/audit logs, evidence index,
findings, eval provenance. Subsystems stay independent; the manifest links them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_VERSION = 1
MANIFEST_FILENAME = "run_manifest.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha_short(payload: dict) -> str:
    try:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]
    except Exception:
        return ""


@dataclass
class RunManifest:
    version: int = MANIFEST_VERSION
    run_id: str = ""
    mission_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    config_hash: str = ""
    prompt_hash: str = ""
    tool_catalog_hash: str = ""
    skill_catalog_hash: str = ""
    model: dict[str, str] = field(default_factory=dict)
    sandbox: dict[str, str] = field(default_factory=dict)
    state_stores: dict[str, str] = field(default_factory=dict)
    decision_log: str = ""
    audit_log: str = ""
    evidence_index: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    eval_provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RunManifest:
        data = dict(payload)
        data.pop("manifest_hash", None)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def build_manifest(
    *,
    run_id: str,
    reports_dir: Path,
    config: dict[str, Any] | None = None,
    mission_id: str = "",
    model: dict[str, str] | None = None,
    sandbox: dict[str, str] | None = None,
    eval_provenance: dict[str, Any] | None = None,
) -> RunManifest:
    """Build a manifest linking existing stores under reports/<run_id>/."""
    cfg = config if isinstance(config, dict) else {}
    manifest = RunManifest(
        run_id=run_id,
        mission_id=mission_id,
        started_at=_now_iso(),
        config_hash=_sha_short(cfg),
        model=dict(model or {}),
        sandbox=dict(sandbox or {}),
        eval_provenance=dict(eval_provenance or {}),
    )
    # Reuse RunProvenance hashes when available (TODO 018 fields).
    prov = manifest.eval_provenance
    for key in ("config_hash", "prompt_hash", "tool_catalog_hash", "skill_catalog_hash"):
        if prov.get(key):
            setattr(manifest, key, str(prov[key]))
    run_dir = Path(reports_dir) / run_id if (Path(reports_dir).name != run_id) else Path(reports_dir)
    candidates = {
        "research_db": "research_workspace/research.db",
        "api_runtime_db": "reports/api_runtime.db",
        "attack_states": "attack_states.json",
        "swarm_state": "swarm_state.json",
        "activity": str(run_dir / "activity.jsonl"),
        "decision_log": str(run_dir / "decision_log.jsonl"),
        "exploit_audit": str(run_dir / "exploit_audit.jsonl"),
        "report": str(run_dir / "enhanced" / "enhanced_report.json"),
    }
    manifest.state_stores = candidates
    manifest.decision_log = candidates["decision_log"]
    manifest.audit_log = candidates["activity"]
    # Evidence index: list artifact paths that exist.
    manifest.evidence_index = [p for p in candidates.values() if Path(p).exists()]
    return manifest


def write_manifest(reports_dir: Path, manifest: RunManifest) -> Path:
    run_dir = Path(reports_dir) / manifest.run_id if Path(reports_dir).name != manifest.run_id else Path(reports_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = manifest.to_dict()
    payload["manifest_hash"] = _sha_short(payload)
    out = run_dir / MANIFEST_FILENAME
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out


def read_manifest(path: Path) -> RunManifest:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = RunManifest.from_dict(payload)
    if manifest.version != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version {manifest.version}")
    return manifest


def validate_manifest(manifest: RunManifest) -> list[str]:
    """Return a list of problems (empty = valid). Finding->evidence traceability."""
    problems: list[str] = []
    if not manifest.run_id:
        problems.append("run_id missing")
    if manifest.version != MANIFEST_VERSION:
        problems.append(f"version {manifest.version} != {MANIFEST_VERSION}")
    for finding in manifest.findings:
        refs = finding.get("evidence_refs", []) if isinstance(finding, dict) else []
        for ref in refs:
            if ref not in manifest.evidence_index and not str(ref).startswith(("audit:", "sha256:", "reports/")):
                problems.append(f"finding {finding.get('id', '?')} refs missing evidence {ref}")
    return problems


def export_run_bundle(reports_dir: Path, run_id: str, dest: Path) -> Path:
    """Export reports/<run_id>/ + manifest into a portable zip."""
    run_dir = Path(reports_dir) / run_id
    if not run_dir.is_dir():
        raise FileNotFoundError(f"no such run: {run_dir}")
    dest = Path(dest)
    if dest.is_dir():
        dest = dest / f"{run_id}.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(run_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(run_dir.parent))
    return dest


def import_run_bundle(bundle: Path, reports_dir: Path) -> Path:
    """Import a bundle created by export_run_bundle (round-trip)."""
    with zipfile.ZipFile(bundle, "r") as zf:
        zf.extractall(Path(reports_dir))
    return Path(reports_dir)
