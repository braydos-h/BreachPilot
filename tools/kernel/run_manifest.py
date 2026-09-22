"""Unified Run Manifest (TODO 007): single index over fragmented state.

State lives in research.db, api_runtime.db, attack_states.json,
swarm_state.json, exploit_audit.jsonl, decision_log.jsonl, loot/,
campaign state, reports/<run_id>/. The manifest is the authoritative index:
run_id, mission_id, timestamps, config/model/sandbox identity (reusing
RunProvenance fields), store paths, decision/audit logs, evidence index,
findings, eval provenance. Subsystems stay independent; the manifest links them.

Lifecycle (p2-06):

- ``build_manifest()`` — run start only (write-once snapshot of candidates).
- ``update_manifest(run_dir)`` — refresh ``finished_at`` / ``state_stores`` /
  ``evidence_index`` / ``findings`` mid-run or at checkpoints; recomputes
  ``manifest_hash``. Requires an existing manifest (raises FileNotFoundError).
- ``finalize_manifest()`` — called ONCE at run end; builds when missing,
  otherwise updates. Wired into the run-service teardown
  (``tools/run_service/execute.py``), campaign end
  (``tools/campaign/orchestrator.py``) and swarm teardown
  (``tools/run_service/tasks.py::_wait_swarm``), all best-effort.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_VERSION = 1
MANIFEST_FILENAME = "run_manifest.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha_short(payload: dict[str, Any]) -> str:
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


def _candidate_stores(run_dir: Path) -> dict[str, str]:
    """All known store locations for a run (existing or not).

    Extends the original TODO 007 set with ``loot/``, campaign state
<<<<<<< Updated upstream
    (``attack_states.json``), the kill-chain graph (``killchain_graph.db``),
    the snapshot index (``snapshots_index.json``), the witness stream
    (``witness.jsonl``), the swarm blackboard (``swarm_workspace/``) and the
    per-target exploit workspaces (``exploit_workspace/``) when present — the
=======
    (``attack_states.json``), the kill-chain graph (``killchain_graph.db``)
    and the snapshot index (``snapshots_index.json``) when present — the
>>>>>>> Stashed changes
    refresh path prunes absent entries, so listing them here is free.
    """
    return {
        "research_db": "research_workspace/research.db",
        "api_runtime_db": "reports/api_runtime.db",
        "attack_states": "attack_states.json",
        "campaign_state": str(run_dir / "attack_states.json"),
        "swarm_state": "swarm_state.json",
        "activity": str(run_dir / "activity.jsonl"),
        "decision_log": str(run_dir / "decision_log.jsonl"),
        "exploit_audit": str(run_dir / "exploit_audit.jsonl"),
        "report": str(run_dir / "enhanced" / "enhanced_report.json"),
        "loot": str(run_dir / "loot"),
        "killchain_graph": str(run_dir / "killchain_graph.db"),
        "snapshots_index": str(run_dir / "snapshots_index.json"),
<<<<<<< Updated upstream
        "witness": str(run_dir / "witness.jsonl"),
        "swarm_workspace": "swarm_workspace",
        "exploit_workspace": "exploit_workspace",
=======
>>>>>>> Stashed changes
    }


def _existing_stores(run_dir: Path) -> dict[str, str]:
    """Candidate stores pruned to paths that actually exist."""
    return {name: path for name, path in _candidate_stores(run_dir).items() if Path(path).exists()}


def _collect_findings(run_dir: Path, manifest: RunManifest) -> list[dict[str, Any]]:
    """Refresh findings from run artifacts, preserving existing entries.

    Prefers the enhanced report (``enhanced/enhanced_report.json``) when it
    carries a ``findings`` list, else a ``findings.json`` sidecar, else the
    manifest's current findings. Never raises — a missing/unparseable
    artifact degrades to the preserved list.
    """
    try:
        report_path = run_dir / "enhanced" / "enhanced_report.json"
        if report_path.is_file():
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            findings = payload.get("findings") if isinstance(payload, dict) else None
            if isinstance(findings, list) and all(isinstance(f, dict) for f in findings):
                return [dict(f) for f in findings]
        sidecar = run_dir / "findings.json"
        if sidecar.is_file():
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            findings = payload.get("findings", payload) if isinstance(payload, dict) else payload
            if isinstance(findings, list) and all(isinstance(f, dict) for f in findings):
                return [dict(f) for f in findings]
    except (OSError, ValueError, TypeError):
        pass
    return list(manifest.findings)


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
    """Build a manifest linking existing stores under reports/<run_id>/.

    Run-start only: write-once snapshot. Mid-run refreshes go through
    :func:`update_manifest`; run end goes through :func:`finalize_manifest`.
    """
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
    candidates = _candidate_stores(run_dir)
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


def _resolve_run_dir(reports_dir: Path, run_id: str = "") -> Path:
    base = Path(reports_dir)
    if run_id and base.name != run_id:
        return base / run_id
    return base


def update_manifest(run_dir: Path) -> RunManifest:
    """Refresh a run's manifest in place; return the updated manifest.

    Refreshes ``finished_at``, ``state_stores`` (pruned to existing paths),
    ``evidence_index`` and ``findings``, then recomputes ``manifest_hash``
    via :func:`write_manifest`. Requires an existing manifest — raises
    ``FileNotFoundError`` when the run dir carries none (teardown call sites
    treat that as "nothing to refresh" and skip).
    """
    run_path = Path(run_dir)
    manifest_path = run_path / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise FileNotFoundError(f"no manifest in run dir: {run_path}")
    manifest = read_manifest(manifest_path)
    manifest.finished_at = _now_iso()
    manifest.state_stores = _existing_stores(run_path)
    # Keep the decision/audit pointers aimed at the refreshed stores; fall
    # back to the canonical run-dir paths when pruned (e.g. log not yet
    # written) so validate_manifest can report exactly what is missing.
    manifest.decision_log = manifest.state_stores.get("decision_log", str(run_path / "decision_log.jsonl"))
    manifest.audit_log = manifest.state_stores.get("activity", str(run_path / "activity.jsonl"))
    manifest.evidence_index = sorted(set(manifest.state_stores.values()))
    manifest.findings = _collect_findings(run_path, manifest)
    write_manifest(run_path, manifest)
    return manifest


def finalize_manifest(reports_dir: Path, run_id: str = "") -> RunManifest:
    """Finalize a run's manifest exactly once at run end.

    Builds a fresh manifest when the run dir carries none (crash paths where
    the start-of-run write never happened), otherwise refreshes via
    :func:`update_manifest`. Returns the finalized manifest.
    """
    run_path = _resolve_run_dir(reports_dir, run_id)
    if not (run_path / MANIFEST_FILENAME).is_file():
        manifest = build_manifest(run_id=run_path.name, reports_dir=run_path)
        write_manifest(run_path, manifest)
    return update_manifest(run_path)


def read_manifest(path: Path) -> RunManifest:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = RunManifest.from_dict(payload)
    if manifest.version != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version {manifest.version}")
    return manifest


def manifest_file_hash(path: Path) -> str:
    """Return the stored ``manifest_hash`` of a manifest file ("" when absent)."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    value = payload.get("manifest_hash", "") if isinstance(payload, dict) else ""
    return str(value)


def validate_manifest(manifest: RunManifest, *, manifest_hash: str = "") -> list[str]:
    """Return a list of problems (empty = valid). Finding->evidence traceability.

    When ``manifest_hash`` is supplied (see :func:`validate_manifest_file`),
    the recomputed content hash must match it — a tampered or hand-edited
    manifest fails validation. ``run_id``/``activity``/``audit_log`` are
    required, and every ``state_stores`` path must exist (stale refs fail).
    """
    problems: list[str] = []
    if not manifest.run_id:
        problems.append("run_id missing")
    if manifest.version != MANIFEST_VERSION:
        problems.append(f"version {manifest.version} != {MANIFEST_VERSION}")
    if manifest_hash:
        recomputed = _sha_short(manifest.to_dict())
        if recomputed != manifest_hash:
            problems.append(f"manifest_hash mismatch (stored {manifest_hash} != recomputed {recomputed})")
    if not manifest.audit_log:
        problems.append("audit_log missing")
    elif not Path(manifest.audit_log).exists():
        problems.append(f"audit_log missing on disk: {manifest.audit_log}")
    activity = manifest.state_stores.get("activity", "")
    if not activity:
        problems.append("activity store missing")
    elif not Path(activity).exists():
        problems.append(f"activity store missing on disk: {activity}")
    for name, path in manifest.state_stores.items():
        if not Path(path).exists():
            problems.append(f"stale state_stores ref {name}: {path}")
    for finding in manifest.findings:
        refs = finding.get("evidence_refs", []) if isinstance(finding, dict) else []
        for ref in refs:
            if ref not in manifest.evidence_index and not str(ref).startswith(("audit:", "sha256:", "reports/")):
                problems.append(f"finding {finding.get('id', '?')} refs missing evidence {ref}")
    return problems


def validate_manifest_file(path: Path) -> list[str]:
    """Validate a manifest file on disk, including its stored content hash."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"unreadable manifest: {exc}"]
    if not isinstance(payload, dict):
        return ["manifest payload is not an object"]
    stored_hash = str(payload.get("manifest_hash", ""))
    if not stored_hash:
        return ["manifest_hash missing"]
    manifest = RunManifest.from_dict(payload)
    return validate_manifest(manifest, manifest_hash=stored_hash)


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


def _is_safe_member(name: str) -> bool:
    """Reject zip members that escape the destination (path traversal)."""
    if not name or name.startswith(("/", "\\")):
        return False
    if len(name) > 1 and name[1] == ":":
        return False
    parts = Path(name).parts
    if ".." in parts:
        return False
    return True


def import_run_bundle(bundle: Path, reports_dir: Path) -> Path:
    """Import a bundle created by export_run_bundle; return the run dir path.

    Hardened: rejects path-traversal members (absolute paths, ``..``
    segments, drive-letter prefixes), verifies the embedded manifest's
    version and content hash, and returns the imported run dir
    (``reports_dir/<run_id>``) rather than the reports root.
    """
    dest_root = Path(reports_dir)
    with zipfile.ZipFile(bundle, "r") as zf:
        members = [info for info in zf.infolist() if not info.is_dir()]
        for info in members:
            if not _is_safe_member(info.filename):
                raise ValueError(f"import rejected: unsafe zip member {info.filename!r}")
        # The bundle root must be a single run dir; resolve it from the first
        # member before writing anything.
        top_levels = {Path(info.filename).parts[0] for info in members}
        if len(top_levels) != 1:
            raise ValueError(f"import rejected: bundle must contain exactly one run dir, found {sorted(top_levels)}")
        run_id = next(iter(top_levels))
        for info in members:
            target = dest_root / info.filename
            # Belt-and-braces: resolved target must stay under dest_root even
            # if the member list passed the string checks above.
            try:
                target.resolve().relative_to(dest_root.resolve())
            except ValueError:
                raise ValueError(f"import rejected: member escapes destination: {info.filename!r}") from None
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src:
                target.write_bytes(src.read())
        manifest_path = dest_root / run_id / MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise ValueError(f"import rejected: bundle carries no {MANIFEST_FILENAME}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ValueError(f"import rejected: manifest is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("version") != MANIFEST_VERSION:
            raise ValueError(
                f"import rejected: unsupported manifest version {payload.get('version') if isinstance(payload, dict) else '?'}"
            )
        stored_hash = str(payload.get("manifest_hash", ""))
        if not stored_hash or _sha_short(RunManifest.from_dict(payload).to_dict()) != stored_hash:
            raise ValueError("import rejected: manifest_hash verification failed")
    return dest_root / run_id
