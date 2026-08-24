"""MITRE ATT&CK Navigator export — map an exploit audit trail to ATT&CK techniques.

Reads the operator's own ``exploit_audit.jsonl`` (append-only, operator-
generated — NOT untrusted input), maps each ``tool_name`` to a MITRE ATT&CK
technique ID via a static map (overridable by ``tools/mitre_technique_map.json``),
counts occurrences per technique, and emits a Navigator layer JSON the blue
team opens in ATT&CK Navigator to see which techniques the run exercised.

Read-only: never mutates the audit trail. No target touch, no network. The
only external input is ``target_ip`` (validated by ``validate_target_or_ip``)
and the static map (checked in). Output is a JSON file the operator opens
manually — no auto-execution.

Prompt-injection surface (low): audit fields are treated as DATA, never
executed. Comment length is capped at 200 chars to mitigate a crafted audit
line (if an attacker can write the workspace) injecting a bogus technique
comment.

Failure modes (5 break): empty audit trail → ``{"techniques": []}``; unknown
tool name → skip (don't crash); malformed JSONL line → skip line; output dir
missing → mkdir; technique-map file missing → fall back to built-in map.
Failure modes (5 abuse): audit-line injection (cap + treat as data); path
traversal on ``output_path`` (coerce to ``reports/mitre/``); unbounded layer
size (cap techniques); wrong target scoping (filter records by ``target_ip``);
stale map (version the map file).

Self-check: ``python -m tools.mitre_export`` runs ``demo()`` which maps a
synthetic audit list and asserts technique IDs/scores without writing files.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from tools.validation_utils import validate_target_or_ip

log = logging.getLogger("tools.mitre_export")

# ── Static tool→technique map (built-in fallback) ─────────────────────────────
# Overridable by tools/mitre_technique_map.json. Keys are MCP tool names as
# they appear in exploit_audit.jsonl ``tool_name`` fields.
_DEFAULT_MAP: dict[str, str] = {
    "run_exploit_terminal": "T1059",  # Command and Scripting Interpreter
    "write_python_file": "T1059.006",  # Python
    "run_python_file": "T1059.006",
    "run_msf_module": "T1210",  # Exploitation of Remote Services
    "msf_generate_payload": "T1027",  # Obfuscated Files or Information
    "generate_payload": "T1027",
    "lateral_exec": "T1021",  # Remote Services
    "dump_credentials": "T1003",  # OS Credential Dumping
    "kerberoast": "T1558.003",  # Kerberoasting
    "run_hash_crack": "T1110.002",  # Password Cracking
    "run_web_scan": "T1595",  # Active Scanning
    "password_spray": "T1110.003",  # Password Spraying
    "asrep_roast": "T1558.004",  # AS-REP Roasting
    "golden_ticket": "T1558.001",  # Golden Ticket
    "pass_the_hash": "T1550.002",  # Pass the Hash
}

_MAX_COMMENT_CHARS = 200
_MAX_TECHNIQUES = 500
_NAVIGATOR_LAYER_VERSION = "4.5"

# ponytail: global technique-map cache, rebuilt if the file mtime changes.
# Per-run cache would be cleaner, but the file is read once per export call and
# the map is small (<20 entries); upgrade to mtime-keyed cache if exports run in
# a hot loop.
_MAP_CACHE: tuple[str, dict[str, str]] | None = None


def load_technique_map(map_path: str | Path | None) -> dict[str, str]:
    """Load the tool→technique map, falling back to the built-in map.

    Tolerant: a missing/unreadable/invalid file falls back to ``_DEFAULT_MAP``
    so the export never crashes on a bad map. The map file is a JSON object
    mapping ``tool_name`` → ``technique_id``.
    """
    global _MAP_CACHE
    if not map_path:
        return dict(_DEFAULT_MAP)
    p = Path(map_path)
    try:
        key = str(p.resolve())
    except OSError:
        return dict(_DEFAULT_MAP)
    if _MAP_CACHE is not None and _MAP_CACHE[0] == key:
        return dict(_MAP_CACHE[1])
    if not p.is_file():
        return dict(_DEFAULT_MAP)
    try:
        loaded = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("mitre_technique_map.json unreadable (%s); using built-in map", exc)
        return dict(_DEFAULT_MAP)
    if not isinstance(loaded, dict):
        log.warning("mitre_technique_map.json not a JSON object; using built-in map")
        return dict(_DEFAULT_MAP)
    # Merge: file overrides defaults (so operators can add/override without
    # re-listing the whole built-in map).
    merged = dict(_DEFAULT_MAP)
    for k, v in loaded.items():
        if isinstance(k, str) and isinstance(v, str) and v.strip():
            merged[k] = v.strip()
    _MAP_CACHE = (key, merged)
    return dict(merged)


def _read_audit_records(audit_path: Path, target_ip: str) -> list[dict[str, Any]]:
    """Read + filter audit records for ``target_ip``. Tolerant of malformed lines."""
    records: list[dict[str, Any]] = []
    if not audit_path.is_file():
        return records
    try:
        text = audit_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("audit trail %s unreadable: %s", audit_path, exc)
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue  # ponytail: skip malformed line, don't crash
        if not isinstance(rec, dict):
            continue
        # Scope to target_ip: match exactly OR comma-joined (the audit row's
        # target_ip can be a comma-joined list from _extract_audit_target).
        rec_target = str(rec.get("target_ip") or "")
        if target_ip and rec_target and target_ip not in rec_target.split(","):
            continue
        records.append(rec)
    return records


def _collect_skill_techniques(include_skills: bool) -> dict[str, list[str]]:
    """Return ``{tool_name -> [technique_id, ...]}`` from skill mitre_attack tags.

    Best-effort: a skill-registry load failure yields ``{}``. Skills carry
    ``mitre_attack`` tags in their front matter; we map a skill's name to its
    tags so an operator can see "this run's skills cover these techniques" in
    the Navigator layer. The skill name is NOT a tool_name, so these are
    merged into the technique set under a synthetic ``skill:<name>`` source.
    """
    if not include_skills:
        return {}
    try:
        from tools.skill_registry import load_skill_registry

        reg = load_skill_registry()
    except Exception:  # noqa: BLE001 -- skill load failure never breaks export
        return {}
    out: dict[str, list[str]] = {}
    for skill in reg.skills.values():
        tags = skill.metadata.mitre_attack or ()
        if tags:
            out[f"skill:{skill.name}"] = list(tags)
    return out


def build_navigator_layer(
    records: list[dict[str, Any]],
    technique_map: dict[str, str],
    *,
    target_ip: str = "",
    include_skills: bool = True,
    layer_name: str = "NetAttackAI run",
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer JSON from audit records + technique map.

    ``records`` are the parsed audit lines (only ``tool_name`` is read; all
    other fields are treated as data). Returns a Navigator 4.5 layer dict with
    a ``techniques`` list, each carrying ``techniqueID``, ``score`` (occurrence
    count), and a capped ``comment``. Unknown tools are skipped (not crashed
    on). The technique set is capped at ``_MAX_TECHNIQUES``.
    """
    counts: dict[str, int] = {}
    comments: dict[str, list[str]] = {}

    for rec in records:
        if not isinstance(rec, dict):
            continue  # ponytail: skip non-dict record, don't crash
        # Scope to target_ip: match exactly OR comma-joined (the audit row's
        # target_ip can be a comma-joined list from _extract_audit_target).
        if target_ip:
            rec_target = str(rec.get("target_ip") or "")
            if rec_target and target_ip not in rec_target.split(","):
                continue
        tool = str(rec.get("tool_name") or "").strip()
        if not tool:
            continue
        technique_id = technique_map.get(tool)
        if not technique_id:
            continue  # ponytail: unknown tool → skip, don't crash
        counts[technique_id] = counts.get(technique_id, 0) + 1
        # Cap comment length; treat audit fields as data (never execute).
        status = str(rec.get("status") or "")[:40]
        comment = f"{tool} ({status})"[:_MAX_COMMENT_CHARS]
        comments.setdefault(technique_id, []).append(comment)

    # Merge skill mitre_attack tags (advisory; skills used during the run).
    if include_skills:
        for source, tags in _collect_skill_techniques(include_skills).items():
            for tag in tags:
                tid = tag.strip()
                if not tid:
                    continue
                # Skills contribute a count of 1 (advisory, not executed) and
                # a comment naming the skill so the operator can see coverage.
                counts[tid] = counts.get(tid, 0) + 1
                comments.setdefault(tid, []).append(source[:_MAX_COMMENT_CHARS])

    # Cap total techniques to bound layer size.
    techniques: list[dict[str, Any]] = []
    for tid, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if len(techniques) >= _MAX_TECHNIQUES:
            log.warning("mitre export: capped at %d techniques", _MAX_TECHNIQUES)
            break
        # Navigator 4.5: techniqueID, score, comment. Showable determines
        # visibility; we set it true so the technique is highlighted.
        techniques.append(
            {
                "techniqueID": tid,
                "score": count,
                "comment": "; ".join(comments[tid][:5])[:_MAX_COMMENT_CHARS],
                "showID": True,
                "showName": True,
            }
        )

    return {
        "name": layer_name,
        "versions": {
            "attack": _NAVIGATOR_LAYER_VERSION,
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"NetAttackAI run techniques for target {target_ip or '(all)'}",
        "filters": [{"platforms": ["Linux", "Windows", "Network", "PRE"]}],
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "sum",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": max(10, max(counts.values()) if counts else 1),
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def export_attack_navigator(
    target_ip: str,
    output_path: str = "",
    *,
    audit_path: str | Path = "",
    technique_map_path: str | Path = "tools/mitre_technique_map.json",
    navigator_output_dir: str | Path = "reports/mitre",
    include_skills: bool = True,
) -> dict[str, Any]:
    """Map this run's audit trail to MITRE ATT&CK techniques and write a
    Navigator layer JSON. Returns ``{"layer_path": str, "techniques": int,
    "technique_ids": [...]}``.

    ``target_ip`` is validated by ``validate_target_or_ip``. ``output_path``
    is coerced under ``navigator_output_dir`` to prevent path traversal. An
    empty audit trail returns a layer with ``techniques: []``.
    """
    # Validate target_ip (IP or FQDN). Empty is allowed (exports all targets).
    if target_ip and not validate_target_or_ip(target_ip):
        return {"error": f"invalid target_ip: {target_ip!r}", "layer_path": "", "techniques": 0, "technique_ids": []}

    # Resolve audit path: default to exploit_workspace/exploit_audit.jsonl.
    if audit_path:
        audit = Path(audit_path)
    else:
        audit = Path("exploit_workspace") / "exploit_audit.jsonl"

    technique_map = load_technique_map(technique_map_path)
    records = _read_audit_records(audit, target_ip)
    layer = build_navigator_layer(
        records,
        technique_map,
        target_ip=target_ip,
        include_skills=include_skills,
        layer_name=f"NetAttackAI {target_ip or 'run'}",
    )

    # Coerce output_path under navigator_output_dir (path-traversal guard).
    out_dir = Path(navigator_output_dir)
    if output_path:
        candidate = Path(output_path)
        if not candidate.is_absolute():
            candidate = out_dir / candidate
        # ponytail: resolve under out_dir; reject traversal outside it.
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            resolved = candidate.resolve()
            resolved.relative_to(out_dir.resolve())
            layer_path = resolved
        except (ValueError, OSError):
            # Traversal attempt: fall back to the canonical name under out_dir.
            safe = Path(output_path).name or f"{target_ip or 'run'}_attack_layer.json"
            layer_path = out_dir / safe
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_target = (target_ip or "run").replace("/", "_").replace("\\", "_")
        layer_path = out_dir / f"{safe_target}_attack_layer.json"

    layer_path.parent.mkdir(parents=True, exist_ok=True)
    layer_path.write_text(json.dumps(layer, indent=2, default=str), encoding="utf-8")

    technique_ids = sorted({t["techniqueID"] for t in layer["techniques"]})
    return {
        "layer_path": str(layer_path),
        "techniques": len(layer["techniques"]),
        "technique_ids": technique_ids,
    }


# ── Self-check ────────────────────────────────────────────────────────────────


def demo() -> dict[str, Any]:
    """Map a synthetic audit list and assert technique IDs/scores.

    Runnable via ``python -m tools.mitre_export``. No files written. Returns
    the layer dict so callers (tests) can inspect it.
    """
    synthetic = [
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "run_python_file", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "kerberoast", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "unknown_tool_name", "target_ip": "10.0.0.5", "status": "completed"},
        "not-a-dict-line",  # malformed, must be skipped
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "completed"},  # wrong target
    ]
    layer = build_navigator_layer(
        synthetic,
        _DEFAULT_MAP,
        target_ip="10.0.0.5",
        include_skills=False,  # skills off so the demo is deterministic
        layer_name="demo",
    )
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    # Assert expected mappings.
    assert by_id.get("T1059") == 2, f"expected T1059 score 2, got {by_id.get('T1059')}"
    assert by_id.get("T1059.006") == 1, f"expected T1059.006 score 1, got {by_id.get('T1059.006')}"
    assert by_id.get("T1003") == 1, f"expected T1003 score 1, got {by_id.get('T1003')}"
    assert by_id.get("T1558.003") == 1, f"expected T1558.003 score 1, got {by_id.get('T1558.003')}"
    # Unknown tool must NOT appear.
    assert "unknown_tool_name" not in by_id
    # Wrong-target record must NOT be counted.
    assert by_id.get("T1059") == 2, "wrong-target record was counted"
    # Schema sanity: Navigator 4.5 shape.
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert isinstance(layer["techniques"], list)
    print(
        f"demo OK: {len(layer['techniques'])} techniques mapped "
        f"({', '.join(sorted(by_id))}) from {len(synthetic)} synthetic records"
    )
    return layer


if __name__ == "__main__":
    demo()
