"""Repeat a finding probe and persist a conservative retest result.

``retest_finding`` reloads a finding's stored verification probe
from the run artifacts (``reports/<run_id>/enhanced/enhanced_report.json``)
and re-executes only that probe through the sandbox:

- verdict ``INCONCLUSIVE`` — generic sandbox worker output cannot establish
  target state, whether it contains access-shaped markers or an apparent
  failure. This tool does not currently have a target-bound verifier.

Reuse (no new execution paths, no new stores):

- probe vocabulary is the ``shell_command`` check-spec shape shared with the
  killchain verify specs (``tools/killchain/edges.py``) and ``eval_checks``
  shell semantics (nonzero-exit-tolerant, output-content judged);
- the verdict reuses the authoritative ``outcome_truth`` classifier
  (``tools/exploit_agent/outcome_truth.py``), never raw output words;
- the probe runs through the already-registered ``run_exploit_terminal``
  tool function in-process (the killchain playbook-dispatch precedent), so
  the target-IP allowlist lock, the JSONL audit trail, and the sandbox
  funnel apply unchanged — sandbox failures surface as ``SANDBOX_*`` text
  and classify ``INCONCLUSIVE`` (fail closed, never a host fallback);
- snapshot state is read best-effort via ``SnapshotManager.list``
  (index read only, fail-open per the snapshots contract) and attached as
  context — a snapshot failure never blocks the retest;
- results persist into the EXISTING run artifact JSON
  (``retest_status`` + ``retest_history[]`` on the finding; sibling
  ``.md``/``.html`` regenerated when present). No new DB, no migration.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.enhanced_reporting import EnhancedReportGenerator
from tools.exploit_agent.outcome_truth import ExploitOutcome, classify_exploit_outcome

# Canonical lifecycle vocabulary — the ONLY definition lives in
# tools.kernel.finding_lifecycle (re-exported here so existing
# ``from tools.mcp_tools.retest import FIXED`` paths keep working).
# No per-lane frozenset is duplicated here: record_retest validates against
# the canonical (STILL_OPEN, FIXED, INCONCLUSIVE) triple imported below and
# every transition goes through check_transition.
from tools.kernel.finding_lifecycle import FIXED, INCONCLUSIVE, STILL_OPEN
from tools.mcp_tools.registry import ToolContext

# Output markers that mean "the probe did not run to a verdict" — execution
# containment / policy denials, never evidence the hole closed.
_INCONCLUSIVE_MARKERS = ("SANDBOX_", "BLOCKED:", "TOOL_EXECUTION_ERROR:", "UNKNOWN_TOOL:", "ERROR:")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reports_root(config: dict[str, Any] | None) -> Path:
    """Resolve the reports root (injectable for tests via config/env)."""
    cfg = config or {}
    for candidate in (cfg.get("reports_dir"), os.environ.get("BREACHPILOT_REPORTS_DIR")):
        if candidate:
            return Path(str(candidate))
    return Path("reports")


def _finding_file(run_dir: Path) -> Path:
    return run_dir / "enhanced" / "enhanced_report.json"


def _iter_run_dirs(root: Path) -> list[Path]:
    """Run dirs (newest first) that hold an enhanced report JSON."""
    if not root.is_dir():
        return []
    dirs = [p for p in root.iterdir() if p.is_dir() and _finding_file(p).is_file()]
    dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return dirs


def _read_report_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LookupError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LookupError(f"report {path} is not a JSON object")
    return data


def _find_in_report(data: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    findings = data.get("technical_findings")
    if not isinstance(findings, list):
        return None
    for item in findings:
        if isinstance(item, dict) and str(item.get("finding_id", "")) == finding_id:
            return item
    return None


def locate_finding(
    reports_root: Path | str,
    finding_id: str,
    run_id: str = "",
) -> tuple[dict[str, Any], dict[str, Any], Path, str]:
    """Load ``(report_data, finding, json_path, resolved_run_id)`` or raise LookupError."""
    fid = (finding_id or "").strip()
    if not fid:
        raise LookupError("finding_id is required")
    root = Path(reports_root)
    if run_id and run_id.strip():
        rid = run_id.strip()
        path = _finding_file(root / rid)
        if not path.is_file():
            raise LookupError(f"run {rid!r} has no enhanced report ({path})")
        data = _read_report_json(path)
        finding = _find_in_report(data, fid)
        if finding is None:
            raise LookupError(f"finding {fid!r} not present in run {rid!r}")
        return data, finding, path, rid
    for run_dir in _iter_run_dirs(root):
        try:
            data = _read_report_json(_finding_file(run_dir))
        except LookupError:
            continue
        finding = _find_in_report(data, fid)
        if finding is not None:
            return data, finding, _finding_file(run_dir), run_dir.name
    raise LookupError(f"finding {fid!r} not found in any run under {root}")


def resolve_probe(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return the stored verification probe, or None when absent (missing-PoC)."""
    probe = finding.get("verification_probe")
    if not isinstance(probe, dict):
        return None
    if not str(probe.get("exec", "") or "").strip():
        return None
    return probe


def resolve_exec(probe: dict[str, Any], target_ip: str) -> str:
    """Fill ``{target_ip}``/``{target}`` placeholders (killchain edge precedent)."""
    cmd = str(probe.get("exec", "") or "")
    return cmd.replace("{target_ip}", target_ip).replace("{target}", target_ip)


def classify_retest_output(output: str) -> tuple[str, str]:
    """Map untrusted probe text to ``(verdict, detail)`` without claiming proof.

    ``run_exploit_terminal`` returns output from the sandbox worker, not an
    authenticated target shell. Neither access-shaped text nor a failed probe
    establishes target state, so generic output can never prove a finding is
    still open or fixed. Only containment markers receive a more specific
    detail; all other text remains INCONCLUSIVE.
    """
    text = str(output or "")
    stripped = text.strip()
    if not stripped:
        return INCONCLUSIVE, "empty probe output"
    for marker in _INCONCLUSIVE_MARKERS:
        if marker in text:
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            # ponytail: prefer the marker-bearing line so SANDBOX_* codes surface in DETAIL.
            detail = next((ln for ln in lines if marker in ln), lines[0] if lines else marker)
            return INCONCLUSIVE, detail[:300]
    outcome = classify_exploit_outcome(text).get("outcome", ExploitOutcome.UNKNOWN)
    return INCONCLUSIVE, f"unverified outcome_truth={outcome}"


def record_retest(
    finding: dict[str, Any],
    verdict: str,
    evidence: str,
    *,
    now: str = "",
) -> dict[str, Any]:
    """Stamp ``retest_status`` + append ``retest_history[]`` (mutates, returns finding).

    The step is validated against the canonical lifecycle
    (:func:`check_transition` with actor ``"retest"``): only ``VERIFIED``
    findings open a retest (``-> STILL_OPEN`` / ``FIXED``) and only
    ``STILL_OPEN`` findings close to ``FIXED`` — retesting a ``REJECTED`` /
    ``FIXED`` / ``PROPOSED`` finding raises ``ValueError`` (a retest can
    never revive a terminal state or skip verification). An idempotent
    re-stamp (same verdict as current) falls through without a transition.
    ``INCONCLUSIVE`` never transitions (it records an attempt, not a state
    change) so it stamps from any state, terminal included.
    """
    if verdict not in (STILL_OPEN, FIXED, INCONCLUSIVE):
        raise ValueError(f"unknown retest verdict {verdict!r}")
    from tools.kernel.finding_lifecycle import INCONCLUSIVE as _L_INCONCLUSIVE
    from tools.kernel.finding_lifecycle import check_transition, current_state

    if verdict != _L_INCONCLUSIVE and current_state(finding) != verdict:
        check_transition(current_state(finding), verdict, "retest")
    finding["retest_status"] = verdict
    history = finding.get("retest_history")
    if not isinstance(history, list):
        history = []
        finding["retest_history"] = history
    history.append({"timestamp": now or _now_iso(), "verdict": verdict, "evidence": str(evidence or "")})
    return finding


def persist_retest(
    json_path: Path | str,
    finding_id: str,
    verdict: str,
    evidence: str,
    *,
    now: str = "",
) -> dict[str, Any]:
    """Persist one retest verdict into the existing run artifact JSON.

    Updates ``technical_findings[]`` in place and regenerates the sibling
    ``.md``/``.html`` reports when they sit next to the JSON (same stem).
    Returns the updated finding dict.
    """
    path = Path(json_path)
    data = _read_report_json(path)
    finding = _find_in_report(data, (finding_id or "").strip())
    if finding is None:
        raise LookupError(f"finding {finding_id!r} not present in {path}")
    record_retest(finding, verdict, evidence, now=now)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    # ponytail: reuse the existing renderers so the verdict lands in the
    # report the operator already reads; only touch siblings that exist.
    # Best-effort: a partial/hand-written JSON must never break persistence.
    try:
        renderer = EnhancedReportGenerator(db=None, mission_id="", workspace=path.parent.parent)
        for suffix, method in ((".md", "_generate_markdown"), (".html", "_generate_html")):
            sibling = path.with_suffix(suffix)
            if sibling.is_file():
                sibling.write_text(getattr(renderer, method)(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 -- report refresh is best-effort; the JSON above is the record
        pass
    return finding


def _parse_ts(value: Any) -> float | None:
    """Parse an ISO-8601 timestamp to epoch seconds; None when absent/unparseable."""
    from datetime import datetime

    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    try:
        return parsed.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def _history_verdicts(finding: dict[str, Any], key: str) -> list[tuple[str, float | None]]:
    """Return ``(verdict, epoch-or-None)`` pairs from a finding history list."""
    entries = finding.get(key)
    if not isinstance(entries, list):
        return []
    out: list[tuple[str, float | None]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        out.append((str(entry.get("verdict", "") or ""), _parse_ts(entry.get("timestamp", ""))))
    return out


def aggregate_retest_lifecycle(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate the FIXED remediation lifecycle over stored finding dicts.

    Pure function over the existing run-artifact shape (``verify_history[]`` /
    ``retest_history[]`` + ``retest_status``); no I/O, no probe execution.
    Feeds reliability metric #11 (mean time finding → verified remediation):

    - a finding counts as *verified* when it carries at least one ``VERIFIED``
      ``verify_history`` entry (or a ``verify_status`` of ``VERIFIED``);
    - a finding counts as *remediated* (``FIXED``) when its ``retest_status``
      is ``FIXED`` or any ``retest_history`` entry reads ``FIXED``;
    - time-to-fix is the last ``FIXED`` timestamp minus the first ``VERIFIED``
      timestamp, over findings where both parse; unparseable or missing
      timestamps exclude that finding from the mean (never fabricated).
    """
    from tools.mcp_tools.verify import VERIFIED as _VERIFIED

    total = 0
    verified = 0
    fixed_ids: list[str] = []
    fix_times: list[float] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        total += 1
        verify_entries = _history_verdicts(finding, "verify_history")
        verified_here = (
            any(v == _VERIFIED for v, _ in verify_entries)
            or str(finding.get("verify_status", "") or "").strip() == _VERIFIED
        )
        if verified_here:
            verified += 1
        retest_entries = _history_verdicts(finding, "retest_history")
        fixed_here = str(finding.get("retest_status", "") or "").strip() == FIXED or any(
            v == FIXED for v, _ in retest_entries
        )
        if not fixed_here:
            continue
        fid = str(finding.get("finding_id", "") or "")
        fixed_ids.append(fid)
        first_verified = next((ts for v, ts in verify_entries if v == _VERIFIED and ts is not None), None)
        fixed_times = [ts for v, ts in retest_entries if v == FIXED and ts is not None]
        if first_verified is not None and fixed_times:
            delta = max(fixed_times) - first_verified
            if delta >= 0:
                fix_times.append(delta)
    mean_fix: float | None = round(sum(fix_times) / len(fix_times), 2) if fix_times else None
    return {
        "total_findings": total,
        "verified_findings": verified,
        "fixed_count": len(fixed_ids),
        "fixed_finding_ids": fixed_ids,
        "remediation_times_seconds": [round(t, 2) for t in fix_times],
        "mean_time_to_fix_seconds": mean_fix,
    }


def _snapshot_note(config: dict[str, Any] | None, ctx: Any, target_ip: str) -> str:
    """Best-effort snapshot context (fail-open: any failure → "")."""
    try:
        from tools.snapshots import SnapshotManager, _vm_id_for_target

        manager = SnapshotManager(config, index_dir=Path(str(getattr(ctx, "workspace", "."))))
        vm_id = _vm_id_for_target(target_ip, config)
        count = len(manager.list(vm_id))
        return f"snapshots recorded for target: {count}"
    except Exception:  # noqa: BLE001 -- snapshots fail open, never block the retest
        return ""


def format_retest_block(
    *,
    finding_id: str,
    target_ip: str,
    run_id: str,
    verdict: str,
    probe_excerpt: str,
    evidence: str,
    detail: str,
) -> str:
    lines = [
        "RETEST_VERDICT:",
        f"FINDING: {finding_id}",
        f"TARGET: {target_ip}",
        f"RUN: {run_id}",
        f"VERDICT: {verdict}",
        f"PROBE: {probe_excerpt[:300]}",
        f"EVIDENCE: {evidence}",
        f"DETAIL: {detail[:500]}",
    ]
    return "\n".join(lines)


async def _run_probe_in_process(mcp: Any, command: str) -> str:
    """Re-execute ONLY the probe via run_exploit_terminal (allowlist+audit+sandbox apply)."""
    from tools.mcp_tools.killchain import _in_process_tool_executor

    executor = _in_process_tool_executor(mcp)
    return str(await executor("run_exploit_terminal", {"command": command}))


def register_retest_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def retest_finding(target_ip: str, finding_id: str, run_id: str = "") -> str:
        """Repeat a stored finding probe and record an unverified diagnostic.

        The probe runs only through ``run_exploit_terminal`` so allowlist,
        audit, and sandbox controls apply. Its worker output is not target-bound
        proof, so this tool currently returns INCONCLUSIVE for both success-
        shaped and failure-shaped output. STILL_OPEN and FIXED require a trusted
        target-bound verifier and are not produced by this execution path.

        Args:
            target_ip: Current address of the finding's asset (must equal the finding's affected_asset and be allowlisted).
            finding_id: Finding to retest (e.g. ``F-10-0-0-50-run_exploit_terminal``).
            run_id: Run holding the finding; empty = latest run containing it.
        """
        if not finding_id or not finding_id.strip():
            return "BLOCKED: finding_id is required."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        target = target_ip.strip()
        fid = finding_id.strip()
        try:
            _data, finding, json_path, resolved_run = locate_finding(_reports_root(config), fid, (run_id or "").strip())
        except LookupError as exc:
            return f"ERROR: retest_finding: {exc}"
        asset = str(finding.get("affected_asset", "") or "").strip()
        if asset.lower() != target.lower():
            return (
                f"BLOCKED: target_ip {target!r} does not match the finding's affected_asset "
                f"{asset!r} — retest runs ONLY against the finding's own asset."
            )
        probe = resolve_probe(finding)
        if probe is None:
            verdict, evidence = INCONCLUSIVE, "no stored verification probe for this finding"
            try:
                persist_retest(json_path, fid, verdict, evidence)
            except (OSError, ValueError, LookupError):
                pass
            return format_retest_block(
                finding_id=fid,
                target_ip=target,
                run_id=resolved_run,
                verdict=verdict,
                probe_excerpt="(none stored)",
                evidence=str(json_path),
                detail=evidence,
            )
        command = resolve_exec(probe, target)
        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                output = asyncio.run(_run_probe_in_process(mcp, command))
            else:
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    output = pool.submit(asyncio.run, _run_probe_in_process(mcp, command)).result()
        except Exception as exc:  # noqa: BLE001 -- executor crash is INCONCLUSIVE, never a pass
            output = f"TOOL_EXECUTION_ERROR: {exc}"
        verdict, detail = classify_retest_output(output)
        snapshot = _snapshot_note(config, ctx, target)
        evidence = str(json_path)
        if snapshot:
            evidence = f"{evidence}; {snapshot}"
        history_evidence = f"probe output: {str(output).strip()[:300] or '(empty)'}"
        try:
            persist_retest(json_path, fid, verdict, history_evidence)
        except (OSError, ValueError, LookupError):
            evidence = f"{evidence} (persistence failed — verdict not saved)"
        probe_id = str(probe.get("id", "") or probe.get("type", "shell_command"))
        return format_retest_block(
            finding_id=fid,
            target_ip=target,
            run_id=resolved_run,
            verdict=verdict,
            probe_excerpt=f"[{probe_id}] {command}",
            evidence=evidence,
            detail=detail,
        )


__all__ = [
    "FIXED",
    "INCONCLUSIVE",
    "STILL_OPEN",
    "aggregate_retest_lifecycle",
    "classify_retest_output",
    "format_retest_block",
    "locate_finding",
    "persist_retest",
    "record_retest",
    "register_retest_tools",
    "resolve_exec",
    "resolve_probe",
]


def demo() -> None:
    """Show that raw probe text cannot prove open or fixed state (no network)."""
    import tempfile

    print("retest demo: generic worker output stays INCONCLUSIVE")
    with tempfile.TemporaryDirectory(prefix="retest_demo_") as tmp:
        root = Path(tmp)
        run_dir = root / "runA"
        (run_dir / "enhanced").mkdir(parents=True)
        report = {
            "report_metadata": {"mission_id": "demo"},
            "technical_findings": [
                {
                    "finding_id": "F-10-0-0-50-poc",
                    "title": "demo finding on 10.0.0.50",
                    "affected_asset": "10.0.0.50",
                    "verification_probe": {"type": "shell_command", "exec": "curl -s http://10.0.0.50/poc"},
                    "retest_status": "",
                    "retest_history": [],
                }
            ],
        }
        json_path = run_dir / "enhanced" / "enhanced_report.json"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        # Access-shaped worker output does not prove target state.
        verdict, _ = classify_retest_output("exploit ok\nuid=0(root) gid=0(root)")
        assert verdict == INCONCLUSIVE, verdict
        persist_retest(json_path, "F-10-0-0-50-poc", verdict, "demo confirm")
        print(f"  shell marker     -> {verdict}")

        # A connection error is also insufficient to prove remediation.
        verdict, _ = classify_retest_output("curl: (7) Failed to connect: connection refused")
        assert verdict == INCONCLUSIVE, verdict
        finding = persist_retest(json_path, "F-10-0-0-50-poc", verdict, "demo patched")
        print(f"  connection error -> {verdict}")

        assert finding["retest_status"] == INCONCLUSIVE
        assert [h["verdict"] for h in finding["retest_history"]] == [INCONCLUSIVE, INCONCLUSIVE]
        print(f"  evidence refs: {json_path}")
    print("demo OK: raw output did not promote verification or remediation state")


if __name__ == "__main__":
    demo()
