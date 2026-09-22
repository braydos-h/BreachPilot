"""Docker target-suite scoring (split from tools.eval_harness)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tools.eval.single_run import run_eval


def _eval_shim(name: str, default: Callable[..., Any]) -> Callable[..., Any]:
    """Resolve ``name`` through the ``tools.eval_harness`` compat shim at call time.

    Patch-seam contract (precedent: ``tools/campaign/phases.py`` resolves
    ``find_modules`` through ``tools.autonomous_orchestrator``): the suite
    historically patched ``tools.eval_harness.run_eval`` /
    ``docker_suite_up`` / ``docker_suite_down`` /
    ``open_exploit_mcp_session`` / ``default_check_executor``. Those tests
    keep patching the shim, so the call sites below resolve through it at
    call time instead of binding this module's globals directly.
    """
    try:
        import tools.eval_harness as _shim
    except ImportError:  # pragma: no cover - shim always present in-repo
        return default
    return getattr(_shim, name, default)


# ---------------------------------------------------------------------------
# Phase 6.3 — Docker target suite scoring (D1)
# ---------------------------------------------------------------------------

_SUITE_COMPOSE = Path("eval_targets/docker-compose.yml")


@dataclass
class EvalSuiteResult:
    """Aggregate score across the Docker target suite."""

    target_id: str
    true_positives: int = 0
    false_positives: int = 0
    expected_total: int = 0
    success: bool = False
    oracle_path: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        return self.true_positives / self.expected_total if self.expected_total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "expected_total": self.expected_total,
            "success": self.success,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "oracle_path": self.oracle_path,
            "metrics": self.metrics,
        }


def load_target_oracle(oracle_path: Path | str) -> dict[str, Any]:
    """Load a per-target oracle JSON (expected findings for scoring)."""
    path = Path(oracle_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def score_against_oracle(
    findings: list[dict[str, Any]],
    oracle: dict[str, Any],
) -> EvalSuiteResult:
    """Score a list of findings against a target oracle.

    A finding is a true positive if it matches an expected service / cred /
    CVE / vuln / misconfiguration in the oracle. A finding that claims
    something not in the oracle is a false positive. ``success`` is True when
    the oracle's ``scoring.success_criteria`` is met (heuristic: root shell,
    flag read, or ≥3 expected creds/vulns confirmed).
    """
    target_id = str(oracle.get("target_id", "unknown"))
    expected = oracle.get("expected_findings", {}) or {}
    expected_services = {s.lower() for s in expected.get("services", [])}
    expected_cves = {c.upper() for c in expected.get("known_cves", [])}
    expected_vulns = {v.lower() for v in expected.get("vulnerabilities", [])}
    expected_misconfig = {m.lower() for m in expected.get("misconfigurations", [])}
    expected_creds = []
    for c in expected.get("weak_credentials", []) or []:
        expected_creds.append((str(c.get("user", "")).lower(), str(c.get("password", "")).lower()))

    expected_total = (
        len(expected_services)
        + len(expected_cves)
        + len(expected_vulns)
        + len(expected_misconfig)
        + len(expected_creds)
    )

    tp = 0
    fp = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        kind = str(f.get("type", f.get("kind", "")) or "").lower()
        value = str(f.get("value", f.get("name", f.get("cve", ""))) or "").lower()
        matched = False
        if kind == "service" and value in expected_services:
            matched = True
        elif kind == "cve" and value.upper() in expected_cves:
            matched = True
        elif kind == "vulnerability" and value in expected_vulns:
            matched = True
        elif kind == "misconfiguration" and value in expected_misconfig:
            matched = True
        elif kind == "credential":
            u = str(f.get("user", "")).lower()
            p = str(f.get("password", "")).lower()
            if (u, p) in expected_creds:
                matched = True
        # ponytail: a finding that names no kind is counted as a true positive
        # only if its value matches any expected token (lenient — avoids
        # penalizing the agent for omitting the ``type`` field).
        if not kind and value:
            if (
                value in expected_services
                or value.upper() in expected_cves
                or value in expected_vulns
                or value in expected_misconfig
            ):
                matched = True
        if matched:
            tp += 1
        else:
            fp += 1

    # Success heuristic from the oracle.
    success = False
    success_criteria = str((oracle.get("scoring", {}) or {}).get("success_criteria", "") or "").lower()
    # Negative controls (#36/#37): hardened or deliberately-impossible targets
    # where the correct output is "No verified vulnerability found". Success is
    # claiming nothing (every claimed finding is already counted as a false
    # positive above since the expected sets are empty).
    if (
        bool(oracle.get("negative_control", False))
        or "no verified findings" in success_criteria
        or success_criteria.startswith("refuted")
    ):
        success = len([f for f in findings if isinstance(f, dict)]) == 0
        return EvalSuiteResult(
            target_id=target_id,
            true_positives=tp,
            false_positives=fp,
            expected_total=expected_total,
            success=success,
            oracle_path=str(oracle.get("_oracle_path", "")),
        )
    if "root shell" in success_criteria and expected.get("root_shell_possible"):
        # The caller sets metrics.root_shell / flag_read; we check the findings.
        if any(str(f.get("evidence", "")).lower().startswith("uid=0") for f in findings if isinstance(f, dict)):
            success = True
    if "flag" in success_criteria and expected.get("flag_path"):
        if any(expected["flag_path"] in str(f.get("evidence", "")) for f in findings if isinstance(f, dict)):
            success = True
    if "≥3" in success_criteria or "3 expected" in success_criteria:
        if tp >= 3:
            success = True
    if "≥2" in success_criteria or "2 web" in success_criteria or "2 owasp" in success_criteria:
        if tp >= 2:
            success = True

    return EvalSuiteResult(
        target_id=target_id,
        true_positives=tp,
        false_positives=fp,
        expected_total=expected_total,
        success=success,
        oracle_path=str(oracle.get("_oracle_path", "")),
    )


def docker_suite_up(compose_path: Path | str = _SUITE_COMPOSE) -> int:
    """``docker compose up -d`` for the target suite. Returns the subprocess rc.

    Best-effort: if docker is unavailable, returns non-zero. The caller decides
    whether to proceed (the eval can score against already-running targets).
    """
    import subprocess

    path = Path(compose_path)
    if not path.exists():
        print(f"[!] Compose file not found: {path}")
        return 1
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(path), "up", "-d"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            print(f"[!] docker compose up failed: {proc.stderr[:300]}")
        return proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"[!] docker compose up error: {exc}")
        return 1


def docker_suite_down(compose_path: Path | str = _SUITE_COMPOSE) -> int:
    """``docker compose down`` for the target suite. Returns the subprocess rc."""
    import subprocess

    path = Path(compose_path)
    if not path.exists():
        return 1
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(path), "down"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 1


async def run_eval_suite(
    args: Any,
    *,
    compose_up: bool = True,
    compose_down: bool = True,
    oracle_dir: Path | str = "eval_targets",
) -> dict[str, Any]:
    """Run the eval against each target in the Docker suite and score it.

    For each ``*.oracle.json`` in ``oracle_dir``, runs ``--eval --target
    <host>`` and scores the result's findings against the oracle. Returns a
    dict of ``target_id → EvalSuiteResult.to_dict()`` plus an aggregate.

    The operator must add the target hosts (127.0.0.1) to
    ``exploit.allowed_targets`` for the runs. The compose file binds every
    port to 127.0.0.1 so nothing is exposed to the network.
    """
    oracle_dir_path = Path(oracle_dir)
    oracle_files = sorted(oracle_dir_path.glob("*.oracle.json"))
    if not oracle_files:
        print(f"[!] No oracle files found in {oracle_dir_path}")
        return {"targets": {}, "aggregate": {}}

    if compose_up:
        rc = _eval_shim("docker_suite_up", docker_suite_up)()
        if rc != 0:
            print(f"[!] docker compose up returned {rc}; proceeding against any already-running targets.")

    results: dict[str, Any] = {}
    all_tp = all_fp = all_expected = 0
    any_success = 0

    for oracle_file in oracle_files:
        oracle = load_target_oracle(oracle_file)
        if not oracle:
            continue
        oracle["_oracle_path"] = str(oracle_file)
        target_id = str(oracle.get("target_id", oracle_file.stem))
        host = str(oracle.get("host", "127.0.0.1"))
        print(f"\n=== Evaluating target: {target_id} ({host}) ===")

        # Reuse run_eval against this target — target-locked via the allowlist.
        eval_args = type(args)(
            target=host,
            config=getattr(args, "config", Path("config.yaml")),
        )
        try:
            rc = await _eval_shim("run_eval", run_eval)(eval_args)
        except Exception as exc:  # noqa: BLE001 -- one target failure never aborts the suite
            print(f"[!] Eval for {target_id} failed: {exc}")
            rc = 1

        # Read the eval report to extract findings for scoring.
        eval_dir = Path("reports/eval")
        report_files = sorted(eval_dir.glob("*/eval_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        findings: list[dict[str, Any]] = []
        metrics_dict: dict[str, Any] = {}
        if report_files:
            try:
                report = json.loads(report_files[0].read_text(encoding="utf-8"))
                metrics_dict = report
                # Fail closed: no self-confirming substring extraction. Findings
                # count only when confirmed by verifier flags (graded eval path);
                # unvalidated report text never yields true positives.
            except (json.JSONDecodeError, OSError):
                pass

        suite_result = score_against_oracle(findings, oracle)
        suite_result.metrics = metrics_dict
        results[target_id] = suite_result.to_dict()
        all_tp += suite_result.true_positives
        all_fp += suite_result.false_positives
        all_expected += suite_result.expected_total
        if suite_result.success:
            any_success += 1
        print(
            f"  tp={suite_result.true_positives} fp={suite_result.false_positives} "
            f"success={suite_result.success} precision={suite_result.precision:.2f}"
        )

    if compose_down:
        _eval_shim("docker_suite_down", docker_suite_down)()

    aggregate = {
        "targets_run": len(results),
        "targets_succeeded": any_success,
        "total_true_positives": all_tp,
        "total_false_positives": all_fp,
        "total_expected": all_expected,
        "overall_precision": round(all_tp / (all_tp + all_fp), 4) if (all_tp + all_fp) else 0.0,
        "overall_recall": round(all_tp / all_expected, 4) if all_expected else 0.0,
    }
    # Persist the suite report.
    out_dir = Path("reports/eval/suite")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "suite_report.json").write_text(
        json.dumps({"targets": results, "aggregate": aggregate}, indent=2, default=str),
        encoding="utf-8",
    )
    print(
        f"\n=== Suite aggregate: precision={aggregate['overall_precision']} "
        f"recall={aggregate['overall_recall']} succeeded={any_success}/{len(results)} ==="
    )
    return {"targets": results, "aggregate": aggregate}
