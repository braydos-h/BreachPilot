"""Replay simulator (D2) -- pre-commit attack-plan critique.

Dry-runs an attack plan against a saved ``ReconAssessment`` JSON. The LLM
critiques its own plan *before* committing to it: confidence score, missing
steps, branch proposals. Zero target touch, no MCP session -- pure simulation.

Rule-based fallback scoring covers the LLM-unavailable path so the simulator
always returns a verdict.

Inputs:
- ``ReconAssessment`` JSON (``tools/goal_suggester.py:ReconAssessment.to_dict``)
  -- the saved recon snapshot for the target.
- ``AttackPlan`` JSON (``tools/attack_planner.py:AttackPlan.to_json``) -- the
  proposed plan to critique.

Output: ``SimulationResult`` with ``confidence`` (0..1), ``critique`` (str),
``branches`` (list of alternative-step dicts), and ``source`` ("llm" or
"rules").

The MCP tool ``replay_simulate`` (``@audit_tool`` -- local, no target) wires
this into the agent. ``replay_simulate`` is registered only when
``replay_simulator.enabled`` is true in config (opt-in).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SimulationResult:
    confidence: float
    critique: str
    branches: list[dict[str, Any]] = field(default_factory=list)
    source: str = "rules"  # "llm" or "rules"
    plan_target: str = ""
    recon_target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(self.confidence, 4),
            "critique": self.critique,
            "branches": self.branches,
            "source": self.source,
            "plan_target": self.plan_target,
            "recon_target": self.recon_target,
        }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"replay input not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"replay input is not valid JSON ({path}): {exc}") from exc


def _target_mismatch(plan: dict[str, Any], recon: dict[str, Any]) -> str | None:
    """Return a mismatch note if the plan's target is not in the recon."""
    plan_ip = str(plan.get("target_ip", "")).strip()
    recon_ip = str(recon.get("target_ip", "")).strip()
    if not plan_ip or not recon_ip:
        return None
    if plan_ip != recon_ip:
        return f"plan target '{plan_ip}' != recon target '{recon_ip}'; branch skipped."
    return None


def _rule_based_score(plan: dict[str, Any], recon: dict[str, Any]) -> SimulationResult:
    """Deterministic fallback critique when the LLM is unavailable.

    Scores the plan against the recon assessment:
    - +0.2 if the plan has at least one step per non-empty phase.
    - +0.2 if the plan references a known open port.
    - +0.2 if the plan references a known CVE.
    - +0.1 if every step has a non-empty ``reason``.
    - -0.2 if any step targets a host other than the recon target (pivot).
    - -0.1 if the plan is empty.
    """
    plan_ip = str(plan.get("target_ip", "")).strip()
    recon_ip = str(recon.get("target_ip", "")).strip()
    steps = plan.get("steps", []) or []
    open_ports = set(recon.get("open_ports", []) or [])
    cves = {
        str(c.get("cve", c.get("id", ""))).upper() for c in recon.get("cve_findings", []) or [] if isinstance(c, dict)
    }
    cves |= set(recon.get("target_cves", []) or [])

    confidence = 0.0
    critique_bits: list[str] = []
    branches: list[dict[str, Any]] = []

    if not steps:
        critique_bits.append("Plan has no steps.")
        confidence = 0.0
    else:
        # Phase coverage
        phases_covered = {s.get("phase", "") for s in steps if s.get("phase")}
        if phases_covered:
            confidence += 0.2

        # Port reference: any step arg or reason mentions an open port.
        # ponytail: digit-boundary regex so port 22 doesn't match the "22"
        # inside "CVE-2021-44228". Upgrade: structured port-field matching if
        # plans ever carry a formal ports schema.
        port_mentioned = False
        for s in steps:
            blob = json.dumps(s.get("arguments", {})) + " " + str(s.get("reason", ""))
            for p in open_ports:
                if re.search(rf"(?<!\d){re.escape(str(p))}(?!\d)", blob):
                    port_mentioned = True
                    break
            if port_mentioned:
                break
        if port_mentioned:
            confidence += 0.2
        else:
            critique_bits.append("No step references a discovered open port.")

        # CVE reference
        cve_mentioned = False
        for s in steps:
            blob = json.dumps(s.get("arguments", {})) + " " + str(s.get("reason", ""))
            for cve in cves:
                if cve and cve in blob.upper():
                    cve_mentioned = True
                    break
            if cve_mentioned:
                break
        if cve_mentioned:
            confidence += 0.2
        elif cves:
            critique_bits.append(f"Plan ignores {len(cves)} known CVE(s).")

        # Every step has a reason
        if all(str(s.get("reason", "")).strip() for s in steps):
            confidence += 0.1

        # Pivot / off-target step
        pivots = [s for s in steps if str(s.get("target_ip", "")).strip() and plan_ip and s.get("target_ip") != plan_ip]
        if pivots:
            confidence -= 0.2
            critique_bits.append(f"{len(pivots)} step(s) target a host other than {plan_ip} -- potential pivot.")

    confidence = max(0.0, min(1.0, confidence))

    # Branch proposals: for each open port with no matching step, suggest one.
    covered_ports = set()
    for s in steps:
        blob = json.dumps(s.get("arguments", {})) + " " + str(s.get("reason", ""))
        for p in open_ports:
            if re.search(rf"(?<!\d){re.escape(str(p))}(?!\d)", blob):
                covered_ports.add(p)
    for p in sorted(open_ports - covered_ports):
        branches.append(
            {
                "phase": "enumerate",
                "tool": "quick_scan",
                "reason": f"Recon found port {p} open but no plan step references it.",
                "target_ip": plan_ip,
                "arguments": {"target_ip": plan_ip, "ports": str(p)},
            }
        )

    critique = " ".join(critique_bits) or "Rule-based scoring: plan covers the recon surface."
    return SimulationResult(
        confidence=confidence,
        critique=critique,
        branches=branches,
        source="rules",
        plan_target=plan_ip,
        recon_target=recon_ip,
    )


def _llm_critique(
    plan: dict[str, Any],
    recon: dict[str, Any],
    *,
    model_client: Any,
    model_alias: str,
) -> SimulationResult | None:
    """Ask the LLM to critique the plan. Returns ``None`` on any failure."""
    plan_ip = str(plan.get("target_ip", "")).strip()
    recon_ip = str(recon.get("target_ip", "")).strip()
    prompt = (
        "You are an authorized-pentest plan reviewer. Critique the following attack plan "
        "against the recon assessment. Return ONLY JSON: "
        '{"confidence": 0.0-1.0, "critique": "...", "branches": [{"phase","tool","reason","target_ip","arguments"}]}\n\n'
        f"RECON ASSESSMENT (target={recon_ip}):\n{json.dumps(recon, indent=2)[:4000]}\n\n"
        f"ATTACK PLAN (target={plan_ip}):\n{json.dumps(plan, indent=2)[:4000]}\n"
    )
    messages = [
        {"role": "system", "content": "You are a penetration-testing plan critic. Output JSON only."},
        {"role": "user", "content": prompt},
    ]
    try:
        response = model_client.chat(model_alias, messages=messages, tools=None, stream=False)
    except Exception:
        return None
    content = _extract_content(response)
    if not content:
        return None
    data = _parse_json_block(content)
    if not isinstance(data, dict):
        return None
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    critique = str(data.get("critique", "")).strip() or "LLM returned no critique."
    branches = data.get("branches", []) or []
    if not isinstance(branches, list):
        branches = []
    return SimulationResult(
        confidence=confidence,
        critique=critique,
        branches=[b for b in branches if isinstance(b, dict)],
        source="llm",
        plan_target=plan_ip,
        recon_target=recon_ip,
    )


def _extract_content(response: Any) -> str:
    if isinstance(response, dict):
        message = response.get("message", {}) or {}
        if isinstance(message, dict):
            return str(message.get("content", "") or "")
        return str(getattr(message, "content", "") or "")
    message = getattr(response, "message", None)
    if isinstance(message, dict):
        return str(message.get("content", "") or "")
    if message is not None:
        return str(getattr(message, "content", "") or "")
    return str(response or "")


def _parse_json_block(text: str) -> Any:
    """Extract a JSON object from an LLM response that may be fenced."""
    t = (text or "").strip()
    if t.startswith("```json"):
        t = t[7:]
    if t.startswith("```"):
        t = t[3:]
    if t.endswith("```"):
        t = t[:-3]
    t = t.strip()
    # Find the first {...} block (the LLM may add prose around it).
    start = t.find("{")
    end = t.rfind("}")
    if start >= 0 and end > start:
        t = t[start : end + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return None


def simulate(
    plan: dict[str, Any],
    recon: dict[str, Any],
    *,
    model_client: Any | None = None,
    model_alias: str = "",
) -> SimulationResult:
    """Run a pre-commit critique of ``plan`` against ``recon``.

    If ``model_client`` is provided and the LLM responds, returns the LLM
    critique; otherwise degrades to rule-based scoring. Always returns a
    ``SimulationResult``.
    """
    mismatch = _target_mismatch(plan, recon)
    if mismatch:
        # Still score, but flag the mismatch in the critique.
        rule = _rule_based_score(plan, recon)
        rule.critique = (mismatch + " " + rule.critique).strip()
        return rule

    if model_client is not None and model_alias:
        llm_result = _llm_critique(plan, recon, model_client=model_client, model_alias=model_alias)
        if llm_result is not None:
            return llm_result
    return _rule_based_score(plan, recon)


def simulate_from_files(
    plan_path: Path,
    recon_path: Path,
    *,
    model_client: Any | None = None,
    model_alias: str = "",
) -> SimulationResult:
    """Load JSON files and run ``simulate``."""
    plan = _load_json(plan_path)
    recon = _load_json(recon_path)
    return simulate(plan, recon, model_client=model_client, model_alias=model_alias)


@dataclass
class RepeatedSimulation:
    """Outcome of N independent critiques of one plan (repeated-trials gate).

    Plan-level repeatability only: ``stable`` means the confidences agree
    within ``tolerance`` across independent runs. It says nothing about
    whether the plan would work — finding-level re-verification stays with
    ``verify_finding`` (metric #9). A single run (``trials=1``) can never be
    stable-by-evidence: ``stable`` is forced False so one lucky critique is
    never presented as reproduced.
    """

    runs: list[SimulationResult] = field(default_factory=list)
    trials: int = 0
    tolerance: float = 0.15
    stable: bool = False
    mean_confidence: float = 0.0
    confidence_spread: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trials": self.trials,
            "tolerance": self.tolerance,
            "stable": self.stable,
            "mean_confidence": round(self.mean_confidence, 4),
            "confidence_spread": round(self.confidence_spread, 4),
            "runs": [r.to_dict() for r in self.runs],
        }


def simulate_repeated(
    plan: dict[str, Any],
    recon: dict[str, Any],
    *,
    trials: int = 2,
    tolerance: float = 0.15,
    model_client: Any | None = None,
    model_alias: str = "",
) -> RepeatedSimulation:
    """Critique ``plan`` N independent times and report agreement.

    Each run goes through :func:`simulate` (LLM when available, else the
    deterministic rules path). ``stable`` is True only when at least two runs
    executed and every confidence falls within ``tolerance`` of the mean —
    the repeated-trials gate (#02 Level C) applied to pre-commit plan review.
    """
    try:
        n = max(1, int(trials or 2))
    except (TypeError, ValueError):
        n = 2
    try:
        tol = float(tolerance)
    except (TypeError, ValueError):
        tol = 0.15
    tol = max(0.0, tol)
    runs = [simulate(plan, recon, model_client=model_client, model_alias=model_alias) for _ in range(n)]
    confidences = [r.confidence for r in runs]
    mean_conf = sum(confidences) / len(confidences) if confidences else 0.0
    spread = (max(confidences) - min(confidences)) if confidences else 0.0
    stable = len(runs) >= 2 and all(abs(c - mean_conf) <= tol for c in confidences)
    return RepeatedSimulation(
        runs=runs,
        trials=len(runs),
        tolerance=tol,
        stable=stable,
        mean_confidence=mean_conf,
        confidence_spread=spread,
    )


def render_simulation_result(result: SimulationResult) -> str:
    """Render the result as the MCP tool's text return."""
    branch_lines = (
        "\n".join(
            f"  - [{b.get('phase', '?')}] {b.get('tool', '?')}: {b.get('reason', '')[:120]}" for b in result.branches
        )
        or "  (none)"
    )
    return (
        f"REPLAY_SIMULATION_RESULT:\n"
        f"SOURCE: {result.source}\n"
        f"PLAN_TARGET: {result.plan_target}\n"
        f"RECON_TARGET: {result.recon_target}\n"
        f"CONFIDENCE: {result.confidence:.2f}\n"
        f"CRITIQUE: {result.critique}\n"
        f"BRANCHES:\n{branch_lines}"
    )


# ─── Self-check ──────────────────────────────────────────────────────────

_SAMPLE_RECON = {
    "target_ip": "10.0.0.50",
    "os_verdict": "LINUX",
    "open_ports": [22, 80, 443],
    "services": [
        {"port": 22, "service": "ssh", "banner": "OpenSSH 8.9"},
        {"port": 80, "service": "http", "banner": "nginx 1.18"},
    ],
    "cve_findings": [{"cve": "CVE-2021-44228", "service": "http"}],
    "overall_risk_score": 70,
}

_SAMPLE_PLAN = {
    "target_ip": "10.0.0.50",
    "target_os": "LINUX",
    "target_cves": ["CVE-2021-44228"],
    "service_context": "ssh:22 http:80",
    "phases": ["recon", "enumerate", "exploit", "escalate", "loot", "pivot", "done"],
    "current_phase": "exploit",
    "current_phase_index": 2,
    "steps": [
        {
            "phase": "exploit",
            "tool": "cve_to_exploit_synth",
            "reason": "Exploit CVE-2021-44228 (Log4Shell) against port 8080.",
            "target_ip": "10.0.0.50",
            "arguments": {"target_ip": "10.0.0.50", "cve_id": "CVE-2021-44228"},
            "depends_on": [],
        },
    ],
    "attack_mode": True,
}


def _demo() -> int:
    """Runnable via ``python -m tools.replay_simulator``."""
    print("=== Replay Simulator self-check ===")
    result = simulate(_SAMPLE_PLAN, _SAMPLE_RECON)
    print(render_simulation_result(result))
    assert 0.0 <= result.confidence <= 1.0
    assert result.source == "rules"  # no model_client passed
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(_demo())
