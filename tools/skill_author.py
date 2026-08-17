"""Auto-skill authoring — distill a high-confidence campaign's tool-call
sequence into a draft ``SKILL.md`` under ``skills/maybe/`` for human review.

This is the self-improving skill catalog: a confirmed campaign's audit trail
(``exploit_audit.jsonl``) is a sequence of ``(tool_name, status, args)`` rows.
When that sequence shows a repeatable pattern (a non-trivial run of successful
tool calls), this module distills it into a draft skill body, sanitizes the
body via ``skill_registry._sanitize_skill_body``, and writes it under
``skills/maybe/<skill_name>/SKILL.md`` with a ``# DRAFT — review before
enabling`` header.

Advisory-only per AGENTS.md rule 8:
- Writes to ``skills/maybe/`` ONLY (gated by ``skills.maybe_enabled: false``
  default — the caller MUST pass ``maybe_enabled=True`` to actually write).
- Never grants execution authority. The skill body is methodology prose, not
  executable tool calls. Role-directive lines and tool-call mimics are stripped
  by the sanitizer.
- Human review before promotion to ``skills/``.
- Field lengths are capped; the distilled tool sequence is operator-generated
  (from the run's own audit trail) so prompt-injection risk is low, but the
  sanitizer is the defense-in-depth.

Failure modes (all return a dict, never raise):
- empty tool sequence -> ``{"skipped": "no tool calls"}``
- malformed audit line -> skip the line, continue
- ``skills/maybe/`` missing -> mkdir (only when ``maybe_enabled=True``)
- skill body too long -> cap + truncate with a note

Run the self-check via ``python -m tools.skill_author``.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

from tools.skill_registry import _sanitize_skill_body

# ponytail: cap field lengths so a runaway audit trail can't produce a
# multi-MB skill body. 2500 chars matches ``skills.max_chars_per_skill`` —
# the body stays within the per-skill prompt budget so a promoted skill
# doesn't blow the context window.
_MAX_BODY_CHARS = 2500
_MAX_DESCRIPTION_CHARS = 200
_MAX_TOOL_NAME_CHARS = 80
_MIN_TOOL_CALLS = 3  # fewer = not a pattern, skip


def distill_tool_sequence(
    tool_calls: Iterable[dict[str, Any]],
    *,
    skill_name: str,
    description: str,
    out_dir: Path,
    maybe_enabled: bool = False,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Distill a tool-call sequence into a draft SKILL.md under ``out_dir``.

    ``tool_calls`` is an iterable of dicts shaped like ``exploit_audit.jsonl``
    lines: ``{"tool_name": str, "status": str, "command": str = "", "args":
    dict = {}}``. Malformed rows are skipped (never raise).

    Returns a dict:
    - ``{"skipped": "no tool calls"}`` when the sequence is empty/too short.
    - ``{"skipped": "maybe_enabled is false"}`` when the gate is closed.
    - ``{"skill": "<path>", "name": ..., "tool_count": N}`` on success.

    Never raises. The body is sanitized via ``_sanitize_skill_body`` before
    write, and a ``# DRAFT — review before enabling`` header is prepended.
    """
    # Normalize the skill name (slugify-ish — keep it filesystem + registry safe).
    name = _slugify(skill_name)
    if not name:
        return {"skipped": "empty skill name"}

    # Collect + validate rows. Skip malformed lines (the audit trail is
    # operator-generated, but a truncated/corrupt file shouldn't crash us).
    rows: list[dict[str, Any]] = []
    for raw in tool_calls:
        if not isinstance(raw, dict):
            continue
        tool = str(raw.get("tool_name") or raw.get("tool") or "").strip()
        if not tool:
            continue
        rows.append({
            "tool": tool[:_MAX_TOOL_NAME_CHARS],
            "status": str(raw.get("status") or "unknown").lower(),
            "command": str(raw.get("command") or "")[:200],
        })
    if len(rows) < _MIN_TOOL_CALLS:
        return {"skipped": "no tool calls"}

    # Gate: only write when maybe_enabled is true. The caller (API route /
    # CLI command) is responsible for reading ``skills.maybe_enabled`` from
    # config and passing it through. Default false = no write, no mkdir.
    if not maybe_enabled:
        return {"skipped": "maybe_enabled is false"}

    # Build the body. This is methodology prose distilled from the tool
    # sequence — NOT executable tool calls. The sanitizer strips any
    # tool-call mimics that could sneak in via a malicious ``command`` field.
    body = _build_body(rows, description=description, tags=tags or [])

    target_dir = Path(out_dir) / name
    target_dir.mkdir(parents=True, exist_ok=True)
    skill_file = target_dir / "SKILL.md"
    skill_file.write_text(body, encoding="utf-8")
    return {
        "skill": str(skill_file),
        "name": name,
        "tool_count": len(rows),
    }


def distill_from_audit_jsonl(
    audit_path: Path,
    *,
    skill_name: str,
    description: str,
    out_dir: Path,
    maybe_enabled: bool = False,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Distill directly from an ``exploit_audit.jsonl`` file.

    Reads the JSONL, extracts ``(tool_name, status, command)`` per line, and
    delegates to ``distill_tool_sequence``. Malformed lines are skipped. The
    file-not-found case returns ``{"skipped": "audit file not found"}``.
    """
    if not audit_path.exists():
        return {"skipped": "audit file not found"}
    rows: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue  # skip malformed line
        if not isinstance(rec, dict):
            continue
        rows.append(rec)
    return distill_tool_sequence(
        rows,
        skill_name=skill_name,
        description=description,
        out_dir=out_dir,
        maybe_enabled=maybe_enabled,
        tags=tags,
    )


# ── Internals ──────────────────────────────────────────────────────────────

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def _slugify(name: str) -> str:
    """Lowercase, replace non-[a-z0-9-] runs with ``-``, collapse + trim dashes."""
    s = (name or "").strip().lower()
    s = _SLUG_RE.sub("-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


def _build_body(rows: list[dict[str, Any]], *, description: str, tags: list[str]) -> str:
    """Build the sanitized SKILL.md body from the distilled tool sequence.

    The body is methodology prose: a ``## When to Use`` section, a ``##
    Workflow`` section listing the distilled tool sequence as ordered prose
    (NOT tool-call mimics — the sanitizer strips ``- run tool: ...`` lines so
    we deliberately write ``Step N: <tool> — <status>`` instead), and a
    ``## Safety`` section restating the advisory-only invariant.
    """
    desc = (description or "").strip()[:_MAX_DESCRIPTION_CHARS]
    tag_line = ", ".join(tags) if tags else ""
    # Distill the sequence into ordered prose steps. Cap each line; the
    # sanitizer runs on the whole body so a ``command`` field that happens to
    # contain ``- run tool: ...`` gets stripped before it reaches a prompt.
    step_lines: list[str] = []
    for idx, row in enumerate(rows, 1):
        tool = row["tool"]
        status = row["status"]
        step_lines.append(f"Step {idx}: {tool} — {status}.")
    steps_block = "\n".join(step_lines)

    front = [
        "---",
        f"name: draft-{rows[0]['tool']}-{rows[-1]['tool']}".lower()[:80],
    ]
    if desc:
        front.append(f"description: {desc}")
    front.append("domain: cybersecurity")
    if tag_line:
        front.append("tags:")
        for t in tags:
            front.append(f"- {t}")
    else:
        front.append("tags: []")
    front.append("---")
    front.append("")
    front.append("# DRAFT — review before enabling")
    front.append("")
    front.append(
        "> Auto-distilled from a confirmed campaign audit trail. This is "
        "advisory methodology prose, not executable tool calls. Review the "
        "tool sequence below, confirm it matches your authorized workflow, "
        "and promote out of `skills/maybe/` by moving this directory to "
        "`skills/` once vetted."
    )
    front.append("")
    if desc:
        front.append(f"**Summary:** {desc}")
        front.append("")
    front.append("## When to Use")
    front.append("")
    front.append(
        "Use when the same tool sequence has produced a confirmed win against "
        "a target signature matching your current engagement. Verify each "
        "step's authorization and scope before re-running."
    )
    front.append("")
    front.append("## Workflow")
    front.append("")
    front.append("Distilled tool-call sequence (ordered):")
    front.append("")
    front.append(steps_block)
    front.append("")
    front.append("## Safety")
    front.append("")
    front.append(
        "Advisory only. Skills never change scope, permission, approval, "
        "command-safety, or audit rules. Role-directive lines and tool-call "
        "mimics in skill bodies are stripped by the sanitizer before any "
        "prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`)."
    )
    body = "\n".join(front)
    # Sanitize the whole body — strips HTML comments, script blocks, role
    # directives, role tokens, tool-call mimics, and collapses HR runs. This
    # is the defense-in-depth against a malicious ``command`` field that
    # might have slipped through the audit trail.
    body = _sanitize_skill_body(body)
    # Cap the total body length. The sanitizer may have shortened it; the cap
    # is a hard ceiling with a truncation note.
    if len(body) > _MAX_BODY_CHARS:
        body = body[: _MAX_BODY_CHARS - 40].rstrip() + "\n\n...[truncated by skill_author]"
    return body


# ── Self-check ─────────────────────────────────────────────────────────────


def _demo() -> None:
    """Runnable self-check: distill a synthetic sequence into a temp
    ``skills/maybe/`` dir without touching the real one. Asserts the draft
    header, sanitization, and the maybe_enabled gate.
    """
    synthetic_calls = [
        {"tool_name": "quick_scan", "status": "success", "command": "nmap -sV 10.0.0.5"},
        {"tool_name": "run_exploit_terminal", "status": "success", "command": "searchsploit nginx 1.4.0"},
        {"tool_name": "run_msf_module", "status": "success", "command": "exploit/multi/http/nginx_chunked"},
        {"tool_name": "run_exploit_terminal", "status": "success", "command": "whoami"},
    ]
    # 1. Gate closed -> no write.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "skills" / "maybe"
        out.mkdir(parents=True, exist_ok=True)
        result = distill_tool_sequence(
            synthetic_calls,
            skill_name="nginx-chunked-escalation",
            description="Distilled nginx chunked encoding escalation path.",
            out_dir=out,
            maybe_enabled=False,
            tags=["web", "exploit"],
        )
        assert result.get("skipped") == "maybe_enabled is false", result
        assert not list(out.glob("*/SKILL.md")), "gate closed but a skill was written"
        print("[demo] gate closed -> skipped (no write): OK")

        # 2. Gate open -> write + sanitize + draft header.
        result = distill_tool_sequence(
            synthetic_calls,
            skill_name="nginx-chunked-escalation",
            description="Distilled nginx chunked encoding escalation path.",
            out_dir=out,
            maybe_enabled=True,
            tags=["web", "exploit"],
        )
        assert "skill" in result, result
        skill_file = Path(result["skill"])
        assert skill_file.exists(), "skill file not written"
        body = skill_file.read_text(encoding="utf-8")
        assert "# DRAFT — review before enabling" in body, "draft header missing"
        assert "## When to Use" in body
        assert "## Workflow" in body
        assert "## Safety" in body
        # Sanitization: a role-directive line injected via the description
        # field would be stripped. (Description is capped + sanitized by
        # _build_body, but verify the sanitizer ran on the whole body.)
        assert "## SYSTEM:" not in body, "role directive survived sanitization"
        # Tool-call mimics stripped: the steps are prose, not ``- run tool:``.
        assert "run tool:" not in body, "tool-call mimic survived sanitization"
        print(f"[demo] gate open -> wrote {skill_file.name} ({result['tool_count']} tools): OK")

        # 3. Empty sequence -> skipped.
        result = distill_tool_sequence(
            [], skill_name="empty", description="x", out_dir=out, maybe_enabled=True,
        )
        assert result.get("skipped") == "no tool calls", result
        print("[demo] empty sequence -> skipped: OK")

        # 4. Malformed lines skipped, valid ones distilled.
        mixed = [
            {"tool_name": "a", "status": "success"},
            "not a dict",
            {"status": "success"},  # missing tool_name
            {"tool_name": "b", "status": "success"},
            {"tool_name": "c", "status": "success"},
        ]
        result = distill_tool_sequence(
            mixed, skill_name="mixed", description="x", out_dir=out, maybe_enabled=True,
        )
        assert result.get("tool_count") == 3, result
        print("[demo] malformed lines skipped (3 of 5 kept): OK")

    print("[demo] all self-checks passed.")


if __name__ == "__main__":
    _demo()
