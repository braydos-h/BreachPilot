"""Peer Models MCP tool registration."""

from __future__ import annotations

import os
import re
import sys
from typing import Any

from tools.mcp_tools.registry import (
    ToolContext,
    _chat_content,
    _consultation_count,
    _consultation_lock,
    _get_model_router,
    _multi_model_enabled,
    _positive_int,
    _resolve_consult_aliases,
    _truncate_text,
)


def _get_consultation_count() -> int:
    server_mod = sys.modules.get("mcp_exploit_server")
    if server_mod is not None and hasattr(server_mod, "_consultation_count"):
        return int(getattr(server_mod, "_consultation_count"))
    return int(_consultation_count)


def _set_consultation_count(value: int) -> None:
    global _consultation_count
    _consultation_count = value
    server_mod = sys.modules.get("mcp_exploit_server")
    if server_mod is not None and hasattr(server_mod, "_consultation_count"):
        setattr(server_mod, "_consultation_count", value)


def register_peer_model_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    if _multi_model_enabled(config):
        @mcp.tool()
        @audit_tool
        def consult_peer_models(question: str, context: str = "", preferred_aliases: str = "") -> str:
            """Ask configured peer AI models for advisory help. Use sparingly when crafting an exploit approach, reviewing generated exploit code, or recovering from repeated failures. Peers receive no tool schemas and cannot execute commands; they only return suggestions. preferred_aliases is optional comma-separated aliases from models.registry."""
            global _consultation_count

            mm = (config or {}).get("multi_model", {}) or {}
            max_consultations = _positive_int(mm.get("max_consultations"), 10)
            max_question_chars = _positive_int(mm.get("max_question_chars"), 4000)
            max_answer_chars = _positive_int(mm.get("max_answer_chars"), 8000)

            q = _truncate_text(question, max_question_chars).strip()
            ctx_text = _truncate_text(context, max_question_chars).strip()
            if not q:
                return "PEER_MODEL_CONSULTATION: BLOCKED\nREASON: question is required."

            router = _get_model_router(config)
            if router is None:
                return "PEER_MODEL_CONSULTATION: UNAVAILABLE\nREASON: model router could not be initialized."

            available = _resolve_consult_aliases(config)
            preferred = [
                alias.strip()
                for alias in re.split(r"[,\s]+", preferred_aliases or "")
                if alias.strip()
            ]
            selected = [alias for alias in available if not preferred or alias in preferred]
            skipped: list[str] = []
            if preferred:
                skipped.extend(alias for alias in preferred if alias not in available)

            if not selected:
                active = os.environ.get("AI_NMAP_ACTIVE_MODEL_ALIAS") or (config or {}).get("models", {}).get("default_alias", "glm")
                return (
                    "PEER_MODEL_CONSULTATION: UNAVAILABLE\n"
                    f"ACTIVE_MODEL: {active}\n"
                    f"AVAILABLE_PEERS: {', '.join(available) if available else '(none)'}\n"
                    f"SKIPPED: {', '.join(skipped) if skipped else '(none)'}"
                )

            with _consultation_lock:
                current_count = _get_consultation_count()
                remaining = max_consultations - current_count
                if remaining <= 0:
                    return (
                        "PEER_MODEL_CONSULTATION: BUDGET_EXHAUSTED\n"
                        f"MAX_CONSULTATIONS: {max_consultations}\n"
                        "REMAINING_BUDGET: 0"
                    )
                selected = selected[:remaining]
                current_count += len(selected)
                _set_consultation_count(current_count)
                remaining_after_reservation = max_consultations - current_count

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a peer reviewer for an authorized security assessment. "
                        "Give concise exploit-development or debugging advice only. "
                        "Do not claim to execute tools, do not request tool calls, and flag assumptions or safety concerns.\n"
                        "Structure your advice as:\n"
                        "ASSUMPTIONS: <what you are assuming about the target/exploit>\n"
                        "RISKS: <safety or feasibility risks>\n"
                        "RECOMMENDATION: <your concrete advice>\n"
                        "Keep each section to a few sentences."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Question:\n{q}\n\n"
                        f"Context:\n{ctx_text if ctx_text else '(none provided)'}"
                    ),
                },
            ]

            consulted: list[str] = []
            sections: list[str] = []
            for alias in selected:
                try:
                    peer = router.get_client(alias)
                    response = peer.chat(alias, messages=messages, tools=None, stream=False)
                    answer = _truncate_text(_chat_content(response), max_answer_chars).strip()
                    if not answer:
                        answer = "(empty response)"
                    consulted.append(alias)
                    sections.append(f"[{alias}]\n{answer}")
                except Exception as exc:
                    skipped.append(f"{alias}: {exc}")

            return (
                "PEER_MODEL_CONSULTATION: COMPLETED\n"
                f"CONSULTED: {', '.join(consulted) if consulted else '(none)'}\n"
                f"SKIPPED: {', '.join(skipped) if skipped else '(none)'}\n"
                f"REMAINING_BUDGET: {remaining_after_reservation}\n\n"
                + ("\n\n".join(sections) if sections else "No peer responses were returned.")
            )

        @mcp.tool()
        @audit_tool
        def peer_review_outcome(
            verdict: str,
            evidence: str,
            planner_alias: str = "",
            preferred_grader_aliases: str = "",
        ) -> str:
            """Cross-model outcome judging (D3). Ask configured peer AI models to grade whether the evidence supports the given verdict (e.g. "compromised" / "refuted"). Advisory only -- the deterministic OutcomeJudge stays the authority. One alias plans, a *different* alias grades. Set planner_alias to exclude the planning model from grading. preferred_grader_aliases is optional comma-separated aliases from models.registry."""
            if not verdict or not verdict.strip():
                return "PEER_REVIEW_OUTCOME: BLOCKED\nREASON: verdict is required."
            if not evidence or not evidence.strip():
                return "PEER_REVIEW_OUTCOME: BLOCKED\nREASON: evidence is required."

            # peer_review requires multi_model + outcome_judgment.peer_review.
            oj_cfg = (config or {}).get("outcome_judgment", {}) or {}
            if not bool(oj_cfg.get("peer_review", False)):
                return (
                    "PEER_REVIEW_OUTCOME: DISABLED\n"
                    "REASON: set outcome_judgment.peer_review: true in config to enable."
                )

            mm = (config or {}).get("multi_model", {}) or {}
            max_answer = _positive_int(mm.get("max_answer_chars"), 8000)

            router = _get_model_router(config)
            if router is None:
                return "PEER_REVIEW_OUTCOME: UNAVAILABLE\nREASON: model router could not be initialized."

            available = _resolve_consult_aliases(config)
            # Exclude the planner alias so a model never grades its own plan.
            planner = (planner_alias or "").strip()
            graders = [a for a in available if a != planner]
            if planner and planner not in available:
                # Planner not in the consult set anyway -- nothing to exclude.
                pass
            preferred = [
                a.strip()
                for a in re.split(r"[,\s]+", preferred_grader_aliases or "")
                if a.strip()
            ]
            if preferred:
                graders = [a for a in graders if a in preferred] or graders
            if not graders:
                return (
                    "PEER_REVIEW_OUTCOME: UNAVAILABLE\n"
                    f"PLANNER_ALIAS: {planner or '(none)'}\n"
                    f"AVAILABLE_PEERS: {', '.join(available) if available else '(none)'}\n"
                    "REASON: no grader aliases available after excluding the planner."
                )

            # Share the per-run ``max_consultations`` budget with
            # ``consult_peer_models`` via the single ``_consultation_count``
            # counter (same source of truth, so the lab box doesn't burn tokens
            # silently when both tools are on).
            mm = (config or {}).get("multi_model", {}) or {}
            max_consultations = _positive_int(mm.get("max_consultations"), 10)
            with _consultation_lock:
                current_count = _get_consultation_count()
                remaining = max_consultations - current_count
                if remaining <= 0:
                    return (
                        "PEER_REVIEW_OUTCOME: BUDGET_EXHAUSTED\n"
                        f"MAX_CONSULTATIONS: {max_consultations}\n"
                        "REMAINING_BUDGET: 0"
                    )
                graders = graders[:remaining]
                current_count += len(graders)
                _set_consultation_count(current_count)
                remaining_after_reservation = max_consultations - current_count

            v = _truncate_text(verdict, 2000).strip()
            e = _truncate_text(evidence, max_answer).strip()
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an independent outcome reviewer for an authorized security assessment. "
                        "You are given a verdict and the evidence claimed to support it. Grade whether "
                        "the evidence actually supports the verdict. Output JSON only:\n"
                        '{"agree": true|false, "confidence": 0.0-1.0, "reason": "..."}\n'
                        "Do not execute tools. Do not request tool calls. Flag unsupported claims."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"VERDICT:\n{v}\n\n"
                        f"EVIDENCE:\n{e}"
                    ),
                },
            ]

            consulted: list[str] = []
            sections: list[str] = []
            disagreements: list[str] = []
            for alias in graders:
                try:
                    peer = router.get_client(alias)
                    response = peer.chat(alias, messages=messages, tools=None, stream=False)
                    answer = _truncate_text(_chat_content(response), max_answer).strip()
                    if not answer:
                        answer = "(empty response)"
                    consulted.append(alias)
                    sections.append(f"[{alias}]\n{answer}")
                    # Track disagreement for the summary line.
                    if '"agree": false' in answer.lower() or '"agree":false' in answer.lower():
                        disagreements.append(alias)
                except Exception as exc:
                    sections.append(f"[{alias}]\n(skipped: {exc})")

            disagreement_flag = "DISAGREEMENT: yes" if disagreements else "DISAGREEMENT: no"
            return (
                "PEER_REVIEW_OUTCOME: COMPLETED\n"
                f"PLANNER_ALIAS: {planner or '(none)'}\n"
                f"GRADERS: {', '.join(consulted) if consulted else '(none)'}\n"
                f"{disagreement_flag}\n"
                f"REMAINING_BUDGET: {remaining_after_reservation}\n"
                "AUTHORITY: deterministic OutcomeJudge (this review is advisory)\n\n"
                + ("\n\n".join(sections) if sections else "No peer responses were returned.")
            )



