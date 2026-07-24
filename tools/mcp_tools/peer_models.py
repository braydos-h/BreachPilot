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
                        "Do not claim to execute tools, do not request tool calls, and flag assumptions or safety concerns."
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



