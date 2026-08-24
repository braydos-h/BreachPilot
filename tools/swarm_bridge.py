"""Bridge swarm tool execution onto a live MCP session."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions


class SwarmMcpBridge:
    """Bridge the (sync) swarm tool_executor / ``ExploitAgent.run`` to the live
    MCP ``ClientSession`` owned by ``run_exploit_session``.

    Tier 5: previously the swarm ran on a STUB ``tool_executor`` that only
    logged ``[swarm] <name> called with ...`` and never dispatched into the MCP
    exploit session (which is opened separately inside ``run_exploit_session``
    and was not exposed to the swarm). As a result recon-mode tool calls were
    simulated and attack-mode ``ExploitAgent`` Path A (which calls
    ``session.call_tool`` itself) failed because it ran ``asyncio.run`` on a
    session bound to the main loop. This bridge fixes both:

      * ``dispatch(name, args)`` (sync, matches the ``tool_executor`` shape at
        ``agent_loop.py:69``) gates through ``ExploitPolicy.approve_action``,
        then hops to the main loop via ``asyncio.run_coroutine_threadsafe`` to
        call ``session.call_tool`` (the session is bound to the main loop; the
        swarm's recon loop runs in a worker thread via ``asyncio.to_thread``).
      * ``attach(session, schemas, policy, loop)`` stashes the live session so
        the attack-mode ``ExploitAgent`` can read ``context["mcp_session"]`` /
        ``["exploit_tools_schemas"]`` / ``["main_loop"]`` and run its
        ``run_exploit_agent`` coroutine on the main loop instead of a fresh one.

    Single-session invariant is preserved: the swarm shares the ONE MCP
    ``ClientSession`` ``run_exploit_session`` opens (the BaseExceptionGroup
    helpers in ``tools/exceptions.py`` depend on that single session's
    lifecycle), it does not open a second one.
    """

    def __init__(self) -> None:
        self._session: Any = None
        self._schemas: list[dict[str, Any]] | None = None
        self._policy: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.dispatched: int = 0

    def attach(
        self,
        session: Any,
        schemas: list[dict[str, Any]],
        policy: Any,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._session = session
        self._schemas = schemas
        self._policy = policy
        self._loop = loop or asyncio.get_running_loop()

    def ready(self) -> bool:
        return self._session is not None and self._policy is not None and self._loop is not None

    def _run_async(self, coro: Any, *, timeout: float = 180.0) -> Any:
        """Run a main-loop-bound coroutine from the swarm's worker thread."""
        loop = self._loop
        if loop is None:
            raise RuntimeError("SwarmMcpBridge has no event loop (attach not called)")
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is loop:
            close = getattr(coro, "close", None)
            if close is not None:
                close()
            raise RuntimeError("SwarmMcpBridge.dispatch cannot run on its MCP event loop; call it from a worker thread")
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=timeout)

    @staticmethod
    def _extract_text(result: Any) -> str:
        """Pull the textual content out of an MCP ``call_tool`` result.

        Mirrors the extraction in ``tools/exploit_agent`` (the agent loop):
        result.content is a list of blocks, each with a ``.text``; non-text
        blocks are JSON-dumped. Handles both dict and attribute access.
        """

        def _get(obj: Any, key: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        blocks = _get(result, "content", []) or []
        parts: list[str] = []
        for block in blocks:
            t = _get(block, "text", None)
            if t is not None:
                parts.append(str(t))
            else:
                try:
                    parts.append(json.dumps(block, indent=2, default=str))
                except (TypeError, ValueError):
                    parts.append(str(block))
        text = "\n".join(p for p in parts if p).strip()
        if text:
            return text
        # No content blocks -- dump the whole result.
        try:
            return json.dumps(result, indent=2, default=str)
        except (TypeError, ValueError):
            return str(result)

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        """Sync ``tool_executor`` entry point. Gate via the exploit policy, then
        dispatch to the live MCP session on the main loop. Returns a textual
        result string (matches the ``BLOCKED:`` / ``TOOL_EXECUTION_ERROR:``
        conventions the agent loop and tool_router already understand)."""
        if not self.ready():
            return (
                "BLOCKED: swarm MCP bridge not attached yet (session="
                f"{self._session is not None}, policy={self._policy is not None})."
            )
        try:
            from tools.command_analyzer import analysis_payload

            command = analysis_payload(name, args)
        except Exception:
            command = json.dumps(args, default=str)[:200]
        try:
            approved = self._run_async(self._policy.approve_action(name, command))
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            return f"TOOL_EXECUTION_ERROR: policy approve failed: {exc}"
        if not approved:
            return f"BLOCKED: ExploitPolicy denied {name}"
        try:
            result = self._run_async(self._session.call_tool(name, arguments=args))
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            return f"TOOL_EXECUTION_ERROR: {exc}"
        self.dispatched += 1
        return self._extract_text(result)
