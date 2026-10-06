"""Bridge swarm tool execution onto a live MCP session."""

from __future__ import annotations

import asyncio
import json
import threading
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

    Thread/loop contract (load-bearing — do not "simplify"):

    * The MCP ``ClientSession`` is bound to the main event loop owned by
      ``run_exploit_session``. ``dispatch`` MUST be called from a worker
      thread (the swarm runs via ``asyncio.to_thread`` / ``run_in_executor``);
      it hops via ``asyncio.run_coroutine_threadsafe`` onto the bound loop.
    * Calling ``dispatch`` (or ``_run_async``) ON the bound loop raises
      ``RuntimeError`` immediately instead of deadlocking — ``dispatch``
      surfaces that as ``TOOL_EXECUTION_ERROR`` (it never raises to the
      agent; every session-bound call is wrapped in ``_EXC_GROUP_CATCH``).
    * ``attach`` must capture the main loop: pass ``loop`` explicitly when
      available, else ``attach`` itself must run on the main loop (it falls
      back to ``asyncio.get_running_loop()``).

    Single-session invariant: this bridge NEVER opens its own MCP session.
    ``attach`` may be called again (run_service re-attaches per run) to
    REPLACE the session/policy/loop/config quadruple, but at most one
    session is ever referenced. ``ready()`` is False until session+policy+
    loop are all set; sync ``dispatch`` before attach returns ``BLOCKED``.
    The sandbox-recon ``call_tool_on_loop`` waits a bounded time for attach,
    because run_service starts its campaign task before the MCP session exists.
    """

    def __init__(self) -> None:
        self._session: Any = None
        self._schemas: list[dict[str, Any]] | None = None
        self._policy: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._attached = threading.Event()
        # Snapshot/rollback (design §snapshots): optional app config dict. When
        # supplied (exploit_session passes the loaded config at attach), the
        # dispatch funnel snapshots before destructive swarm tool calls.
        # None (legacy callers, tests) -> snapshot hook is inert.
        self._config: dict[str, Any] | None = None
        self._snapshot_mgr: Any | None = None
        self.dispatched: int = 0
        self._stopped = False
        self._dispatch_outcome_unknown = False
        self._state_lock = threading.Lock()
        self._dispatch_lock = threading.Lock()
        self._inflight_condition = threading.Condition()
        self._inflight: dict[threading.Event, Any | None] = {}
        self._tool_call_timeout_seconds = 180.0

    def attach(
        self,
        session: Any,
        schemas: list[dict[str, Any]],
        policy: Any,
        loop: asyncio.AbstractEventLoop | None = None,
        *,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._session = session
        self._schemas = schemas
        self._policy = policy
        self._loop = loop or asyncio.get_running_loop()
        self._config = config
        self._attached.set()

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

    def _run_tool_async(self, coro: Any) -> Any:
        """Run and track a session-bound MCP call from the swarm worker.

        A timeout makes the remote side effect uncertain. The bridge then
        blocks all later dispatches for this run, and cancellation/drain keeps
        the shared ClientSession alive until the local call coroutine has
        actually unwound.
        """
        loop = self._loop
        if loop is None:
            close = getattr(coro, "close", None)
            if close is not None:
                close()
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

        completed = threading.Event()

        async def _tracked_call() -> Any:
            try:
                async with asyncio.timeout(self._tool_call_timeout_seconds):
                    return await coro
            finally:
                with self._inflight_condition:
                    completed.set()
                    self._inflight.pop(completed, None)
                    self._inflight_condition.notify_all()

        with self._state_lock:
            if self._stopped or self._dispatch_outcome_unknown:
                close = getattr(coro, "close", None)
                if close is not None:
                    close()
                raise RuntimeError("SwarmMcpBridge is stopped or has an unknown in-flight tool outcome")
            with self._inflight_condition:
                self._inflight[completed] = None
            try:
                future = asyncio.run_coroutine_threadsafe(_tracked_call(), loop)
            except _EXC_GROUP_CATCH:
                close = getattr(coro, "close", None)
                if close is not None:
                    close()
                with self._inflight_condition:
                    self._inflight.pop(completed, None)
                    self._inflight_condition.notify_all()
                raise
            with self._inflight_condition:
                if not completed.is_set():
                    self._inflight[completed] = future
        future.add_done_callback(lambda _future: self._forget_future(completed, loop))
        try:
            # Leave time for asyncio.timeout() to cancel and unwind the MCP
            # coroutine before this worker observes the timeout.
            return future.result(timeout=self._tool_call_timeout_seconds + 5.0)
        except TimeoutError as exc:
            with self._state_lock:
                self._dispatch_outcome_unknown = True
            future.cancel()
            raise TimeoutError("MCP tool call timed out; remote outcome is unknown") from exc

    def _forget_future(self, completed: threading.Event, loop: asyncio.AbstractEventLoop) -> None:
        # The coroutine's finally block owns normal removal. A submitted
        # future cancelled before its coroutine starts never enters that
        # finally block; queue cleanup behind the loop's cancellation callback
        # so active coroutine cleanup gets first chance to finish.
        def _remove_unstarted() -> None:
            with self._inflight_condition:
                if not completed.is_set():
                    completed.set()
                    self._inflight.pop(completed, None)
                    self._inflight_condition.notify_all()

        try:
            loop.call_soon_threadsafe(_remove_unstarted)
        except RuntimeError:
            _remove_unstarted()

    async def wait_until_idle(self) -> None:
        """Wait until every session-bound coroutine has unwound."""

        def _wait() -> None:
            with self._inflight_condition:
                while self._inflight:
                    self._inflight_condition.wait()

        await asyncio.to_thread(_wait)

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
        # MCP ClientSession is a single shared resource. Serialize its sync
        # bridge callers so a timeout cannot race with a second dispatch that
        # passed the outcome-unknown check just before the first timed out.
        with self._dispatch_lock:
            return self._dispatch_locked(name, args)

    def _dispatch_locked(self, name: str, args: dict[str, Any]) -> str:
        if self._stopped:
            return "BLOCKED: swarm run is stopping; no further MCP tools may be dispatched."
        with self._state_lock:
            outcome_unknown = self._dispatch_outcome_unknown
        if outcome_unknown:
            return "BLOCKED: a previous MCP call timed out with unknown outcome; no further tools may be dispatched."
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
        # ── Snapshot before destructive swarm dispatch (design §snapshots) ──
        # Fail-open and additive: mirrors the exploit-loop hook. Only fires
        # when attach() was given the app config AND snapshots.enabled — so
        # legacy callers and tests (config=None) keep the old behavior.
        self._snapshot_before_destructive(name, command)
        try:
            result = self._run_tool_async(self._session.call_tool(name, arguments=args))
        except TimeoutError as exc:
            return f"TOOL_EXECUTION_ERROR: {exc} Further MCP dispatch is blocked for this run."
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            return f"TOOL_EXECUTION_ERROR: {exc}"
        self.dispatched += 1
        return self._extract_text(result)

    async def call_tool_on_loop(self, name: str, args: dict[str, Any]) -> Any:
        """Call one MCP tool from the attached session's owning event loop.

        Used by Flow A's trusted sandbox recon adapter, which already runs on
        the session loop. It applies the same ExploitPolicy approval as
        ``dispatch`` and never opens or substitutes a session.
        """
        if self._stopped:
            raise RuntimeError("swarm run is stopping; no further MCP tools may be dispatched")
        with self._state_lock:
            if self._dispatch_outcome_unknown:
                raise RuntimeError("previous MCP call timed out with unknown outcome; dispatch is blocked")
        if not self.ready():
            # run_service launches its campaign task before run_exploit_session
            # opens and attaches the shared MCP session. Waiting here lets the
            # campaign yield to that setup while still failing closed if no
            # session arrives. The event is thread-safe because attach/stop
            # may run on the owner loop while this await uses a worker thread.
            attached = await asyncio.to_thread(self._attached.wait, 30.0)
            if not attached or self._stopped or not self.ready():
                raise RuntimeError("SwarmMcpBridge was not attached to an MCP session before timeout or stop")
        if asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("call_tool_on_loop must run on the attached MCP event loop")
        try:
            from tools.command_analyzer import analysis_payload

            command = analysis_payload(name, args)
        except Exception:
            command = json.dumps(args, default=str)[:200]
        if not await self._policy.approve_action(name, command):
            raise PermissionError(f"ExploitPolicy denied {name}")
        with self._state_lock:
            if self._stopped or self._dispatch_outcome_unknown:
                raise RuntimeError("swarm MCP dispatch stopped before the approved call could be sent")
        self._snapshot_before_destructive(name, command)
        result = await self._session.call_tool(name, arguments=args)
        self.dispatched += 1
        return result

    def stop(self) -> None:
        """Prevent new session-bound calls after the owning run is stopped."""
        with self._state_lock:
            self._stopped = True
            self._attached.set()
            with self._inflight_condition:
                futures = [future for future in self._inflight.values() if future is not None]
        for future in futures:
            future.cancel()

    def _snapshot_before_destructive(self, name: str, command: str) -> None:
        """Auto-snapshot before a destructive swarm tool call (fail-open).

        Gated on ``snapshots.enabled`` + ``auto_before_destructive`` via
        ``tools.snapshots.should_snapshot``. The bridge runs on a worker
        thread, so the (subprocess-backed) provider call runs inline here —
        never on the MCP loop. A failure only logs; the dispatch proceeds.
        The vm_id comes from the first IP in the command payload (the swarm
        dispatch has no separate target arg) resolved through the snapshot
        vm map; commands with no IP are skipped.
        """
        if self._config is None:
            return
        try:
            from tools.snapshots import SnapshotManager, should_snapshot
            from tools.validation_utils import extract_ips_from_command

            if not should_snapshot(name, command, self._config):
                return
            ips = extract_ips_from_command(command) or []
            if not ips:
                return
            if self._snapshot_mgr is None:
                workspace = str((self._config or {}).get("exploit", {}).get("workspace_dir", ".") or ".")
                self._snapshot_mgr = SnapshotManager(self._config, index_dir=workspace)
            ref = self._snapshot_mgr.before_destructive(ips[0], f"pre-{name}")
            if ref is not None:
                print(f"[swarm] snapshot taken: {ref.snapshot_id} ({ref.provider}) before {name}")
        except Exception as exc:  # noqa: BLE001 -- fail-open by contract
            try:
                print(f"[swarm] snapshot before {name} failed (continuing): {exc}")
            except Exception:  # pragma: no cover
                pass
