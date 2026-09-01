"""Local WebUI API daemon (``--daemon`` (legacy alias: ``--demon``)).

Exposes a versioned, loopback-only REST + WebSocket API so third-party WebUIs
can drive assessments, answer decisions, stream live events, and invoke MCP
tools through a policy-gated gateway — all through the same
``AssessmentService`` the CLI uses.

v1 constraints:
- Loopback-only bind (no public override).
- One active run at a time (HTTP 409 on a second).
- Bearer token auth everywhere except ``/health``.
- WebSocket origin validation + auth message before subscribing.
- Separate ``reports/api_runtime.db`` SQLite (Flow B schema untouched).

The ASGI factory ``create_app`` lives in ``app.py`` at the repo root (not in
this package) to avoid circular imports.
"""
