"""Focused MCP exploit tool registration modules.

Each ``tools.mcp_tools.<family>.py`` defines ``register_<family>_tools(mcp, ctx)``
which registers its ``@audit_tool`` / ``@require_allowlist()`` handlers.
``mcp_exploit_server.create_mcp_server`` auto-discovers all such registrars via
``tools.mcp_tools.registry._discover_tool_registrars`` — adding a new family
requires only one new file, adding a tool to an existing family requires only
one function in that file (see ``docs/module-guide.md``).
"""
