"""Tooling package — see docs/module-guide.md for module map.

Flow A (modern, what users run): main.py/app.py → tools/exploit_agent/ →
  mcp_exploit_server.py → tools/mcp_tools/* → tools/kernel/* (allowlist/audit/workspace)
  + tools/swarm/ + tools/autonomous_orchestrator.py + tools/run_service/ + tools/api/
Flow B (legacy, SQLite): cli.py → agent_loop.py/db.py/mission.py/scope_gate.py
  (DO NOT EDIT safety files per AGENTS.md)
Shared kernel (pure, no I/O): tools/kernel/{allowlist,audit,workspace}.py +
  tools/validation_utils.py + tools/config_manager.py (config.yaml:495)
Key boundaries: tools/exploit_agent 3.8K, tools/mcp_tools 18 families (auto-discovered
  via registry._discover_tool_registrars), tools/swarm, tools/api, tools/run_service.
"""
