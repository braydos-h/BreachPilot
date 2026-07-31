# Team Onboarding Docs

These docs are the fastest path into this codebase for new contributors. The root `README.md` is the product and usage guide; this folder is the engineering guide.

## Start Here

- [Getting Started](getting-started.md): setup, common commands, and local development loop.
- [Architecture](architecture.md): system shape, entry points, persistence, and major flows.
- [Runtime Flows](runtime-flows.md): how recon, task execution, exploitation, swarm, and MCP flows move through the code.
- [Module Guide](module-guide.md): responsibilities of the top-level modules, `tools/`, and tests.
- [Extension Guide](extension-guide.md): exact edit points for adding tools, integrations, config, persistent data, and tests.
- [Safety Model](safety-model.md): scope checks, risk checks, permission modes, audit records, and secure development rules.
- [Testing Guide](testing-guide.md): test layout, focused test commands, and what to update with each kind of change.
- [Plugin Development](plugin-development.md): how to write, package, enable, and distribute out-of-tree plugins.
- [Runtime Skills](skills.md): advisory skill pipeline, selection, re-selection, feedback, and semantic matching.
- [WebUI API](api.md): v1 REST + WebSocket reference for the `--demon`/`--daemon` API (runs, decisions, events, tools, config, secrets).

## Mental Model

This project is a locally run, AI-assisted security research agent. It has several surfaces over the same core concepts:

- `main.py`: interactive launcher and direct recon/attack entry point.
- `cli.py`: database-backed workflow commands for missions, scope, tasks, findings, and reports.
- `mcp_server.py`: defensive, scope-enforced MCP scan server.
- `mcp_exploit_server.py`: permissive exploit MCP server whose tool use is expected to be gated by policy in `tools.exploit_agent`.

The shared domain model is:

`Mission -> Scope/Risk gates -> Planner -> TaskQueue -> Executor/Tools -> Observer -> OutcomeJudge/Hypothesis state -> Memory/Graph/Evidence -> FindingVerifier -> ReportGenerator`

## Extension Paths

- In-tree edits: see `extension-guide.md` for exact edit points for adding tools, integrations, config, persistent data, and tests.
- Out-of-tree plugins: see `plugin-development.md` for writing, packaging, enabling, and distributing plugins.

## Generated Directories

The repository contains runtime artifacts from previous local runs. Contributors should understand them, but normally should not edit them:

- `reports/`: generated reports, run logs, and copied exploit workspaces.
- `exploit_workspace/`: generated exploit scripts, command logs, plans, and loot workspace.
- `research_workspace/`: local research database/logs.
- `test_workspace*`: temporary workspaces used by tests and manual regression runs.
- `__pycache__/`, `.pytest_cache/`, `.venv/`: local Python artifacts.
