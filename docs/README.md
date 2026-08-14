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
- [Building & Improving Skills](skill-authoring.md): how to author new `SKILL.md` files and tune selection/feedback for existing ones.
- [WebUI API](api.md): v1 REST + WebSocket reference for the `--demon`/`--daemon` API (runs, decisions, events, tools, config, secrets).
- [WebUI](webui.md): the bundled React/Vite SPA — stack, pages, auth, real-time transport, and extension points.

## Deep Dives

- [Exploit Agent](exploit-agent.md): the Flow A agent — loop lifecycle, prompts, model routing, permission model, outcome pipeline, reflection, research assistant.
- [MCP Tools](mcp-tools.md): every tool family across the three MCP servers, the `@audit_tool`/`@require_allowlist` wiring, and the target-IP allowlist lock.
- [MCP Wiring](mcp-wiring.md): servers, transports, ports, how the agent/swarm connect, env-var propagation, and exception-group handling.
- [Swarm](swarm.md): multi-agent missions — orchestrator, blackboard, the six agent roles, phase flow, MCP bridge, observability.
- [Attack Modules](attack-modules.md): the module registry, all 15 module families (~90 modules), applicability scoring, and the add-a-module checklist.
- [Run Service](run-service.md): run lifecycle, providers, event/decision brokers, persistence, auth, and WebSocket transport.
- [Model Providers](providers.md): Ollama wiring for chat/generate, embeddings, and research — and how to add a new provider.
- [Config Reference](config-reference.md): every `config.yaml` key — type, default, consumer `file:line`, env overrides.
- [CLI Reference](cli-reference.md): every entry point and flag across `main.py` / `app.py` / `cli.py`, interactive menu, exit codes, example workflows.
- [Database & Mission](database-mission.md): SQLite schema (both DBs), mission lifecycle, task queue, memory, target graph, evidence-to-report pipeline.
- [Outcomes & Evidence](outcome-evidence.md): outcome taxonomy, truth-vs-claim, evidence model, audit JSONL, finding verification, PoE, report generation.
- [Research](research.md): research assistant, web research, recon enrichers, CVE lookup, and how findings flow into the agent.
- [Evaluation](evaluation.md): eval harness vs oracle-backed benchmark, metrics, scenarios, detection coverage, PoE canary scoring.
- [Deployment](deployment.md): Windows/Linux install, Ollama cloud vs local, nmap privileges, WebUI build, daemon mode, hardening checklist.
- [Troubleshooting](troubleshooting.md): symptom → cause → check → fix for setup, startup, runtime, tests, WebUI, and platform issues.
- [Tutorial](tutorial.md): hands-on walkthrough — setup, `--self-test`, recon-first run, exploit session, swarm mission, WebUI, demo/eval.
- [Glossary](glossary.md): alphabetized domain vocabulary with `file:line` pointers.
- [Prompts](prompts.md): inventory of every AI prompt in the codebase and where to edit them.

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
