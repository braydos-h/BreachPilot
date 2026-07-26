# Changelog

## v0.49.5 (2026-07-26) — Tool-layer hardening: binary writes, local-target autonomous path, sudo-pivot, git_clone preflight, unified env registry, GITHUB_TOKEN bootstrap

Six residual gaps that remained even at v0.49.4 after the `127.0.0.1` run. All are
tool-layer, low-risk, and **none touch Flow B** (`cli.py` / `agent_loop.py` /
`scope_gate.py` / `mission.py` / `db.py`) or weaken the target-IP lock. 43 new
regression tests; full suite green apart from pre-existing Windows-only
`PermissionError`/offline-Ollama environmental failures (verified identical on a
clean `v0.49.4` checkout with these changes stashed).

### Added
- **`write_python_file(..., binary=True)`** (`tools/mcp_tools/workspace.py`). When
  `binary=True`, `code` is base64-decoded and `write_bytes`'d verbatim — so SSH-key
  / payload materialization no longer corrupts non-UTF-8 bytes via `write_text`.
  Default path (`binary=False`) is byte-identical to existing callers. Invalid
  base64 returns `BLOCKED: binary=True requires valid base64 (...)`. The agent
  prompt (`tools/exploit_agent/prompt.py`) and FastMCP `instructions`
  (`mcp_exploit_server.py`) now point at `write_python_file(..., binary=True)`
  with a base64 payload instead of the old "writes bytes verbatim" claim that the
  text-mode implementation didn't honor. Verified by `tests/test_workspace_binary_write.py`.
- **Local-target short-circuit in the autonomous orchestrator** (`tools/autonomous_orchestrator.py`).
  The LOCAL TARGET PLAYBOOK added in v0.49.4 only influenced the LLM `exploit_agent`
  path; the autonomous orchestrator against `127.0.0.1` still led with network
  brute-force of its own listeners. `_attack_target` now detects
  `is_local_target(state.target)` and runs a new `_phase_local_takeover` (the
  playbook's local-read commands — `/etc/passwd`, `sudo -n cat /etc/shadow`,
  `~/.ssh`, SUID/SGID, cron, service secrets — via `self._tool_executor` when
  wired, best-effort) then `_phase_privilege_escalation` and `_phase_validation`,
  returning before recon/network-exploit. `_phase_lateral_movement` returns early
  when local. The `scope_gate.check_scope(asset=task.target)` call inside
  `AttackModuleExecutor.execute` is **preserved** — the local branch only adds a
  locality path before the existing phase calls, it does not bypass the Path-B
  target lock. Verified by `tests/test_autonomous_local_target.py`.
- **`git_clone` existence preflight** (`tools/mcp_tools/terminal.py`). For `http(s)`
  URLs only, `git_clone` now calls the new module-level
  `tools/exploit_search.url_exists(url, timeout) -> (ok, reason)` before cloning.
  **Never hard-blocks** (private/auth-gated repos 404 to unauthenticated HEAD) —
  emits a `PREFLIGHT_WARNING` on `not_found` or `connection_error` and lets the
  clone proceed (it fails cleanly on its own if the URL is genuinely bad). Skipped
  for `ssh://` / `git://`. `url_exists` is the refactored-out core of
  `ExploitSearch._url_exists` (HEAD then 1-byte ranged-GET; never raises).
  Defense-in-depth behind `cve_to_poc`, which remains the upstream gate.
  Verified by `tests/test_git_clone_preflight.py`.
- **Optional `GITHUB_TOKEN` bootstrap.** `cve_to_poc` reads `os.getenv("GITHUB_TOKEN")`
  for the GitHub Search API rate limit (60/hr unauth → 5000/hr authed) but the
  token wasn't threaded through the key bootstrap. Now mirrored exactly on
  `NVD_API_KEY` handling and kept **optional** (`cve_to_poc` falls through to
  searchsploit / NVD refs on rate-limit — confirmed): `.env.example` documents it,
  `tools/config_manager.py` adds `cve_lookup.github.token_env: "GITHUB_TOKEN"`,
  `tools/api_key_store.py:configured_api_key_env_names` appends it, and
  `config.yaml` carries the matching block for discoverability. No change to
  `exploit_search.py` — `bootstrap_api_keys` now loads it into env and the existing
  `os.getenv` picks it up. Verified by `tests/test_github_token_bootstrap.py`.

### Fixed
- **`apt_install` / `install_package` / `run_as_root` no longer hang on sudo-less
  boxes.** These tools unconditionally built `sudo ...` via `bash -c` with no `-n`
  and no precheck; on a password-required box the subprocess hung on an interactive
  password prompt. New shared helper `tools/mcp_tools/terminal.py::_require_sudo_or_pivot`
  short-circuits *before* spawning the subprocess using the existing
  `_can_passwordless_sudo` probe: if unavailable it returns
  `BLOCKED: <tool> requires passwordless sudo ... PIVOT: call preflight_env_check,
  then implement <payload> as a workspace Python script via write_python_file +
  run_python_file. Do not retry.` The `BLOCKED:` prefix makes the agent's existing
  BLOCKED-result detection treat it as a hard constraint. Wired into `apt_install`
  (after validation), `run_as_root` (after the target-lock check so the lock still
  reports first), and the apt/snap branches of `install_package`. Windows gets the
  pivot message instead of a bogus `sudo` spawn. Verified by `tests/test_sudo_pivot.py`
  (the existing `test_run_as_root_*` tests patch `_can_passwordless_sudo→True` to
  keep exercising the run path on a Windows host).
- **`write_python_file` text/binary mismatch** (the v0.49.4 issue-6 guidance leak).
  The prompt told the agent `write_python_file` "writes bytes verbatim" for SSH-key
  materialization, but the implementation used `write_text(code, encoding="utf-8")`
  — non-UTF-8 key bytes corrupted. Fixed by the `binary=True` path above; the
  prompt/instructions now name the real signature.

### Changed
- **Single required-tool registry.** `tools/env_probe.py:_ENV_TOOLS`,
  `terminal.py:check_environment`'s `default_tools` literal, and
  `recon_pipeline.py:ReconConfig`'s `*_path` fields were three different lists, so
  the agent could see three different "missing tools" answers. `env_probe.py` is now
  the single source of truth: `_ENV_TOOLS` renamed to public `ENV_TOOLS` (with
  `_ENV_TOOLS = ENV_TOOLS` alias kept for patch-site compatibility), and
  `check_environment`'s default list derives from `ENV_TOOLS` plus an explicit
  `_CHECK_ENV_EXTRAS` (masscan, rustscan, feroxbuster, nuclei, …) with dedup via
  `_check_env_default_tools()`. `ReconConfig`'s `*_path` fields are intentionally
  **not** unified — they are binary-path overrides, a separate concern. Verified by
  `tests/test_env_probe.py`.

### Safety
- No change to `ExploitPermission` defaults, the target-IP allowlist lock,
  `scope_gate.py`, `safety_reviewer.py`, or any Flow B file. The autonomous
  orchestrator's Path-B `scope_gate.check_scope(asset=task.target)` target lock is
  preserved on the new local-takeover branch (asserted by
  `test_scope_gate_still_enforced_on_local_path`). `git_clone`'s preflight is
  warn-only and never hard-blocks. `GITHUB_TOKEN` is optional and never gates
  `cve_to_poc` correctness.

## v0.49.4 (2026-07-26) — verified CVE→PoC resolution, local-target playbook, unprivileged recon fallback, transport/parse split

Reliability + safety hardening for the exploit agent and recon pipeline (shipped in
commit `9996d39`; no CHANGELOG entry was cut at the time — backfilled here for history).

### Added
- **CVE→PoC (no more hallucinated clone URLs).** `tools/exploit_search.py:ExploitSearch.cve_to_poc`
  resolves a CVE to VERIFIED PoC URLs only — GitHub Search API + `searchsploit --cve`
  + NVD refs, each HTTP-existence-checked (HEAD / ranged-GET). Returns
  `NO_VERIFIED_POC_FOUND` when none verify, so the model writes a workspace-contained
  exploit instead of inventing a repo URL. New MCP tool `cve_to_poc`
  (`tools/mcp_tools/research.py`); `cve_to_exploit_synth` (`attack_modules.py`) now
  uses the verified resolver. Agent + server prompts forbid fabricating clone URLs.
- **Local-target playbook + key handling.** `tools/validation_utils.py:is_local_target`
  detects loopback / local-interface IPs. `tools/exploit_agent/prompt.py` injects a
  LOCAL TARGET PLAYBOOK (read `/etc/shadow`, `~/.ssh`, SUID, cron before network
  brute-force) and a FILE & KEY HANDLING rule (never paste keys into a heredoc;
  reference or `write_python_file` + `chmod 600`). Mirrored in `mcp_exploit_server.py`.
- **Unprivileged recon fallback (non-root operator box).** `tools/nmap_priv.py`:
  shared privilege/downgrade helpers; the recon pipeline applies the `sudo`/`-sT`
  downgrade and stops retrying on privilege errors. `tools/socket_scan.py`: native
  TCP-connect + banner scanner used as the final fallback tier when nmap/rustscan/
  masscan are unavailable or fail for lack of root. `ReconConfig.from_config()` reads
  `nmap.sudo` / `nmap.priv_fallback`.
- **Pre-flight environment probe (Issue 4).** `tools/env_probe.py`: stdlib-only
  startup probe of tool availability + installability; renders a PRE-FLIGHT
  ENVIRONMENT block into the system prompt (`loop.py`) so the model pivots to
  Python fallbacks instead of a doomed `apt_install` on a sudo-less box. New
  `preflight_env_check` MCP tool.

### Fixed
- **`cannot access local variable 'result'` (transport/parse split).**
  `tools/exploit_agent/loop.py` had a single `try` around both the MCP transport
  call (`session.call_tool`) and the result parsing (`result.content`); when
  `call_tool` raised, `result` was never bound and the shared `except` referenced
  it → `UnboundLocalError`, and a parse failure was mis-reported as a transport
  failure. The try was split: `result` is bound by the transport try before the
  parse try runs; a parse failure now surfaces as `INTERNAL_PARSE_ERROR:` (tool
  role, no blocked-accounting) instead of crashing. Verified by
  `tests/test_tool_call_parse_split.py`.
- **`[STATUS] Booting MCP server (stdio)...` spam.** `tools/mcp_session.py`'s
  `with ui.spinner(...)` enclosed `yield session`, so the redraw thread kept
  printing the elapsed-seconds line at 1 Hz for the entire exploit run.
  `ui.release_active_spinner()` is now called between `session.initialize()`
  success and `yield session`. Verified by `tests/test_spinner_release.py`.

## v0.49.3 (2026-07-25) — Best-effort installer + `natai` command; MCP HTTP soft-fail fixes

### Added
- **One-command install + global `natai` launcher.** `./install.sh` is now best-effort end-to-end: it installs OS prerequisites, Ollama, the venv, pulls models, runs `--doctor`, and drops a `natai` command in `~/.local/bin` that always runs from the repo root (so `config.yaml`/`mission.yaml`/`reports/` resolve from any cwd). `./install.sh --uninstall` removes the launcher and the guarded PATH block.
- **Installer env knobs:** `ADD_TO_PATH=0` (skip the launcher), `INSTALL_KALI_TOOLS=0` (skip Kali-only packages), `SKIP_MODEL_PULL=1` (skip model downloads).
- **README quick-install section** documenting the `natai` flow alongside the manual install steps.

### Fixed
- **MCP exploit server path resolution.** `open_exploit_mcp_session` located `mcp_exploit_server.py` with `Path(__file__).with_name(...)`, which resolves inside `tools/` and misses the repo-root server. Now walks up to the parent directory.
- **Three HTTP-transport soft-fail gaps** in `open_exploit_mcp_session` (`transport="http"`). The stdio branch was hardened against `BaseExceptionGroup` (Bug #20/#21/M19) but the HTTP branch was not — a group from `start_exploit_http_server` (port in use / `Popen` OSError), from `streamable_http_client`/`ClientSession` entry, or from `ClientSession.initialize()` (server dying mid-handshake) propagated past `soft_fail` and crashed the recon-first path instead of degrading to a `None` session. All three now yield `None` with `soft_fail=True`, emit `[WARN]`, and never print `[ERROR]`, using `_EXC_GROUP_CATCH` + `_log_nested_exceptions` as required.
- **HTTP soft-fail regression tests** (`TestHttpTransportSoftFail`) covering all three sites; fixed the boot-spinner count assertion to count the spinner form rather than the coexisting `boot_step` checklist lines.

## v0.49.2 (2026-07-24) — First public release

Initial public release of NetAttackAI (the "AI Target Exploitation Engine"), a
local-first, Ollama-driven penetration testing / bug bounty research agent.

### Added
- **Two assessment surfaces over one core**: the async, MCP-based exploitation engine (`main.py`/`app.py`) and the database-driven legacy research loop (`cli.py`).
- **MCP exploit server** (`mcp_exploit_server.py`) — terminal execution, Python file write/run, searchsploit, Metasploit, msfvenom, impacket lateral movement, credential dumping, kerberoasting — gated at the policy layer and target-locked at the tool layer.
- **Defensive MCP server** (`mcp_server.py`) — scope-gated Nmap scanning, sanitized vulnerability search, NVD CVE lookup (circuit breakered + rate limited).
- **Multi-agent swarm** (`tools/swarm/`) — 6 specialist agents with a shared blackboard, critic pre-check, and parallel dispatch; live MCP dispatch via `SwarmMcpBridge`.
- **Autonomous orchestrator** (`tools/autonomous_orchestrator.py`) — persistent multi-phase campaigns with adaptive aggression, auto-retry, and vulnerability chaining.
- **Textual TUI** (`python -m tui`) — 18-screen dashboard (missions, tasks, findings, evidence, scope, targets, target graph, reports, logs, settings, swarm, skills, memory, help).
- **Interactive menu** (`tools/interactive_menu.py`) — arrow-key-driven launcher, the default no-args behavior; `--menu` forces it.
- **Long-session mode** (`--long-session`) — opt-in multi-hour attack runs with crash-safe resume.
- **Reasoning loop** — `[REASONING]` feedback, opt-in LLM inline reflection, and auto peer-consult on consecutive exploit failures.
- **Runtime skills system** — advisory prompt-context layer over the `skills-to-add/` catalog with semantic matching, mid-run re-selection, cross-mission feedback, and untrusted-content sanitization.
- **Opt-in peer-model consultation** (`--multi-model-consult`).
- **Recon pipeline** — host discovery, service identification, enrichment, and recon-driven goal suggestion.
- **Reporting** — per-run timelines, CVSS, vulnerability chains, and findings export.
- **Linux/macOS support** — nmap unprivileged fallback (`-sS`→`-sT`, `-O` dropped), `attacker_os` correctness, UTF-8 sanitization fix, doctor Linux awareness, Makefile + `scripts/setup-linux.sh`.
- **Default model `glm-5.2:cloud`** (976K context) with adaptive context compaction.
- **`--version`**, `--doctor`, `--self-test`, and `--demo` entry points.

### Safety
- Recon remains fully scope-gated and propose-only (`read_only`) with a post-session `SafetyReviewer`.
- Attack is target-locked to the single operator-specified IP (no pivoting) via the MCP allowlist.
- Hard-forbidden actions regardless of config: denial of service, destructive exploit, social engineering, physical attack, malware, credential theft.
- Full JSONL audit trail (`exploit_audit.jsonl`) with SHA256 of generated code.

---

> **Note:** The `v1.1.0` and `v1.0.0` entries below were internal pre-launch milestones.
> The project was re-versioned to `0.x` for its first public release; they are preserved
> here for history.

## v1.1.0 (unreleased)

### Added
- **Long-session mode (`--long-session` / `long_session:` config block)** — opt-in multi-hour attack runs. Absent/false = current behavior; first-run defaults unchanged.
  - Sends the model's real context window (`options.num_ctx`) to Ollama on every chat call so the server actually allocates the window the compactor already assumes (prevents silent truncation). Routed through `model_router._normalize_chat_args` unchanged; omitted when long-session is off so non-long runs are byte-identical.
  - Per-LLM-call httpx timeout (`long_session.request_timeout_seconds`, default 600) passed to `OllamaClient(timeout=...)` so a hung generation raises `httpx.ReadTimeout` (already caught by `_is_retryable_error` → 3x retry → synthetic error) instead of hanging the event loop forever.
  - Raises `attack_max_rounds` / `attack_max_commands` / `attack_max_duration_minutes` from the `long_session:` block; explicit `--max-rounds` / `--max-commands` still win.
  - Lifts the hardcoded 300s swarm cap via `long_session.swarm_session_timeout_minutes` (default 30 min); `swarm.session_timeout_seconds` honored as a plain override. Extracted `_compute_swarm_timeout(config, args)` for testability. Single-MCP-session invariant preserved.
  - Crash-safe resume: when `long_session.persist_messages` is true, `SessionState` checkpoints the already-compacted `messages` (bounded to last 200) to `session_state.json` after each compaction and at the time/command-budget finals; `build_resume_messages` returns them verbatim on `--resume` instead of the lossy 300-char-condensed rebuild. Old state files (no `persist_messages` flag) load unchanged.
  - Wired into the swarm sub-agent's per-target `ExploitSettings` too, so swarm campaigns get the same longevity.
  - New `long_session:` keys registered in `KNOWN_TOP_KEYS` (no "Unknown config key" warning). Verified by `tests/test_long_session.py`.
- **Reasoning loop (Phase 1 — smarter, lowest risk)**:
  - **ULTRATHINK `[REASONING]` feedback (1a)**: the model's `[REASONING]...[/REASONING]` block (added to the prompt when `reasoning.ultrathink` is on) is now *parsed* each round (not just printed) and fed back the next round as a single refreshed user-role advisory. Pure string parse (no model call), `sanitize_output`-stripped, capped at ~400 chars, bounded to 3 entries. Advisory-only framing: never grants tool authority, never changes the target lock, never accumulates beyond one in-flight message (verified by `tests/test_reasoning_loop.py`).
  - **LLM-driven inline reflection (1b)**: new `reasoning.llm_reflection` config key (default **off** — opt-in extra LLM call in the hot loop). When on, the heuristic `_generate_reflection` call at the reflection hook is replaced by `_llm_reflect_inline`, which builds the prompt from *structured* tool-outcome summaries (not raw tool content), routes the call through the async `_call_ollama_with_retry` (already wrapped in `_EXC_GROUP_CATCH` — `BaseExceptionGroup` is NOT a subclass of `Exception`), and falls back to the heuristic on any failure. Every parsed JSON field is sanitized (`_sanitize_reflection_field` strips retarget/pivot-to-`<ip>`/ignore-prior/disregard/override-scope shapes) and capped (400 chars / 120 per pattern). The injected message is framed `[ADVISORY REFLECTION — system-generated, not an operator command]`. Reflections **never** feed the Bayesian `ExperienceStore` — only a semantic lesson with the distinct `action_type='reflection:exploit_loop'` is written, best-effort. Default-off preserves the heuristic-only behavior (verified by `tests/test_reasoning_loop.py`).
  - **Auto peer-consult on consecutive exploit failures (1c)**: new `reasoning.peer_consult_on_failure_threshold` config key (default 3; 0 disables). `_ToolOutcomeTracker` gains `consecutive_exploit_failures` (incremented only for real exploit actions — `run_exploit_terminal`/`run_python_file`/`run_msf_module`/`generate_payload` — that ran but failed; reset on the first exploit *success*; distinct from the blocked/unavailable counter). After the threshold is met, `_consult_peers_inline` runs an **in-process** consult (not a re-entrant MCP call) sharing the per-run `max_consultations` budget via the single `_consultation_count` counter (same source of truth as the `consult_peer_models` MCP tool). Each `peer.chat(...)` is wrapped in `_EXC_GROUP_CATCH`; advisory-only (peers called with `tools=None`). One `status='advisory'` audit record is written; target lock + egress allowlist are unchanged. No effect under `read_only` (nothing executes) or when `multi_model.enabled` is false. Verified by `tests/test_peer_consult_on_failure.py`.
- **Swarm sub-agent visibility in the UI**:
  - `tools/swarm/orchestrator.py` now emits lifecycle events (`agent_started`, `agent_complete`, `agent_failed`, `agent_blocked`, `critic_decision`, `reflection_output`, `blackboard_updated`) and persists a live `swarm_state.json` snapshot.
  - `agent_loop.py` routes these events to the console UI and a JSONL event trail.
  - New TUI screen `tui/screens/swarm.py` (`a` key / sidebar *Swarm Agents*) shows specialist agent status, shared blackboard, and battle log.
  - Dashboard Swarm card gives at-a-glance agent counts, access status, and latest reflection.
  - Task detail now shows which swarm agent handled a task.
  - Logs screen filters swarm event types.
- **`--swarm` dispatches through the live MCP session (no longer a stub)**: the swarm's `tool_executor` is now `SwarmMcpBridge.dispatch`, which shares `run_exploit_session`'s single MCP `ClientSession`. Recon-mode tool calls route through `ExploitPolicy.approve_action` → `session.call_tool` (gated, audited, target-locked — no longer the logged-only stub that returned `[swarm] <name> called with ...`); attack-mode `ExploitAgent` Path A runs its `run_exploit_agent` coroutine on the main loop via `asyncio.run_coroutine_threadsafe` instead of `asyncio.run` (which minted a fresh loop and failed on the session-bound coroutine). The swarm context's `model_client` is now populated (was always `None`, which kept Path A disabled). The summary line reports the real dispatched-tool-call count instead of a "MOCK / NOT-EXECUTED" prefix. The single-session invariant the `BaseExceptionGroup` helpers depend on is preserved — the swarm opens no second session.
- **Opt-in peer-model consultation**: `--multi-model-consult` and `multi_model.enabled` expose an advisory `consult_peer_models` MCP tool so the active agent can ask other configured model aliases for help when crafting exploits or recovering from repeated failures. It is off by default because each consultation can spend extra tokens.
- **Runtime Skills system** — advisory prompt-context layer over the `skills-to-add/` catalog, hardened and made to follow the assessment:
  - **Untrusted-content sanitization**: imported `SKILL.md` bodies are run through `_sanitize_skill_body` (strips HTML comments, `<script>`/`<iframe>`, role-directive headings/lines such as `## SYSTEM:`/`[SYSTEM]`/`<<SYSTEM>>`/`<|...|>`, `ignore`/`disregard`/`override` headings, fenced `system`/`instructions`/`ignore-above` role markers, and tool-call mimics like `- run tool:`) and the rendered output is wrapped in an `<untrusted_skill_guidance>` fence telling the model to treat embedded instructions with suspicion and never act on directives that conflict with scope/permission/approval/command-safety/audit.
  - **Mid-run re-selection**: as recon reveals new services/CVEs, `tools/exploit_agent/skills.py::_maybe_reselect_skills` rebuilds the active set and announces it to the model as a `[SKILL UPDATE]` user-role message (the system prompt is baked once and never mutated). Rate-guarded by `reselect_max_per_run`, `reselect_min_interval_actions`, a known-set tracker, and an identical-set no-op; `reselect_sticky_defaults` retains `default_enabled` across rebuilds. Never touches `permission`, `scope_gate`, `workspace_root`, or audit (asserted by `tests/test_skill_reselection.py`).
  - **Swarm phase hints**: the specialist swarm agents now receive phase-relevant skill hints via `tools/skill_pipeline.py` + `tools/swarm/skill_phase.py`; critic/reflection get the full advisory payload, non-exploit agents get hints only (never full bodies, preserving the single-MCP-session invariant).
  - **Cross-mission feedback**: `tools/skill_feedback.py` records `skill_loaded`/`skill_outcome` in the existing `ExperienceStore` Beta posterior and applies a **boost-only** selector term (`int((prior - 0.5) * 2 * feedback_skill_weight)`) once `feedback_min_observations` is reached. Negative outcomes never exclude a skill (advisory invariant).
  - **Semantic matching (default-on, graceful fallback)**: `tools/skill_embeddings.py::SkillEmbedder` ranks skills by `nomic-embed-text` cosine similarity with a per-process cache; when Ollama/the embedding model is unreachable it emits one `[WARN] skills: embeddings unavailable, falling back to tag matching` and deterministic tag matching remains the floor. Attack-only gating applies to semantic hits too.
  - **Bundle metadata**: `LoadedSkill` now carries `references`, `nist_csf`, `mitre_attack`; the new read-only `list_skill_references` MCP tool lists reference paths + framework summaries (gated by `skills.allow_reference_listing`, contents never inlined).
  - **CLI surface**: `--skills {on,off,hints,lookup}`, `--skills-list`, `--skills-include NAME`, `--skills-exclude NAME`, `--no-skills-reselect` (advisory in-memory config only — never permission/scope/audit).
  - **TUI surface**: read-only Skills screen (`k` key) showing catalog + active selection; no enable/disable toggle by design.
  - **`maybe/` tier**: `skills-to-add/maybe/` is gated by `skills.maybe_enabled` (default `false`); a placeholder skill ships at `skills-to-add/maybe/experimental-skill-test/`.
  - **New config keys** (all under `skills:`): `reselect_mid_run`, `reselect_max_per_run`, `reselect_min_interval_actions`, `reselect_sticky_defaults`, `swarm_inject`, `swarm_phase_hints_only`, `feedback_enabled`, `feedback_skill_weight`, `feedback_min_observations`, `semantic_matching`, `semantic_skill_weight`, `semantic_model`, `include_metadata`, `allow_reference_listing`.
  - **Docs**: `docs/skills.md` and the README Runtime Skills section describe the full pipeline; `skills-to-add/README.md` documents frontmatter, the `maybe/` tier, and the sanitization rules for upstream authors.
  - **Invariant**: skills remain advisory prompt context only — they never change `ExploitPermission`, widen `scope_gate`, bypass `require_allowlist`/command-safety/workspace containment, or suppress audit logging. The read-only MCP skill tools remain the only way the model pulls a full skill body mid-run; re-selection only changes which hints are pre-injected.
- **Tests**: `tests/test_swarm_ui.py` (7 tests) covers orchestrator events, persistence, ServiceRegistry parsing, and AgentLoop event persistence. New skill tests across `tests/test_skill_reselection.py`, `test_skill_pipeline.py`, `test_skill_feedback.py`, `test_skill_embeddings.py`, `test_skills_cli.py`, `test_tui_skills_screen.py`, and extensions to `test_skill_registry.py`, `test_skill_selector.py`, `test_mcp_runtime_skills.py`, and the swarm tests.

### Changed
- **Linux/macOS support pass**: the app now runs cleanly on a non-Kali Linux host and on macOS.
  - **nmap unprivileged fallback** (`mcp_server.py:_run_nmap`): nmap scans that require root (`-O` OS detection, `-sS` SYN) are auto-downgraded (`-sS`→`-sT`, `-O` dropped) when run unprivileged, instead of failing with a permission error. New `nmap.sudo` (run nmap via `sudo -n`) and `nmap.priv_fallback` (default `true`) config keys control it; `nmap.path` overrides the binary when nmap isn't on PATH. The `run_nmap_service_scan` (`-sV -sC -O`) tool now succeeds as `-sV -sC` for a normal non-root Linux user.
  - **`attacker_os` correctness**: `_resolve_attacker_os` distinguishes Darwin/macOS from Linux (macOS was previously told it was "running on Kali Linux"), and the Linux system-prompt branch now hedges on Kali-tool availability (verify `searchsploit`/`msfconsole`/`hydra`/`impacket-*` before relying on them; fall back to workspace-contained Python when missing). Resolves `exploit.attacker_os: auto` correctly for all three platforms.
  - **`sanitize_output` UTF-8 fix**: the Windows-only `cp1252` round-trip no longer runs on Linux/macOS, so em-dashes, accents, CJK, and box-drawing glyphs survive in terminal output (they were silently replaced with `?`).
  - **Doctor Linux awareness**: `--doctor` honors `nmap.path`, adds a POSIX privilege check (warns non-root users about `-O`/`-sS` and points to `nmap.sudo`), and reports present/missing Kali tooling (`searchsploit`/`msfconsole`/`tmux`/`hydra`/`impacket-secretsdump`) as informational guidance rather than a failure — so a Debian/Ubuntu host no longer fails the doctor for lacking Kali.
  - **Configurable tool paths**: new `exploit.shell` (Linux terminal shell, default `bash`) and `exploit.msfconsole_path` keys; `run_exploit_terminal` and the Metasploit tool honor them.
  - **Install docs + helpers**: README/CLAUDE.md/`docs/getting-started.md`/`docs/testing-guide.md` now show `source .venv/bin/activate` Linux/macOS steps alongside the Windows PowerShell ones; generic command fences converted to `bash`; new `Makefile` (`make install`/`doctor`/`test`/`run`/`tui`) and `scripts/setup-linux.sh` one-shot bootstrap.
  - **Tests**: `tests/test_linux_support.py` and new `tests/test_doctor.py` cases cover the UTF-8 fix, the OS resolver, the nmap downgrade helper, and the doctor's config-path/privilege/optional-tools checks.
- **Default model is now `glm-5.2:cloud` (976K context)**: `config.yaml` `ollama.model`, `models.registry.glm`, and `models.default_alias` now resolve to GLM-5.2 (alias `glm`), superseding GLM-5.1; `models.info.glm.context_window` bumped 128K → 976K. The adaptive context compactor gains a `glm` profile (compact at ~340K tokens, ~35% of the window), fixing premature compaction that would otherwise fire at ~83K. `deepseek`, `kimi`, and `minimax` remain selectable via `--model`/Settings; operators with an explicit `default_alias` in `config.yaml` are unaffected.
- `tui/services.py`: added `SwarmStateSnapshot`, `ServiceRegistry.swarm`, and swarm fields in `DashboardStats`.
- `tui/app.py`: added sidebar navigation and global `a` binding for the Swarm screen.
- `tui/app.tcss`: added dashboard and swarm screen styles.

## v1.0.0 (2026-04-30)

### Added
- **Interactive Menu System** (`tools/interactive_menu.py`): Full arrow-key-driven menu when running `python main.py` with no arguments. Includes Start New Session, TUI Dashboard, Mission Management, Reports Browser, Settings Editor, and Help.
- **`--tui` flag**: Launch the full Textual TUI dashboard directly from `main.py` (`python main.py --tui`).
- **`--menu` flag**: Force interactive menu mode even when other CLI arguments are present.
- **Config Validator** (`tools/config_manager.py`): Validates `config.yaml` structure, provides sensible defaults for missing keys, warns about unknown keys, and can save updated config back to disk.
- **Centralized Logging** (`tools/logging_setup.py`): Rotating file logger writing to `research_workspace/logs/app.log` with colored console output.
- **Settings Persistence**: TUI Settings screen now saves to `research_workspace/settings.json` with fields for Ollama host, default model, stealth defaults, risk profile, workspace directory, and theme.
- **Dashboard Quick Actions**: New Mission, Run Next Task, Refresh, and Open Logs buttons on the TUI dashboard.
- **System Status Indicator**: DB connection and mission status shown on the TUI dashboard.
- **Mission Setup Wizard**: Now uses real interactive form widgets (Input, TextArea, Checkbox, Select) instead of hard-coded defaults. Includes validation (name required, at least one asset, risk profile selected).
- **3 New Test Modules**: `test_interactive_menu.py` (8 tests), `test_config_manager.py` (10 tests), `test_tui_services.py` (5 tests).

### Fixed
- **ListItem `disabled=True` crash**: `tui/app.py` sidebar no longer uses the unsupported `disabled` attribute on `ListItem`. Separator items are now filtered by ID in the click handler.
- **DashboardScreen missing imports**: Added imports for `MissionSetupScreen`, `TasksScreen`, and `FindingsScreen`.
- **Circular import**: Resolved circular dependency between `dashboard.py` and `mission_setup.py` by using lazy imports.
- **Dashboard refresh timer crash**: Timer is now properly stopped when the dashboard screen is popped.
- **Defensive `query_one` calls**: All widget queries in dashboard and settings screens now use `_safe_update` helper to handle `NoMatches` gracefully.
- **TUI sync exception handling**: `main.py` now catches specific exceptions (`ImportError`, `OSError`, `ValueError`, `KeyError`) instead of bare `except Exception`.
- **Safe string handling**: `args.target` is consistently stripped and validated throughout `main.py`.

### Changed
- **main.py refactored**: `main()` now checks for `--tui`, `--menu`, and no-args cases before falling through to the existing CLI flow.
- **TUI Settings expanded**: Now includes Ollama host URL, default model alias, workspace directory, auto-refresh interval, risk profile, stealth defaults (rotate UA, DoH), and Unicode icon toggle.
- **Mission Setup auto-redirect**: After creating a mission, the wizard now auto-redirects to the Dashboard screen.
- **README updated**: New quick start section, interactive menu documentation, TUI screen reference, CLI flags table, and configuration guide.
- **Test suite**: 135 tests passing (up from 112).

### Safety
- All existing CLI flags remain functional for power users.
- Interactive menu is only triggered for no-args case or explicit `--menu` flag.
- Ctrl+C handled gracefully throughout — no stack traces, just "Goodbye!" or "Aborted."
- Backward compatible: all existing functionality preserved.
