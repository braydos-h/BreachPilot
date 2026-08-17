"""Configuration validator and manager for config.yaml.

Provides:
- Validation of required keys and types
- Sensible defaults for missing values
- Warning about unknown keys
- Save updated config back to disk
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ── Expected schema with defaults ──────────────────────────────────────────

CONFIG_SCHEMA: dict[str, Any] = {
    "ollama": {
        # ponytail: cloud-only by default. Chat/generate go to Ollama Cloud
        # (https://api.ollama.com); the ollama Python client auto-attaches
        # ``Authorization: Bearer $OLLAMA_API_KEY``. Override ``host`` to use
        # a local daemon. ``embed_host`` keeps embeddings on local Ollama
        # (nomic-embed-text is small + cheap to self-host) and falls back to
        # ``host`` when absent — see config.yaml for the full rationale.
        "host": "https://api.ollama.com",
        "model": "glm-5.2:cloud",
        "api_key_env": "OLLAMA_API_KEY",
        "embed_host": "http://localhost:11434",
    },
    "models": {
        # ponytail: chat/generate provider selector. ``ollama`` (default) is
        # the unchanged per-alias registry path. ``chatgpt`` routes through
        # the local openai-oauth proxy (see the ``chatgpt`` block below).
        # Absent key = ``ollama`` so first-run behavior is unchanged.
        "provider": "ollama",
        "registry": {
            "kimi": "kimi-k2.6:cloud",
            "deepseek": "deepseek-v4-pro:cloud",
            "deepseek_flash": "deepseek-v4-flash:cloud",
            "glm": "glm-5.2:cloud",
            "minimax": "minimax-m3:cloud",
        },
        "default_alias": "glm",
        # Per-model metadata. The ``context_window`` value is the SOURCE OF
        # TRUTH for the adaptive context compactor in ``tools.exploit_agent``
        # -- keep in sync with config.yaml's ``models.info`` block. Mirrored
        # here so a missing config.yaml still yields the correct window per
        # alias (GLM-5.2 default = 976K); exploit_agent.py has no in-code
        # ``glm`` profile, so without this it would fall back to 128K.
        "info": {
            "kimi": {
                "label": "Kimi K2.6",
                "context_window": 256000,
                "description": "Moonshot Kimi K2.6 — strong long-form reasoning, 256K context.",
            },
            "deepseek": {
                "label": "DeepSeek V4 Pro",
                "context_window": 1000000,
                "description": "DeepSeek V4 Pro — 1M token context, deep code reasoning.",
            },
            "deepseek_flash": {
                "label": "DeepSeek V4 Flash",
                "context_window": 1000000,
                "description": "DeepSeek V4 Flash - 1M token context, fast DeepSeek option for lower-latency work.",
            },
            "glm": {
                "label": "GLM-5.2",
                "context_window": 976000,
                "description": "Zhipu GLM-5.2 — 976K context, the smartest/newest GLM for deep reasoning + coding.",
            },
            "minimax": {
                "label": "Minimax M3",
                "context_window": 512000,
                "description": "Minimax M3 (cloud) — 512K context, balanced coding + reasoning.",
            },
        },
    },
    # ChatGPT provider (openai-oauth). Opt-in: ``enabled: false`` by default so
    # first-run behavior is unchanged. When ``models.provider: chatgpt`` the
    # chat/generate path routes through the local openai-oauth proxy at
    # ``base_url`` (loopback-only by default). OAuth credentials stay in
    # openai-oauth's ``~/.codex/auth.json`` — they are NEVER copied into this
    # config or read by NetAttackAi (only their existence is checked). See
    # tools/providers/chatgpt_provider.py and docs/providers.md.
    "chatgpt": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 10531,
        "base_url": "http://127.0.0.1:10531/v1",
        "auto_start": True,
        "local_repo": "./oauth",
        "runtime": "auto",
        "request_timeout_seconds": 300,
        "default_model": "gpt-5.2",
        "models": [],
        "context_window": 128000,
        "login_timeout_seconds": 300,
        "start_timeout_seconds": 30,
        "discover_cache_seconds": 300,
        "oauth_file": "",
    },
    "mcp": {
        "default_transport": "stdio",
        "http_host": "127.0.0.1",
        "http_port": 8001,
    },
    # Engine advisory MCP server (``mcp_engine_server.py``): read-only skill
    # search / CVE lookup / run history for foreign AI assistants. Defaults
    # for the CLI entrypoint; HTTP transport is loopback-only via
    # ``tools.mcp_shared``.
    "engine_mcp": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8002,
    },
    # Linux-friendly nmap invocation. ``path`` overrides the binary when nmap
    # is not on PATH; ``sudo`` runs nmap via `sudo -n` so root-only scans
    # (-O OS detection, -sS SYN) work from a non-root shell; ``priv_fallback``
    # auto-downgrades those root-requiring flags instead of failing when the
    # host is unprivileged and sudo is off. No-op on Windows (no root concept).
    "nmap": {
        "path": "nmap",
        "sudo": False,
        "priv_fallback": True,
    },
    "exploit": {
        "enabled": True,
        "mode": "standalone",
        # LAB BUILD: defaults grant live exploitation. Full access auto-
        # approves every action; the only remaining gate is the target-IP lock
        # (require_explicit_allowlist unions the runtime --target via
        # EXPLOIT_TARGET env). Set permission to read_only for propose-only
        # recon. See CLAUDE.md "Permission Model". Only run against lab systems
        # you own.
        "permission": "full_access",
        "attack_mode": True,
        "terminal": "visible",
        "command_timeout_seconds": 300,
        "max_commands_per_session": 9999,
        "max_rounds": 200,
        "attack_max_commands": 150,
        "attack_max_rounds": 50,
        "attack_max_duration_minutes": 360,
        "context_summarize_every": 10,
        "auto_post_exploit": True,
        "max_pivot_depth": 2,
        "workspace_dir": "exploit_workspace",
        "loot_workspace": "exploit_workspace/loot",
        "attacker_os": "auto",
        "searchsploit_path": "searchsploit",
        # Linux: the shell used by `run_exploit_terminal` (default bash). No
        # effect on Windows (cmd.exe is used). ``msfconsole_path`` overrides
        # the Metasploit console binary when it's not on PATH.
        "shell": "bash",
        "msfconsole_path": "msfconsole",
        "web_search": True,
        "max_query_chars": 200,
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 50,
        # Target-IP lock. Interactive Start New Session saves entered IPs in
        # allowed_targets; the runtime --target is also injected via
        # EXPLOIT_TARGET (see mcp_session.py) and unioned at check time
        # (mcp_shared._check_allowlist). Add hosts here to authorize them in
        # addition to the runtime target.
        "require_explicit_allowlist": True,
        "allowed_targets": [],
        "disallowed_assets": [],
        "forbidden_actions": [],
        # Active Directory / Kerberos post-exploit suite (Phase 1). Opt-in:
        # the master ``enabled`` plus a per-tool flag must BOTH be true, or the
        # tool short-circuits with ``BLOCKED: ... disabled`` before the allowlist.
        # ``smb_signing_check`` is detection-only and defaults ON. Every tool is
        # target-IP-locked (@require_allowlist + check_targets_allowlist for DC).
        "ad_kerberos": {
            "enabled": False,
            "asrep_roast": False,
            "pass_the_hash": False,
            "adcs_enum": False,
            "bloodhound": False,
            "responder_relay": False,
            "golden_ticket": False,
            "smb_signing_check": True,
        },
        # Phase 3: MSF recipe dispatch + handler orchestration. Opt-in: when
        # ``recipes_enabled`` is false the ``msf_run_recipe`` MCP tool returns
        # BLOCKED before any dispatch. ``auto_local_exploit_suggester`` adds an
        # advisory LocalExploitSuggester task to the orchestrator privesc phase
        # (only surfaces the suggestion; Path B has no MSF session id, so it
        # never fabricates one).
        "msf": {
            "recipes_enabled": False,
            "auto_local_exploit_suggester": False,
        },
        # Phase 3: extended C2 listener types for ``start_listener``. Each is
        # opt-in (default OFF); the legacy netcat/socat/http types stay ungated.
        # ``socks_pivot`` upstream is allowlist-gated at the tool layer (pivot
        # lock).
        "listeners": {
            "tls": False,
            "dns": False,
            "https_beacon": False,
            "socks_pivot": False,
        },
    },
    "stealth": {
        "rotate_ua": False,
        "dns_over_https": False,
        "doh_provider": "cloudflare",
    },
    "cve_lookup": {
        "enabled": True,
        "max_results": 5,
        "rate_limit_seconds": 6.0,
        "timeout_seconds": 30,
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 100,
        "api_key_env": "NVD_API_KEY",
        # Tier 1.2: NVD circuit-breaker tuning (see CVESearchSettings).
        "circuit_failure_threshold": 5,
        "circuit_recovery_timeout": 60.0,
        # Tier 1.8: process-wide shared NVD rate budget (per minute); 0 disables.
        "search_rate_limit_per_minute": 10,
        # Phase 2: EPSS + KEV vuln-intel enrichment (lab build: ON by default
        # so enrichment is live out-of-the-box). EPSS adds exploit-likelihood
        # scoring; KEV flags CISA-known-exploited CVEs. Set false to disable.
        "epss_enabled": True,
        "kev_enabled": True,
        "kev_cache_ttl_seconds": 86400,
        "kev_cache_path": "",
        # Gap 6: GitHub Search API token for cve_to_poc (CVE->verified-PoC URL
        # resolution). OPTIONAL -- absent = unauthenticated 60/hr rate limit;
        # cve_to_poc still works (falls through to searchsploit/NVD on rate-limit).
        # Mirrored into env at boot via api_key_store alongside NVD_API_KEY.
        "github": {
            "token_env": "GITHUB_TOKEN",
        },
    },
    # Threat-intel feed (OSV.dev + GitHub Security Advisories + CISA KEV).
    # Advisory-only, never touches the target. Lab build: ON by default so the
    # feed is live out-of-the-box. Reuses cve_lookup's KEV catalog (shared
    # disk cache). GHSA needs GITHUB_TOKEN (shared with
    # cve_lookup.github.token_env); when absent, ghsa is silently dropped and
    # osv+kev still answer.
    "threat_intel": {
        "enabled": True,
        "cache_dir": "exploit_workspace/.threat_intel",
        "cache_ttl_seconds": 86400,
        "sources": {
            "osv": True,
            "ghsa": True,
            "kev": True,
            "exploitdb_rss": False,
        },
        "max_results": 20,
        "github_token_env": "GITHUB_TOKEN",
        "timeout_seconds": 30,
    },
    "research": {
        "enabled": True,
        "provider": "ollama",
        "fallback_provider": "serpapi",
        "timeout_seconds": 15,
        "max_results": 8,
        "max_fetch_depth": 5,
        "max_content_chars": 12000,
        "cache_ttl_seconds": 1800,
        "cache_max_entries": 250,
        "min_source_quality": "medium",
        "require_api_key_for_mcp_tools": True,
        "allow_local_fetch": False,
        "ollama": {
            "api_key_env": "OLLAMA_API_KEY",
            "max_results": 8,
            "use_web_search": True,
            "use_web_fetch": True,
        },
        "serpapi": {
            "api_key_env": "SERPAPI_API_KEY",
            "endpoint": "https://serpapi.com/search.json",
            "engine": "duckduckgo",
            "region": "us-en",
        },
        "assistant": {
            "enabled": True,
            "model_alias": "",
            "automatic": True,
            "failure_trigger": 2,
            "max_auto_consultations": 4,
            "max_tool_calls_per_consultation": 5,
            "max_model_rounds": 3,
            "max_advisory_chars": 4000,
            "timeout_seconds": 90,
            "save_advisories": True,
        },
    },
    "swarm": {
        "enabled": True,
        "agents": ["recon", "vuln", "exploit", "post_exploit", "critic", "reflection"],
        "max_parallel_agents": 3,
        # Phase 3/4: parallel sub-agents. ``parallel_enabled`` gates BOTH
        # route_parallel (the swarm's batched same-phase dispatch) AND the
        # spawn_subagent MCP tool (the main AI's delegation surface). Off by
        # default per the recon-first rollout — opt in via config or
        # ``--parallel-swarm``. ``per_phase_concurrency`` is the semaphore
        # size for route_parallel (3 = up to 3 concurrent same-phase agents).
        # ``exploit_parallel`` defaults False (exploit/post_exploit stay
        # sequential in route_parallel unless flipped); flip to True once
        # you've validated parallel recon is stable on your targets.
        "parallel_enabled": False,
        "per_phase_concurrency": 3,
        "exploit_parallel": False,
        # Phase 4: the spawn_subagent/await_subagent/list_subagents MCP tools
        # are gated on ``parallel_enabled`` (above) at registration time.
        # ``subagent_timeout_seconds`` is the ceiling for await_subagent so
        # a stuck sub-agent can't wedge the main AI's loop.
        "subagent_timeout_seconds": 600,
        # Bounded critic↔exploit negotiation rounds. 0 (default) = legacy
        # one-shot: the critic's ``modify`` is applied once and the task runs.
        # N>0 = after a ``modify``, the modified task is re-reviewed by the
        # critic up to N times until ``approve``/``deny``, a scope-expanding
        # modification is proposed (rejected), or the same modification
        # repeats (deadlock break). The negotiation is about HOW to execute a
        # planned action (risk level, tool swap, mutation, rate limiting),
        # never WHAT target/scope to hit — the allowlist lock is untouched.
        "negotiation_rounds": 0,
    },
    # Witness agent — advisory real-time audit-stream watcher (agent-on-agent
    # safety). Library default is OFF (conservative for downstream re-use);
    # config.yaml (the lab runtime) flips it ON so a lab run streams
    # anomaly telemetry by default. When enabled it polls the audit JSONL
    # trails (exploit_audit.jsonl, activity.jsonl) mid-run and flags
    # anomalies (allowlist breach, PoC escape, permission escalation,
    # prompt-injection pattern, DoS drift) to a witness log + the event
    # broker. It is advisory ONLY: it flags, it never blocks / modifies /
    # kills a run. See tools/swarm/agents/witness_agent.py.
    "witness": {
        "enabled": False,
        "log_path": "reports/witness.jsonl",
        "poll_interval_seconds": 5,
        "escalate_to_event_broker": True,
        "max_flags_per_signal_per_minute": 10,
        "dos_failure_window_seconds": 60.0,
        "dos_failure_threshold": 8,
    },
    # Autonomous orchestrator Phase 2 capabilities (opt-in). All keys default
    # OFF / 0 so default behavior is unchanged -- the new attack-path
    # capabilities must be explicitly enabled per the CLAUDE.md opt-in rule.
    "autonomous": {
        "persistence_phase": False,     # Phase 2.2: run PERSISTENCE phase after access achieved
        "checkpoint_every": 0,          # Phase 2.3: save attack_states.json every N completed targets (0 = off)
        "adaptive_replan": False,       # Phase 2.4: per-target multi-round replan + vuln-chaining
        "max_cycles": 100,              # round cap when adaptive_replan is on
        "max_pivot_depth": 0,           # already consumed by the orchestrator (single-IP lock default)
    },
    # D1: cross-mission semantic-memory consumer for the autonomous
    # orchestrator. When true, the orchestrator builds a
    # SemanticMemoryManager and calls store_lesson on confirmed module wins.
    # Advisory-only (read-only memory store consumer, no execution authority
    # change). Lab default ON — matches ``memory.semantic_enabled: true``;
    # the orchestrator is the missing campaign-level consumer of an
    # already-on capability, not a new attack-path opt-in.
    "orchestrator": {
        "semantic_memory": True,
    },
    # Recon coverage & depth (Phase 3). These gate the additive enumerators
    # (TLS/SSL cert parse, SMTP/DB banner parse, web spider, passive OSINT +
    # IPv6 AAAA lookup) and the UDP top-ports scan added in Phase 3. The TCP
    # ``scan_host`` path is unchanged regardless of these settings. IPv6 stays
    # PASSIVE-ONLY (AAAA lookup) -- the target-IP allowlist lock is untouched.
    "recon": {
        "extended_enumerators": True,   # enable TLS/SMTP/DB/spider/OSINT additive enumerators
        "udp_top_ports": 100,           # nmap -sU --top-ports N for run_udp_recon / recon_udp
        # Optional Shodan API key for passive OSINT. Empty = Shodan disabled
        # (run_osint returns {"enabled": False, ...}). Falls back to the
        # SHODAN_API_KEY env var at ReconConfig.from_config time.
        "shodan_api_key": "",
        # Extended depth enumerators (Phase 2). Each is independently gated and
        # default OFF; when False the coroutine never runs (no network, no
        # regressions to the legacy nine enumerators). All network I/O is
        # injectable for tests.
        "subdomain_enum": False,
        "vhost_discovery": False,
        "waf_fingerprint": False,
        "asn_whois": False,
        "cloud_metadata_probe": False,
        "snmp_enum": False,
        "dns_zone_transfer": False,
    },
    # OPSEC / detection-evasion (Phase 6.2). This is the agent's OWN operational
    # hardening (pacing/jitter/UA-rotation/DNS-over-HTTPS/quiet-commands) so an
    # authorized assessment can simulate a low-noise adversary, plus detection-
    # coverage testing (canary probes + read-only footprint summary). It is NOT
    # active evasion of the target's defenses: no log-clearing, timestomping, or
    # EDR/SIEM defeat; the append-only tamper-evident audit chain is untouched.
    # Defaults OFF per the CLAUDE.md opt-in rule -- first-run behavior is
    # unchanged. When enabled, AggressionLevel.STEALTH becomes load-bearing
    # (max jitter + min-gap + UA rotation + quiet-command denylist).
    "opsec": {
        "enabled": False,
        "ua_rotation": False,           # rotate User-Agent across HTTP egress
        "doh": False,                   # resolve via DNS-over-HTTPS (cloudflare/google)
        "doh_provider": "cloudflare",   # "cloudflare" | "google"
        "min_gap_seconds": 0.0,         # base pacing gap between actions
        "jitter_seconds": 0.0,          # +/- random jitter on the gap
        "rate_per_minute": 0,           # 0 = no token-bucket cap
        "quiet_command_patterns": [],   # substrings to refuse when enabled (e.g. ["masscan", "nuclei"])
        "noise_budget": 0,              # max noisy commands allowed (0 = unlimited)
        # Target-aware OPSEC: when the target IP is private/local (RFC1918,
        # loopback, link-local, reserved, ULA, or any local_cidrs entry) the
        # effective profile is forced OFF -- the operator owns the box and the
        # AI moves freely with no pacing/UA-rotation/quiet-blocking. A public-
        # routable target keeps the configured posture (OPSEC ON) and the AI
        # retains full attack autonomy (public_autonomy). Default true so the
        # local-off/public-on behavior is the out-of-the-box rule.
        "local_targets_off": True,
        "local_cidrs": [],              # extra CIDRs/IPs treated as local (e.g. ["10.99.0.0/16"])
        "public_autonomy": True,        # for public targets the AI chooses its own attacks (documentary)
    },
    # Eval/benchmark harness config. The --eval CLI flag still works when
    # ``enabled`` is false, but this block gates the defaults used by the
    # eval runner (output location, round budget, report formats).
    "eval": {
        "enabled": True,              # eval/benchmark harness enable (the --eval flag still works when false, but the config gates defaults)
        "output_dir": "reports/eval",  # where reports/eval/<run_id>/ trees are written
        "max_rounds": 30,             # attack_max_rounds for an eval run
        "write_markdown": True,       # emit eval_report.md alongside the JSON
        "write_html": True,           # emit eval_report.html alongside the JSON
    },
    # Long-session mode (opt-in). Absent/false = current behavior; the keys here
    # are the defaults applied when --long-session is passed or enabled: true.
    "long_session": {
        "enabled": False,
        "request_timeout_seconds": 600,
        "swarm_session_timeout_minutes": 30,
        "attack_max_rounds": 200,
        "attack_max_commands": 1000,
        "attack_max_duration_minutes": 720,
        "persist_messages": True,
    },
    "reasoning": {
        "chain_of_thought": True,
        "reflection_every_n_actions": 10,
        "critic_enabled": True,
        "observer_mode": "hybrid",
        "ultrathink": False,
        "ultrathink_reflection_interval": 3,
        "llm_reflection": False,
        "peer_consult_on_failure_threshold": 3,
    },
    "memory": {
        "semantic_enabled": True,
        "embedding_model": "nomic-embed-text",
        "cross_mission_learning": True,
        "attack_memory_enabled": True,
        "attack_memory_max_context_chars": 6000,
        # Tier 1.1: ExperienceStore soundness gates (see config.yaml memory).
        "experience_min_samples": 3,
        "experience_time_decay_days": 90,
    },
    "outcome_judgment": {
        # Only materially different checks count. A minimum of two ensures one
        # failed command cannot exhaust a hypothesis.
        "max_inconclusive_attempts": 3,
        "confirmation_threshold": 0.75,
        "refutation_threshold": 0.75,
        "min_evidence_references": 1,
        # Phase 1.2: wire OutcomeJudge into Flow A (exploit engine). Default OFF
        # per the CLAUDE.md opt-in rule -- first-run behavior is unchanged. When
        # true, the exploit loop runs classify_exploit_result + OutcomeJudge.judge
        # to produce an evidence-grounded verdict that overrides the shallow
        # ``exit_code == 0`` success flag.
        "flow_a": False,
        # D3: peer-model outcome judging. Advisory-only: one alias plans, a
        # different alias grades the evidence. Deterministic judge stays the
        # authority. Default OFF.
        "peer_review": False,
    },
    # D1: self-healing PoC verification (Killer Feature #3). When enabled,
    # ``cve_to_exploit_synth`` syntax-checks its synthesized PoC inline
    # (``py_compile``, no exec) and the ``verify_poc`` MCP tool compile-tests
    # the PoC inside a fully-isolated Docker container
    # (``--network=none --read-only --memory=256m``). The PoC is NEVER executed
    # on the operator box. Default OFF.
    "poc_verification": {
        "enabled": False,
        "docker_image": "python:3.11-slim",
        "compile_timeout_seconds": 30,
        "max_retries": 3,
        "docker_network": "none",
        "docker_read_only": True,
        "docker_memory": "256m",
    },
    # D2: replay simulator. When enabled, registers the ``replay_simulate``
    # MCP tool -- a local-only ``@audit_tool`` that dry-runs an attack plan
    # against a saved ReconAssessment JSON for pre-commit critique. Zero
    # target touch. Default OFF.
    "replay_simulator": {
        "enabled": False,
    },
    "adaptive_exploits": {
        "enabled": True,
        "max_mutations": 5,
        "mutation_strategies": [
            "parameter_tweak",
            "encoding_change",
            "delivery_swap",
            "context_aware",
        ],
    },
    "multi_model": {
        "enabled": False,
        "consult_aliases": ["kimi", "deepseek", "deepseek_flash", "glm", "minimax"],
        "max_consultations": 10,
        "max_question_chars": 4000,
        "max_answer_chars": 8000,
    },
    "skills": {
        "enabled": True,
        "roots": ["skills"],
        "default_enabled": [
            "scanning-network-with-nmap-advanced",
            "conducting-network-penetration-test",
            "executing-red-team-engagement-planning",
            "auditing-mcp-servers-for-tool-poisoning",
            "securing-agentic-ai-tool-invocation",
        ],
        "include_tags": [],
        "exclude_names": [],
        "maybe_enabled": False,
        "allow_model_lookup": True,
        "inject_startup_context": False,
        "max_active_skills": 6,
        "max_chars_per_skill": 2500,
        "max_total_chars": 9000,
        "min_contextual_skills": 3,
        "default_skill_weight": 12,
        "context_skill_weight": 24,
        "reselect_mid_run": True,
        "reselect_max_per_run": 3,
        "reselect_min_interval_actions": 5,
        "reselect_sticky_defaults": True,
        "swarm_inject": True,
        "swarm_phase_hints_only": True,
        "feedback_enabled": True,
        "feedback_skill_weight": 8,
        "feedback_min_observations": 3,
        "semantic_matching": True,
        "semantic_skill_weight": 16,
        "semantic_min_similarity": 0.35,
        "semantic_model": "nomic-embed-text",
        "diversity_penalty": 12,
        "include_metadata": False,
        "allow_reference_listing": True,
    },
    # Plugin/extension ecosystem (opt-in; defaults OFF). Plugins are trusted
    # Python with full operator-box privileges (lab build, same as built-ins).
    # ``enabled`` explicitly loads the named plugins; ``disabled`` hard-blocks
    # them regardless of manifest enablement; ``search_paths`` are the
    # filesystem dirs scanned for plugin.yaml manifests; ``entry_points`` gates
    # importlib entry-point discovery in the ``netattackai.plugins`` group.
    "plugins": {
        "enabled": [],
        "disabled": [],
        "search_paths": ["plugins"],
        "entry_points": True,
    },
    # Outbound-only Slack/Discord run-status notifications (webhook_notify
    # plugin). The plugin is OFF by default; enable here AND in
    # ``plugins.enabled``. ``url`` is a secret — never logged in plaintext.
    # ``events`` is the event-type filter list (e.g. ["finding","state"]).
    # Lab build: enabled true (no-op without a url — logs once then drops).
    "webhook_notify": {
        "enabled": True,
        "url": "",
        "events": ["finding", "state"],
        "timeout_seconds": 5,
        "max_retries": 3,
        "backoff_seconds": 2.0,
        "max_payload_chars": 8192,
    },
    # MITRE ATT&CK Navigator export (mitre-attack-export). Maps the run's
    # exploit_audit.jsonl → ATT&CK technique IDs → Navigator layer JSON the
    # blue team opens in ATT&CK Navigator. Lab build: enabled true.
    "mitre": {
        "enabled": True,
        "technique_map": "tools/mitre_technique_map.json",
        "navigator_output_dir": "reports/mitre",
        "include_skill_tags": True,
    },
    # Remediation ticket generation (remediation-tickets). Outbound-only
    # Jira/GitHub ticket creation from confirmed findings. The token is read
    # from the named env var — never copied into config or logs. Lab build:
    # enabled true (no-op without provider/base_url/token — logs once).
    "ticketing": {
        "enabled": True,
        "provider": "",
        "base_url": "",
        "token_env": "TICKETING_TOKEN",
        "project_key": "",
        "max_retries": 3,
        "backoff_seconds": 2.0,
    },
    # Local WebUI API daemon (``--demon`` / ``--daemon``). V1 is loopback-only;
    # there is no public-bind override. The bearer token is generated into
    # ``token_file`` (gitignored) on first boot, or overridden via
    # ``NETATTACKAI_API_TOKEN``. ``allowed_origins`` are extra loopback origins
    # permitted for CORS/WS (in addition to localhost/127.0.0.1); ``null`` and
    # non-loopback origins are always rejected.
    "api": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8765,
        "token_file": ".webui_secret_key",
        "allowed_origins": [],
        "event_buffer_size": 256,
        "shutdown_timeout_seconds": 15,
        "serve_webui": False,
        # D3: attack-path DAG API route. Lab build: enabled true.
        "graph_route": True,
    },
}

# Known top-level keys
KNOWN_TOP_KEYS = set(CONFIG_SCHEMA.keys())

# Alias for the schema-with-defaults dict, used by tests and downstream code
# that refers to it as the default config.
DEFAULT_CONFIG = CONFIG_SCHEMA


class ConfigValidationResult:
    """Result of config validation."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.unknown_keys: list[str] = []

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0 or len(self.unknown_keys) > 0

    def __repr__(self) -> str:
        return (
            f"ConfigValidationResult(errors={len(self.errors)}, "
            f"warnings={len(self.warnings)}, unknown={len(self.unknown_keys)})"
        )


class ConfigValidator:
    """Validates and manages config.yaml."""

    def __init__(self, config_path: Path | str = "config.yaml") -> None:
        self._path = Path(config_path)
        self._config: dict[str, Any] = {}

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self._path

    @property
    def config(self) -> dict[str, Any]:
        return self._config

    # ── Load & Validate ────────────────────────────────────────────────

    def load(self) -> dict[str, Any]:
        """Load config from disk. Returns the loaded config dict."""
        if not self._path.exists():
            logger.warning("config.yaml not found at %s, using defaults", self._path)
            self._config = self._build_defaults()
            return self._config

        with self._path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}

        if not isinstance(loaded, dict):
            raise ValueError(f"{self._path} must contain a YAML mapping, got {type(loaded).__name__}")

        self._config = loaded
        return self._config

    def validate(self) -> ConfigValidationResult:
        """Validate the loaded config. Returns a result with errors/warnings."""
        result = ConfigValidationResult()

        if not self._config:
            result.errors.append("Config is empty or not loaded.")
            return result

        # Check for unknown top-level keys
        plugin_sections: set[str] = set()
        try:
            from tools.plugins import PLUGIN_REGISTRY
            plugin_sections = set(PLUGIN_REGISTRY.config_sections.keys())
        except Exception:  # noqa: BLE001 -- plugins import must not break validation
            plugin_sections = set()
        for key in self._config:
            if key in KNOWN_TOP_KEYS or key in plugin_sections:
                continue
            result.unknown_keys.append(key)

        # Validate required sections exist
        for section in ("ollama", "models", "mcp", "exploit"):
            if section not in self._config:
                result.warnings.append(
                    f"Missing section '{section}'. Defaults will be used."
                )

        # Validate ollama section
        if "ollama" in self._config:
            ollama = self._config["ollama"]
            if not isinstance(ollama, dict):
                result.errors.append("'ollama' must be a mapping.")
            elif "host" not in ollama:
                result.warnings.append("ollama.host is missing. Default: https://api.ollama.com")

        # Validate models section
        if "models" in self._config:
            models = self._config["models"]
            if not isinstance(models, dict):
                result.errors.append("'models' must be a mapping.")
            else:
                if "registry" not in models:
                    result.warnings.append("models.registry is missing.")
                if "default_alias" not in models:
                    result.warnings.append("models.default_alias is missing. Default: glm")
                provider = models.get("provider")
                if provider is not None and str(provider).lower() not in {"ollama", "chatgpt"}:
                    result.warnings.append(
                        "models.provider should be one of: ollama, chatgpt."
                    )

        # Validate chatgpt provider block (opt-in; warn-only on absence).
        if "chatgpt" in self._config:
            chatgpt = self._config["chatgpt"]
            if not isinstance(chatgpt, dict):
                result.errors.append("'chatgpt' must be a mapping.")
            else:
                port = chatgpt.get("port")
                if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                    result.warnings.append(f"chatgpt.port {port} is invalid. Use 1-65535.")
                for bkey in ("enabled", "auto_start"):
                    val = chatgpt.get(bkey)
                    if val is not None and not isinstance(val, bool):
                        result.warnings.append(f"chatgpt.{bkey} must be a boolean.")
                for nkey in ("request_timeout_seconds", "context_window",
                             "login_timeout_seconds", "start_timeout_seconds",
                             "discover_cache_seconds"):
                    val = chatgpt.get(nkey)
                    if val is not None and (not isinstance(val, (int, float)) or val < 0):
                        result.warnings.append(f"chatgpt.{nkey} must be a non-negative number.")
                runtime = chatgpt.get("runtime")
                if runtime is not None and str(runtime).lower() not in {"auto", "bun", "node"}:
                    result.warnings.append(
                        "chatgpt.runtime should be one of: auto, bun, node."
                    )
                models_list = chatgpt.get("models")
                if models_list is not None and not isinstance(models_list, list):
                    result.warnings.append("chatgpt.models must be a list.")

        # Validate MCP section
        if "mcp" in self._config:
            mcp = self._config["mcp"]
            if not isinstance(mcp, dict):
                result.errors.append("'mcp' must be a mapping.")
            else:
                transport = mcp.get("default_transport", "")
                if transport not in ("stdio", "http", ""):
                    result.warnings.append(
                        f"mcp.default_transport '{transport}' is invalid. Use 'stdio' or 'http'."
                    )
                port = mcp.get("http_port")
                if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                    result.warnings.append(f"mcp.http_port {port} is invalid. Use 1-65535.")

        # Validate exploit section
        if "exploit" in self._config:
            exploit = self._config["exploit"]
            if not isinstance(exploit, dict):
                result.errors.append("'exploit' must be a mapping.")

        # Validate cve_lookup section (Tier 1.2: circuit-breaker tuning)
        if "cve_lookup" in self._config:
            cve = self._config["cve_lookup"]
            if not isinstance(cve, dict):
                result.errors.append("'cve_lookup' must be a mapping.")
            else:
                ft = cve.get("circuit_failure_threshold")
                if ft is not None and (not isinstance(ft, int) or ft < 1):
                    result.warnings.append(
                        "cve_lookup.circuit_failure_threshold must be a positive integer."
                    )
                rt = cve.get("circuit_recovery_timeout")
                if rt is not None and (not isinstance(rt, (int, float)) or rt <= 0):
                    result.warnings.append(
                        "cve_lookup.circuit_recovery_timeout must be a positive number."
                    )
                # Tier 1.8: shared NVD rate budget (per minute); 0 disables.
                spm = cve.get("search_rate_limit_per_minute")
                if spm is not None and (not isinstance(spm, (int, float)) or spm < 0):
                    result.warnings.append(
                        "cve_lookup.search_rate_limit_per_minute must be a non-negative number."
                    )

        # Validate research provider config
        if "research" in self._config:
            research = self._config["research"]
            if not isinstance(research, dict):
                result.errors.append("'research' must be a mapping.")
            else:
                provider = research.get("provider")
                if provider is not None and str(provider).lower() not in {"ollama", "serpapi", "stdlib"}:
                    result.warnings.append(
                        "research.provider should be one of: ollama, serpapi, stdlib."
                    )
                fallback = research.get("fallback_provider")
                if fallback is not None and str(fallback).lower() not in {"ollama", "serpapi", "stdlib", ""}:
                    result.warnings.append(
                        "research.fallback_provider should be one of: ollama, serpapi, stdlib."
                    )
                for key in ("timeout_seconds", "max_results", "max_fetch_depth", "max_content_chars", "cache_max_entries"):
                    value = research.get(key)
                    if value is not None and (not isinstance(value, int) or value < 1):
                        result.warnings.append(f"research.{key} must be a positive integer.")
                ttl = research.get("cache_ttl_seconds")
                if ttl is not None and (not isinstance(ttl, (int, float)) or ttl < 0):
                    result.warnings.append("research.cache_ttl_seconds must be a non-negative number.")
                quality = research.get("min_source_quality")
                if quality is not None and str(quality).lower() not in {"low", "medium", "high"}:
                    result.warnings.append("research.min_source_quality should be low, medium, or high.")
                require_key = research.get("require_api_key_for_mcp_tools")
                if require_key is not None and not isinstance(require_key, bool):
                    result.warnings.append("research.require_api_key_for_mcp_tools must be a boolean.")
                for nested in ("ollama", "serpapi"):
                    block = research.get(nested)
                    if block is not None and not isinstance(block, dict):
                        result.warnings.append(f"research.{nested} must be a mapping.")
                assistant = research.get("assistant")
                if assistant is not None and not isinstance(assistant, dict):
                    result.warnings.append("research.assistant must be a mapping.")
                elif isinstance(assistant, dict):
                    for key in ("enabled", "automatic", "save_advisories"):
                        value = assistant.get(key)
                        if value is not None and not isinstance(value, bool):
                            result.warnings.append(
                                f"research.assistant.{key} must be a boolean."
                            )
                    for key in (
                        "failure_trigger",
                        "max_auto_consultations",
                        "max_tool_calls_per_consultation",
                        "max_model_rounds",
                        "max_advisory_chars",
                    ):
                        value = assistant.get(key)
                        if value is not None and (not isinstance(value, int) or value < 1):
                            result.warnings.append(
                                f"research.assistant.{key} must be a positive integer."
                            )
                    timeout = assistant.get("timeout_seconds")
                    if timeout is not None and (
                        not isinstance(timeout, (int, float)) or timeout <= 0
                    ):
                        result.warnings.append(
                            "research.assistant.timeout_seconds must be a positive number."
                        )
                    alias = str(assistant.get("model_alias") or "").strip()
                    registry = (self._config.get("models", {}) or {}).get("registry", {})
                    if alias and isinstance(registry, dict) and alias not in registry:
                        result.warnings.append(
                            f"research.assistant.model_alias {alias!r} is not in models.registry."
                        )

        # Validate memory section (Tier 1.1: ExperienceStore soundness gates)
        if "memory" in self._config:
            memory = self._config["memory"]
            if not isinstance(memory, dict):
                result.errors.append("'memory' must be a mapping.")
            else:
                ms = memory.get("experience_min_samples")
                if ms is not None and (not isinstance(ms, int) or ms < 1):
                    result.warnings.append(
                        "memory.experience_min_samples must be a positive integer."
                    )
                td = memory.get("experience_time_decay_days")
                if td is not None and not isinstance(td, (int, float)):
                    result.warnings.append(
                        "memory.experience_time_decay_days must be a number "
                        "(set <= 0 to disable decay)."
                    )
                ame = memory.get("attack_memory_enabled")
                if ame is not None and not isinstance(ame, bool):
                    result.warnings.append("memory.attack_memory_enabled must be a boolean.")
                amc = memory.get("attack_memory_max_context_chars")
                if amc is not None and (not isinstance(amc, int) or amc < 1000):
                    result.warnings.append(
                        "memory.attack_memory_max_context_chars must be an integer >= 1000."
                    )

        # Validate deterministic evidence-grounded outcome judgment.
        if "outcome_judgment" in self._config:
            judgment = self._config["outcome_judgment"]
            if not isinstance(judgment, dict):
                result.errors.append("'outcome_judgment' must be a mapping.")
            else:
                max_attempts = judgment.get("max_inconclusive_attempts")
                if max_attempts is not None and (
                    not isinstance(max_attempts, int)
                    or isinstance(max_attempts, bool)
                    or max_attempts < 2
                ):
                    result.warnings.append(
                        "outcome_judgment.max_inconclusive_attempts must be an integer >= 2."
                    )
                for key in ("confirmation_threshold", "refutation_threshold"):
                    value = judgment.get(key)
                    if value is not None and (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not 0.5 <= value <= 1.0
                    ):
                        result.warnings.append(
                            f"outcome_judgment.{key} must be between 0.5 and 1.0."
                        )
                min_refs = judgment.get("min_evidence_references")
                if min_refs is not None and (
                    not isinstance(min_refs, int)
                    or isinstance(min_refs, bool)
                    or min_refs < 1
                ):
                    result.warnings.append(
                        "outcome_judgment.min_evidence_references must be a positive integer."
                    )
                flow_a = judgment.get("flow_a")
                if flow_a is not None and not isinstance(flow_a, bool):
                    result.warnings.append("outcome_judgment.flow_a must be a boolean.")

        # Validate reasoning section
        if "reasoning" in self._config:
            reasoning = self._config["reasoning"]
            if not isinstance(reasoning, dict):
                result.errors.append("'reasoning' must be a mapping.")
            else:
                ut = reasoning.get("ultrathink")
                if ut is not None and not isinstance(ut, bool):
                    result.warnings.append("reasoning.ultrathink must be a boolean.")
                ut_interval = reasoning.get("ultrathink_reflection_interval")
                if ut_interval is not None and (
                    not isinstance(ut_interval, int) or ut_interval < 1
                ):
                    result.warnings.append(
                        "reasoning.ultrathink_reflection_interval must be a positive integer."
                    )
                llm_reflect = reasoning.get("llm_reflection")
                if llm_reflect is not None and not isinstance(llm_reflect, bool):
                    result.warnings.append("reasoning.llm_reflection must be a boolean.")
                peer_threshold = reasoning.get("peer_consult_on_failure_threshold")
                if peer_threshold is not None:
                    if not isinstance(peer_threshold, int) or isinstance(peer_threshold, bool):
                        result.warnings.append(
                            "reasoning.peer_consult_on_failure_threshold must be an integer (0 disables)."
                        )
                    elif peer_threshold < 0:
                        result.warnings.append(
                            "reasoning.peer_consult_on_failure_threshold must be >= 0."
                        )

        # Validate multi-model peer consultation section
        if "multi_model" in self._config:
            multi_model = self._config["multi_model"]
            if not isinstance(multi_model, dict):
                result.errors.append("'multi_model' must be a mapping.")
            else:
                enabled = multi_model.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    result.warnings.append("multi_model.enabled must be a boolean.")
                aliases = multi_model.get("consult_aliases")
                if aliases is not None and (
                    not isinstance(aliases, list)
                    or not all(isinstance(alias, str) and alias.strip() for alias in aliases)
                ):
                    result.warnings.append("multi_model.consult_aliases must be a list of model alias strings.")
                for key in ("max_consultations", "max_question_chars", "max_answer_chars"):
                    value = multi_model.get(key)
                    if value is not None and (not isinstance(value, int) or value < 1):
                        result.warnings.append(f"multi_model.{key} must be a positive integer.")

        # Validate runtime skill system section
        if "skills" in self._config:
            skills = self._config["skills"]
            if not isinstance(skills, dict):
                result.errors.append("'skills' must be a mapping.")
            else:
                enabled = skills.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    result.warnings.append("skills.enabled must be a boolean.")
                maybe_enabled = skills.get("maybe_enabled")
                if maybe_enabled is not None and not isinstance(maybe_enabled, bool):
                    result.warnings.append("skills.maybe_enabled must be a boolean.")
                allow_lookup = skills.get("allow_model_lookup")
                if allow_lookup is not None and not isinstance(allow_lookup, bool):
                    result.warnings.append("skills.allow_model_lookup must be a boolean.")
                inject_startup = skills.get("inject_startup_context")
                if inject_startup is not None and not isinstance(inject_startup, bool):
                    result.warnings.append("skills.inject_startup_context must be a boolean.")
                for bool_key in (
                    "reselect_mid_run",
                    "reselect_sticky_defaults",
                    "swarm_inject",
                    "swarm_phase_hints_only",
                    "feedback_enabled",
                    "semantic_matching",
                    "include_metadata",
                    "allow_reference_listing",
                ):
                    value = skills.get(bool_key)
                    if value is not None and not isinstance(value, bool):
                        result.warnings.append(f"skills.{bool_key} must be a boolean.")
                for int_key in (
                    "reselect_max_per_run",
                    "reselect_min_interval_actions",
                    "feedback_skill_weight",
                    "feedback_min_observations",
                    "semantic_skill_weight",
                    "diversity_penalty",
                ):
                    value = skills.get(int_key)
                    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                        result.warnings.append(f"skills.{int_key} must be a non-negative integer.")
                sem_model = skills.get("semantic_model")
                if sem_model is not None and (not isinstance(sem_model, str) or not sem_model.strip()):
                    result.warnings.append("skills.semantic_model must be a non-empty string.")
                sem_threshold = skills.get("semantic_min_similarity")
                if sem_threshold is not None and (
                    isinstance(sem_threshold, bool)
                    or not isinstance(sem_threshold, (int, float))
                    or not 0 <= sem_threshold <= 1
                ):
                    result.warnings.append(
                        "skills.semantic_min_similarity must be a number between 0 and 1."
                    )
                for key in ("roots", "default_enabled", "include_tags", "exclude_names"):
                    value = skills.get(key)
                    if value is not None and (
                        not isinstance(value, list)
                        or not all(isinstance(item, str) and item.strip() for item in value)
                    ):
                        result.warnings.append(f"skills.{key} must be a list of non-empty strings.")
                for key in (
                    "max_active_skills",
                    "max_chars_per_skill",
                    "max_total_chars",
                    "min_contextual_skills",
                    "default_skill_weight",
                    "context_skill_weight",
                ):
                    value = skills.get(key)
                    if value is not None and (not isinstance(value, int) or value < 1):
                        result.warnings.append(f"skills.{key} must be a positive integer.")

        # D1: validate the orchestrator config section (cross-mission
        # semantic-memory consumer for the autonomous orchestrator).
        if "orchestrator" in self._config:
            orch = self._config["orchestrator"]
            if not isinstance(orch, dict):
                result.errors.append("'orchestrator' must be a mapping.")
            else:
                sem_mem = orch.get("semantic_memory")
                if sem_mem is not None and not isinstance(sem_mem, bool):
                    result.warnings.append("orchestrator.semantic_memory must be a boolean.")

        # Validate eval/benchmark harness section
        if "eval" in self._config:
            ev = self._config["eval"]
            if not isinstance(ev, dict):
                result.errors.append("'eval' must be a mapping.")
            else:
                enabled = ev.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    result.errors.append("eval.enabled must be a boolean.")
                output_dir = ev.get("output_dir")
                if output_dir is not None and (not isinstance(output_dir, str) or not output_dir.strip()):
                    result.errors.append("eval.output_dir must be a non-empty string.")
                max_rounds = ev.get("max_rounds")
                if max_rounds is not None and (
                    not isinstance(max_rounds, int) or isinstance(max_rounds, bool) or max_rounds < 0
                ):
                    result.errors.append("eval.max_rounds must be a non-negative integer.")
                for key in ("write_markdown", "write_html"):
                    value = ev.get(key)
                    if value is not None and not isinstance(value, bool):
                        result.errors.append(f"eval.{key} must be a boolean.")

        # Validate api (WebUI daemon) section
        if "api" in self._config:
            ap = self._config["api"]
            if not isinstance(ap, dict):
                result.errors.append("'api' must be a mapping.")
            else:
                host = ap.get("host", "127.0.0.1")
                if not isinstance(host, str) or not host.strip():
                    result.errors.append("api.host must be a non-empty string.")
                elif host not in ("127.0.0.1", "localhost", "::1"):
                    # v1 is loopback-only; no public-bind override.
                    result.errors.append(
                        f"api.host must be a loopback address (127.0.0.1/localhost/::1); "
                        f"got {host!r}. Public binds are not supported in v1."
                    )
                port = ap.get("port", 8765)
                if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
                    result.errors.append("api.port must be an integer in 1-65535.")
                token_file = ap.get("token_file")
                if token_file is not None and (not isinstance(token_file, str) or not token_file.strip()):
                    result.errors.append("api.token_file must be a non-empty string.")
                allowed_origins = ap.get("allowed_origins", [])
                if not isinstance(allowed_origins, list) or not all(
                    isinstance(o, str) for o in allowed_origins
                ):
                    result.errors.append("api.allowed_origins must be a list of strings.")
                for key in ("event_buffer_size", "shutdown_timeout_seconds"):
                    value = ap.get(key)
                    if value is not None and (
                        not isinstance(value, int) or isinstance(value, bool) or value < 0
                    ):
                        result.errors.append(f"api.{key} must be a non-negative integer.")
                serve_webui = ap.get("serve_webui")
                if serve_webui is not None and not isinstance(serve_webui, bool):
                    result.errors.append("api.serve_webui must be a boolean.")

        return result

    def load_and_validate(self) -> tuple[dict[str, Any], ConfigValidationResult]:
        """Load and validate in one call. Returns (config, result)."""
        config = self.load()
        result = self.validate()
        return config, result

    # ── Defaults ───────────────────────────────────────────────────────

    def _build_defaults(self) -> dict[str, Any]:
        """Build a complete config with all defaults."""
        import copy
        return copy.deepcopy(CONFIG_SCHEMA)

    def apply_defaults(self) -> dict[str, Any]:
        """Fill missing keys with defaults. Returns the merged config."""
        import copy
        defaults = copy.deepcopy(CONFIG_SCHEMA)

        def _deep_merge(base: dict, overlay: dict) -> dict:
            for key, value in overlay.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    _deep_merge(base[key], value)
                else:
                    base[key] = value
            return base

        merged = copy.deepcopy(defaults)
        _deep_merge(merged, self._config)
        self._config = merged
        return merged

    # ── Save ───────────────────────────────────────────────────────────

    def save(self, path: Path | str | None = None) -> None:
        """Save current config to disk."""
        target = Path(path) if path else self._path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(self._config, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        logger.info("Config saved to %s", target)

    # ── Convenience accessors ──────────────────────────────────────────

    def get_ollama_host(self) -> str:
        return str(self._config.get("ollama", {}).get("host", "https://api.ollama.com"))

    def get_ollama_embed_host(self) -> str:
        """Embedding host — local Ollama for nomic-embed-text by default.

        Falls back to the main ``ollama.host`` when ``embed_host`` is absent
        (so a cloud-only install with no local daemon still serves embeddings
        through the cloud).
        """
        ollama = self._config.get("ollama", {})
        return str(ollama.get("embed_host") or ollama.get("host", "https://api.ollama.com"))

    def get_default_model(self) -> str:
        return str(self._config.get("models", {}).get("default_alias", "glm"))

    def get_model_registry(self) -> dict[str, str]:
        return dict(self._config.get("models", {}).get("registry", {}))

    def get_mcp_transport(self) -> str:
        return str(self._config.get("mcp", {}).get("default_transport", "stdio"))

    def get_mcp_http_port(self) -> int:
        return int(self._config.get("mcp", {}).get("http_port", 8001))

    def get_exploit_config(self) -> dict[str, Any]:
        return dict(self._config.get("exploit", {}) or {})

    def get_stealth_config(self) -> dict[str, Any]:
        return dict(self._config.get("stealth", {}) or {})

    def get_multi_model_config(self) -> dict[str, Any]:
        return dict(self._config.get("multi_model", {}) or {})

    def get_skills_config(self) -> dict[str, Any]:
        return dict(self._config.get("skills", {}) or {})


# ── Module-level convenience ───────────────────────────────────────────────


def validate_config_file(path: Path | str = "config.yaml") -> ConfigValidationResult:
    """Quick validation of a config file. Returns the result."""
    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    return result


def load_validated_config(path: Path | str = "config.yaml") -> dict[str, Any]:
    """Load config with validation and defaults applied. Raises on errors."""
    validator = ConfigValidator(path)
    config, result = validator.load_and_validate()

    if not result.is_valid:
        error_msg = "; ".join(result.errors)
        raise ValueError(f"Config validation failed: {error_msg}")

    if result.has_warnings:
        for w in result.warnings:
            logger.warning("Config warning: %s", w)
        for uk in result.unknown_keys:
            logger.warning("Unknown config key: %s", uk)

    return validator.apply_defaults()


def get_ai_provider(config: dict[str, Any] | None = None) -> str:
    """Return the active chat/generate provider (``ollama`` | ``chatgpt``).

    Reads ``models.provider``; defaults to ``ollama`` so an absent key (the
    common case) is unchanged. Tolerates a None config.
    """
    cfg = config or {}
    models = cfg.get("models") if isinstance(cfg, dict) else None
    if isinstance(models, dict):
        provider = models.get("provider")
        if provider:
            return str(provider).lower()
    return "ollama"


def get_chatgpt_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the ``chatgpt`` block with schema defaults applied.

    The merge is shallow-over-defaults; used by the model-router and proxy
    manager. Never returns None.
    """
    import copy
    base = copy.deepcopy(CONFIG_SCHEMA.get("chatgpt", {}))
    cfg = config or {}
    overlay = cfg.get("chatgpt") if isinstance(cfg, dict) else None
    if isinstance(overlay, dict):
        for key, value in overlay.items():
            if value is not None:
                base[key] = value
    return base


def get_ollama_host(config: dict[str, Any] | None = None) -> str:
    """Return ``ollama.host`` from a config dict (module-level convenience)."""
    cfg = config or {}
    ollama = cfg.get("ollama") if isinstance(cfg, dict) else None
    if isinstance(ollama, dict):
        return str(ollama.get("host", "https://api.ollama.com"))
    return "https://api.ollama.com"
