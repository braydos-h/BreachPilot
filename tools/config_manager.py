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
        "host": "http://localhost:11434",
        "model": "glm-5.2:cloud",
    },
    "models": {
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
    "mcp": {
        "default_transport": "stdio",
        "http_host": "127.0.0.1",
        "http_port": 8001,
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
        # LAB BUILD: defaults grant live exploitation. Attack mode auto-
        # approves every action; the only remaining gate is the target-IP lock
        # (require_explicit_allowlist unions the runtime --target via
        # EXPLOIT_TARGET env). Recon mode keeps its own safety. See CLAUDE.md
        # "Permission Model". Only run against lab systems you own.
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
        # Gap 6: GitHub Search API token for cve_to_poc (CVE->verified-PoC URL
        # resolution). OPTIONAL -- absent = unauthenticated 60/hr rate limit;
        # cve_to_poc still works (falls through to searchsploit/NVD on rate-limit).
        # Mirrored into env at boot via api_key_store alongside NVD_API_KEY.
        "github": {
            "token_env": "GITHUB_TOKEN",
        },
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
    },
    "swarm": {
        "enabled": True,
        "agents": ["recon", "vuln", "exploit", "post_exploit", "critic", "reflection"],
        "max_parallel_agents": 3,
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
        "roots": ["skills-to-add"],
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
}

# Known top-level keys
KNOWN_TOP_KEYS = set(CONFIG_SCHEMA.keys())


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
        for key in self._config:
            if key not in KNOWN_TOP_KEYS:
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
                result.warnings.append("ollama.host is missing. Default: http://localhost:11434")

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
        return str(self._config.get("ollama", {}).get("host", "http://localhost:11434"))

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
