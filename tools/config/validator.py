"""Configuration validator — validation logic."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .schema import CONFIG_SCHEMA, KNOWN_TOP_KEYS

logger = logging.getLogger(__name__)


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

        # Strict nested-key check for core sections (typos like exploit.permision
        # must be errors, not silent warnings — see test_exploit_permision_typo_is_error).
        for strict_section in ("ollama", "models", "mcp", "exploit"):
            sec = self._config.get(strict_section)
            if isinstance(sec, dict):
                allowed = set(CONFIG_SCHEMA.get(strict_section, {}).keys())
                for key in sec:
                    if key not in allowed:
                        result.errors.append(f"Unknown key '{strict_section}.{key}'")

        # Validate required sections exist
        for section in ("ollama", "models", "mcp", "exploit"):
            if section not in self._config:
                result.warnings.append(f"Missing section '{section}'. Defaults will be used.")

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
                    result.warnings.append("models.provider should be one of: ollama, chatgpt.")
                # Model-role routing: each value should be a string alias (or
                # empty = use default_alias). A non-string / non-alias value
                # is ambiguous only when it doesn't resolve — warn, never
                # reject (existing warn-not-reject convention).
                roles = models.get("roles")
                if roles is not None:
                    if not isinstance(roles, dict):
                        result.warnings.append("models.roles must be a mapping.")
                    else:
                        registry = models.get("registry", {}) or {}
                        for role, alias in roles.items():
                            if alias is None:
                                continue
                            if not isinstance(alias, str):
                                result.warnings.append(
                                    f"models.roles.{role} must be a string alias (empty = default_alias)."
                                )
                                continue
                            stripped = alias.strip()
                            if stripped == "":
                                continue
                            if isinstance(registry, dict) and stripped not in registry:
                                result.warnings.append(f"models.roles.{role} {stripped!r} is not in models.registry.")

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
                for nkey in (
                    "request_timeout_seconds",
                    "context_window",
                    "login_timeout_seconds",
                    "start_timeout_seconds",
                    "discover_cache_seconds",
                ):
                    val = chatgpt.get(nkey)
                    if val is not None and (not isinstance(val, (int, float)) or val < 0):
                        result.warnings.append(f"chatgpt.{nkey} must be a non-negative number.")
                runtime = chatgpt.get("runtime")
                if runtime is not None and str(runtime).lower() not in {"auto", "bun", "node"}:
                    result.warnings.append("chatgpt.runtime should be one of: auto, bun, node.")
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
                    result.warnings.append(f"mcp.default_transport '{transport}' is invalid. Use 'stdio' or 'http'.")
                port = mcp.get("http_port")
                if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                    result.warnings.append(f"mcp.http_port {port} is invalid. Use 1-65535.")

        # Validate exploit section
        if "exploit" in self._config:
            exploit = self._config["exploit"]
            if not isinstance(exploit, dict):
                result.errors.append("'exploit' must be a mapping.")
            else:
                perm = exploit.get("permission")
                if perm is not None:
                    if perm not in ("read_only", "approve_only", "full_access"):
                        result.errors.append("exploit.permission must be one of: read_only, approve_only, full_access")

        # Validate cve_lookup section (Tier 1.2: circuit-breaker tuning)
        if "cve_lookup" in self._config:
            cve = self._config["cve_lookup"]
            if not isinstance(cve, dict):
                result.errors.append("'cve_lookup' must be a mapping.")
            else:
                ft = cve.get("circuit_failure_threshold")
                if ft is not None and (not isinstance(ft, int) or ft < 1):
                    result.warnings.append("cve_lookup.circuit_failure_threshold must be a positive integer.")
                rt = cve.get("circuit_recovery_timeout")
                if rt is not None and (not isinstance(rt, (int, float)) or rt <= 0):
                    result.warnings.append("cve_lookup.circuit_recovery_timeout must be a positive number.")
                # Tier 1.8: shared NVD rate budget (per minute); 0 disables.
                spm = cve.get("search_rate_limit_per_minute")
                if spm is not None and (not isinstance(spm, (int, float)) or spm < 0):
                    result.warnings.append("cve_lookup.search_rate_limit_per_minute must be a non-negative number.")

        # Validate research provider config
        if "research" in self._config:
            research = self._config["research"]
            if not isinstance(research, dict):
                result.errors.append("'research' must be a mapping.")
            else:
                provider = research.get("provider")
                if provider is not None and str(provider).lower() not in {"ollama", "serpapi", "stdlib"}:
                    result.warnings.append("research.provider should be one of: ollama, serpapi, stdlib.")
                fallback = research.get("fallback_provider")
                if fallback is not None and str(fallback).lower() not in {"ollama", "serpapi", "stdlib", ""}:
                    result.warnings.append("research.fallback_provider should be one of: ollama, serpapi, stdlib.")
                for key in (
                    "timeout_seconds",
                    "max_results",
                    "max_fetch_depth",
                    "max_content_chars",
                    "cache_max_entries",
                ):
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
                            result.warnings.append(f"research.assistant.{key} must be a boolean.")
                    for key in (
                        "failure_trigger",
                        "max_auto_consultations",
                        "max_tool_calls_per_consultation",
                        "max_model_rounds",
                        "max_advisory_chars",
                    ):
                        value = assistant.get(key)
                        if value is not None and (not isinstance(value, int) or value < 1):
                            result.warnings.append(f"research.assistant.{key} must be a positive integer.")
                    timeout = assistant.get("timeout_seconds")
                    if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
                        result.warnings.append("research.assistant.timeout_seconds must be a positive number.")
                    alias = str(assistant.get("model_alias") or "").strip()
                    registry = (self._config.get("models", {}) or {}).get("registry", {})
                    if alias and isinstance(registry, dict) and alias not in registry:
                        result.warnings.append(f"research.assistant.model_alias {alias!r} is not in models.registry.")

        # Validate memory section (Tier 1.1: ExperienceStore soundness gates)
        if "memory" in self._config:
            memory = self._config["memory"]
            if not isinstance(memory, dict):
                result.errors.append("'memory' must be a mapping.")
            else:
                ms = memory.get("experience_min_samples")
                if ms is not None and (not isinstance(ms, int) or ms < 1):
                    result.warnings.append("memory.experience_min_samples must be a positive integer.")
                td = memory.get("experience_time_decay_days")
                if td is not None and not isinstance(td, (int, float)):
                    result.warnings.append(
                        "memory.experience_time_decay_days must be a number (set <= 0 to disable decay)."
                    )
                ame = memory.get("attack_memory_enabled")
                if ame is not None and not isinstance(ame, bool):
                    result.warnings.append("memory.attack_memory_enabled must be a boolean.")
                amc = memory.get("attack_memory_max_context_chars")
                if amc is not None and (not isinstance(amc, int) or amc < 1000):
                    result.warnings.append("memory.attack_memory_max_context_chars must be an integer >= 1000.")

        # Validate deterministic evidence-grounded outcome judgment.
        if "outcome_judgment" in self._config:
            judgment = self._config["outcome_judgment"]
            if not isinstance(judgment, dict):
                result.errors.append("'outcome_judgment' must be a mapping.")
            else:
                max_attempts = judgment.get("max_inconclusive_attempts")
                if max_attempts is not None and (
                    not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 2
                ):
                    result.warnings.append("outcome_judgment.max_inconclusive_attempts must be an integer >= 2.")
                for key in ("confirmation_threshold", "refutation_threshold"):
                    value = judgment.get(key)
                    if value is not None and (
                        isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.5 <= value <= 1.0
                    ):
                        result.warnings.append(f"outcome_judgment.{key} must be between 0.5 and 1.0.")
                min_refs = judgment.get("min_evidence_references")
                if min_refs is not None and (
                    not isinstance(min_refs, int) or isinstance(min_refs, bool) or min_refs < 1
                ):
                    result.warnings.append("outcome_judgment.min_evidence_references must be a positive integer.")
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
                if ut_interval is not None and (not isinstance(ut_interval, int) or ut_interval < 1):
                    result.warnings.append("reasoning.ultrathink_reflection_interval must be a positive integer.")
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
                        result.warnings.append("reasoning.peer_consult_on_failure_threshold must be >= 0.")

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
                    result.warnings.append("skills.semantic_min_similarity must be a number between 0 and 1.")
                for key in ("roots", "default_enabled", "include_tags", "exclude_names"):
                    value = skills.get(key)
                    if value is not None and (
                        not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value)
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

        # Capability-upgrade agent block (design §23): warn-not-reject on
        # type/range for the toggles + budgets. Bools/ints follow the existing
        # convention (see chatgpt/skills blocks above).
        if "agent" in self._config:
            agent = self._config["agent"]
            if not isinstance(agent, dict):
                result.errors.append("'agent' must be a mapping.")
            else:
                for bkey in (
                    "task_graph_enabled",
                    "capability_discovery_enabled",
                    "state_tools_enabled",
                    "planner_hints_enabled",
                    "decision_log_enabled",
                    "reflection_enabled",
                ):
                    val = agent.get(bkey)
                    if val is not None and not isinstance(val, bool):
                        result.warnings.append(f"agent.{bkey} must be a boolean.")
                for ikey in ("max_retries_per_task", "max_actions", "generated_code_repair_attempts"):
                    val = agent.get(ikey)
                    if val is not None and (not isinstance(val, int) or isinstance(val, bool) or val < 0):
                        result.warnings.append(f"agent.{ikey} must be a non-negative integer (0 = legacy default).")

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

        # Validate benchmark suite section
        if "benchmark" in self._config:
            bm = self._config["benchmark"]
            if not isinstance(bm, dict):
                result.errors.append("'benchmark' must be a mapping.")
            else:
                enabled = bm.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    result.errors.append("benchmark.enabled must be a boolean.")
                output_dir = bm.get("output_dir")
                if output_dir is not None and (not isinstance(output_dir, str) or not output_dir.strip()):
                    result.errors.append("benchmark.output_dir must be a non-empty string.")
                trials = bm.get("trials")
                if trials is not None and (not isinstance(trials, int) or isinstance(trials, bool) or not 1 <= trials <= 20):
                    result.errors.append("benchmark.trials must be an integer in 1-20.")
                timeout = bm.get("timeout_seconds")
                if timeout is not None and (
                    not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 30
                ):
                    result.errors.append("benchmark.timeout_seconds must be an integer >= 30.")
                sandbox_required = bm.get("sandbox_required")
                if sandbox_required is not None and not isinstance(sandbox_required, bool):
                    result.errors.append("benchmark.sandbox_required must be a boolean.")
                regression = bm.get("regression")
                if regression is not None:
                    if not isinstance(regression, dict):
                        result.errors.append("benchmark.regression must be a mapping.")
                    else:
                        for key in (
                            "success_rate_tolerance",
                            "false_positive_tolerance",
                            "median_time_tolerance",
                            "tool_actions_tolerance",
                            "cost_tolerance",
                        ):
                            val = regression.get(key)
                            if val is not None and (
                                not isinstance(val, (int, float)) or isinstance(val, bool) or not 0 <= val <= 1
                            ):
                                result.errors.append(f"benchmark.regression.{key} must be a number in 0-1.")
                telemetry = bm.get("telemetry")
                if telemetry is not None:
                    if not isinstance(telemetry, dict):
                        result.errors.append("benchmark.telemetry must be a mapping.")
                    else:
                        for key in ("events", "token_usage", "cost"):
                            val = telemetry.get(key)
                            if val is not None and not isinstance(val, bool):
                                result.errors.append(f"benchmark.telemetry.{key} must be a boolean.")

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
                if not isinstance(allowed_origins, list) or not all(isinstance(o, str) for o in allowed_origins):
                    result.errors.append("api.allowed_origins must be a list of strings.")
                for key in ("event_buffer_size", "shutdown_timeout_seconds"):
                    value = ap.get(key)
                    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
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
