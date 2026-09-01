"""Background warmup of process-global caches at daemon startup.

Run creation used to pay every cold-start cost synchronously inside
``POST /runs``: the plugin discovery walk, the 138-file skill-registry parse,
the model-router module import, and the first SSL context for the Ollama
client (≈4s on Windows). The create path now caches those (see
``tools.plugins``, ``tools.skill_registry_cache``,
``tools.model_router._registry_info_from_config``,
``tools.providers.ollama_provider.build_ollama_raw_client``), and this module
pays them once in a daemon thread at daemon boot so even the FIRST run
creation skips the cold-start stall.

Best-effort by design: every stage is individually wrapped so a warmup
failure never prevents startup, and nothing here performs network I/O or
health checks — construction/caching only.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

log = logging.getLogger("breachpilot.run_create")


def warm_runtime_caches(config: dict[str, Any] | None) -> dict[str, float]:
    """Warm plugin/skill/model caches synchronously; return stage timings (ms).

    Safe to call from any thread. Never raises.
    """
    timings: dict[str, float] = {}

    def _stage(name: str, fn) -> None:
        start = time.perf_counter()
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- warmup is best-effort
            log.debug("warmup stage %s failed: %s", name, exc)
        finally:
            timings[name] = round((time.perf_counter() - start) * 1000.0, 1)

    # 1. Plugin discovery + registration (once per process).
    def _plugins() -> None:
        from tools.plugins import load_plugins

        load_plugins(config or {})

    _stage("plugins", _plugins)

    # 2. Skill registry parse (SKILL.md files under the configured roots).
    def _skills() -> None:
        from tools.skill_registry_cache import get_registry

        get_registry(config or {})

    _stage("skills", _skills)

    # 3. Model router module import + (ollama only) router construction so the
    # raw-client cache holds a warm SSL context. Non-ollama providers are NOT
    # constructed here: their build_router may spawn subprocesses (chatgpt
    # proxy) — construction stays on the create path for them.
    def _model_router() -> None:
        import tools.model_router  # noqa: F401 -- import cost paid at boot
        from tools.config.loader import get_ai_provider

        if get_ai_provider(config) != "ollama":
            return
        cfg = config or {}
        registry = (cfg.get("models", {}) or {}).get("registry")
        host = (cfg.get("ollama", {}) or {}).get("host", "https://api.ollama.com")
        tools.model_router.build_router(registry, host=host)

    _stage("model_router", _model_router)

    if timings:
        log.info(
            "runtime cache warmup: %s",
            " ".join(f"{name}={ms}ms" for name, ms in timings.items()),
        )
    return timings


def start_background_warmup(config: dict[str, Any] | None) -> threading.Thread | None:
    """Run :func:`warm_runtime_caches` on a daemon thread; return the thread."""
    thread = threading.Thread(
        target=warm_runtime_caches,
        args=(config,),
        daemon=True,
        name="breachpilot-warmup",
    )
    thread.start()
    return thread
