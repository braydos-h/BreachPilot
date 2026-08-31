"""AI-generated session titles for past runs.

Best-effort, fire-and-forget: a failure here must never break a run or the
API. ``generate_session_title`` builds a short prompt from the run's
result/request and asks the configured provider (``models.provider``) via the
provider registry for a <=60-char human-readable title summarizing what the
session did.

Provider-neutral: the non-Ollama path resolves the active provider adapter
(``tools.providers.registry.get_provider``) and asks it for the cheap title
model (``title_model(config)``) before routing every call through
``build_model_client_for_provider`` — no per-provider branches here. The
Ollama path keeps its raw ``/api/chat`` client (with the Ollama-only
``options={...}`` kwarg) because the Ollama API shape is Ollama's, and it is
the only place in this module that touches the Ollama SDK.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Mapping

from tools.providers.ollama_provider import load_client_cls

log = logging.getLogger(__name__)

TITLE_MODEL = "gemma4:31b-cloud"
_MAX_TITLE_CHARS = 60
_MAX_INPUT_CHARS = 1500  # cap the prompt's run-summary payload
_REQUEST_TIMEOUT_S = 30.0

# Raw Ollama SDK client class, loaded through the Ollama provider (the only
# module allowed to touch the SDK). ``None`` when the optional Ollama
# dependency is absent — the Ollama titling path then degrades to "" while the
# generic provider path stays fully functional.
OllamaClient = load_client_cls()


def _clip(text: Any, limit: int) -> str:
    s = str(text or "").strip()
    return s if len(s) <= limit else s[:limit].rsplit(" ", 1)[0] + "\u2026"


def _build_prompt(result: Mapping[str, Any], request: Mapping[str, Any]) -> str:
    """Build a compact summary of what the session did for the titler model."""
    target = result.get("target_ip") or request.get("target") or "unknown target"
    mode = result.get("mode") or request.get("mode") or "attack"
    goal = result.get("goal_name") or request.get("goal_name") or ""
    actions = result.get("total_actions") or 0
    outcome = _clip(result.get("outcome_summary") or "", 400)
    error = _clip(result.get("error") or "", 300)
    skills = result.get("active_skills") or []
    skill_names = ", ".join(s.get("name", "") for s in skills[:4] if isinstance(s, Mapping))
    skill_block = f"\nSkills used: {skill_names}" if skill_names else ""

    body = f"Target: {target}\nMode: {mode}\nGoal: {goal}\nActions executed: {actions}\nOutcome: {outcome}\n"
    if error:
        body += f"Error: {error}\n"
    body += skill_block
    body = body[:_MAX_INPUT_CHARS]

    return (
        "You are titling a penetration-testing session log entry. "
        "Read what the session did, then write ONE short title (<=60 chars) "
        "that summarizes the activity in plain English. "
        "No quotes, no trailing punctuation, no prefix like 'Title:'. "
        "Examples: 'Recon scan of 10.0.0.50', 'SMB exploit attempt on file share', "
        "'Failed SSH brute force against 192.168.1.10'.\n\n"
        f"Session data:\n{body}\n\nTitle:"
    )


def _clean_title(raw: str) -> str:
    """Strip model chatter, quotes, prefixes; cap to _MAX_TITLE_CHARS."""
    title = (raw or "").strip()
    # Drop common prefix artifacts.
    for prefix in ("Title:", "title:", "TITLE:", "Session title:"):
        if title.startswith(prefix):
            title = title[len(prefix) :].strip()
    # Strip markdown bold/quote/italics markers from both ends.
    title = title.strip("\"'`*_")
    # Take the first line only — model may elaborate after a newline.
    title = title.split("\n", 1)[0].strip()
    # Strip trailing period/ellipsis and any leftover emphasis markers.
    title = title.rstrip(".!?\u2026*_").strip()
    if not title:
        return ""
    if len(title) > _MAX_TITLE_CHARS:
        title = title[:_MAX_TITLE_CHARS].rsplit(" ", 1)[0]
    return title


def _generic_title(config: Mapping[str, Any] | None, provider_id: str, prompt: str) -> str:
    """Best-effort title via the active non-Ollama provider adapter.

    Single provider-neutral path: the adapter resolves the cheap title model
    (``title_model(config)``) and ``build_model_client_for_provider`` routes
    through the registry — no per-provider branches. Ollama-only kwargs are
    dropped by the model-router closure; temperature + max_tokens forward.
    Returns "" on any failure.
    """
    try:
        from tools.model_router import build_model_client_for_provider
        from tools.providers.registry import get_provider

        provider = get_provider(provider_id)
        model_id = provider.title_model(config)
        client = build_model_client_for_provider(config, model_id, request_timeout_seconds=_REQUEST_TIMEOUT_S)
        response = client.chat(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=30,
        )
        content = ""
        try:
            content = response["message"]["content"]
        except (KeyError, TypeError, IndexError):
            content = ""
        return _clean_title(content)
    except Exception as exc:  # best-effort — never raise to the caller
        log.debug("%s session title generation failed: %s", provider_id, exc)
        return ""


def _active_provider_id(config: Mapping[str, Any] | None) -> str:
    """Resolve the configured chat provider id (default ``ollama``)."""
    try:
        from tools.config_manager import get_ai_provider

        return get_ai_provider(config) if config else "ollama"
    except Exception:
        return "ollama"


async def generate_session_title(
    result: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    host: str = "https://api.ollama.com",
    model: str = TITLE_MODEL,
    config: Mapping[str, Any] | None = None,
) -> str:
    """Ask the configured provider for a short title summarizing the session.

    Returns "" on any failure (provider unreachable, missing pkg, bad
    response, timeout). Callers must treat the return as best-effort and
    persist only when non-empty. Non-Ollama providers go through the single
    generic registry path (``_generic_title``); the Ollama path keeps its raw
    ``/api/chat`` client with ``host``/``model`` unchanged.
    """
    return await asyncio.to_thread(generate_session_title_sync, result, request, host=host, model=model, config=config)


def generate_session_title_sync(
    result: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    host: str = "https://api.ollama.com",
    model: str = TITLE_MODEL,
    config: Mapping[str, Any] | None = None,
) -> str:
    """Synchronous variant for non-async callers (e.g. the retitle route).

    Same best-effort contract: returns "" on any failure.
    """
    prompt = _build_prompt(result, request)
    provider_id = _active_provider_id(config)
    if provider_id != "ollama":
        return _generic_title(config, provider_id, prompt)
    if OllamaClient is None:
        return ""
    try:
        client = OllamaClient(host=host, timeout=_REQUEST_TIMEOUT_S)
        response = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 30},
        )
        try:
            content = response["message"]["content"]
        except (KeyError, TypeError, IndexError):
            content = ""
        return _clean_title(content)
    except Exception as exc:
        log.debug("session title generation failed: %s", exc)
        return ""
