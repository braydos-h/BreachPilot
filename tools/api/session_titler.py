"""AI-generated session titles for past runs.

Best-effort, fire-and-forget: a failure here must never break a run or the
API. ``generate_session_title`` builds a short prompt from the run's
result/request and asks ``gemma4:31b-cloud`` (via the Ollama client) for a
<=60-char human-readable title summarizing what the session did.

The model is a separate, smaller cloud model (not the main attack model) so
titling stays cheap and never competes with the attack loop for the main
model's context window. The host and API key reuse the same Ollama Cloud
wiring (``ollama.host`` + ``OLLAMA_API_KEY``) — no extra config.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Mapping

try:
    from ollama import Client as OllamaClient
except ImportError:  # pragma: no cover - ollama is a runtime dep
    OllamaClient = None  # type: ignore

log = logging.getLogger(__name__)

TITLE_MODEL = "gemma4:31b-cloud"
_MAX_TITLE_CHARS = 60
_MAX_INPUT_CHARS = 1500  # cap the prompt's run-summary payload
_REQUEST_TIMEOUT_S = 30.0


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

    body = (
        f"Target: {target}\n"
        f"Mode: {mode}\n"
        f"Goal: {goal}\n"
        f"Actions executed: {actions}\n"
        f"Outcome: {outcome}\n"
    )
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
            title = title[len(prefix):].strip()
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


def _chatgpt_title(config: Mapping[str, Any], prompt: str) -> str:
    """Best-effort title via the ChatGPT provider. Returns "" on any failure.

    Uses ``chatgpt.default_model`` (GPT models have no dedicated cheap title
    model in openai-oauth's /v1/models). Ollama-only kwargs (options/num_predict)
    are dropped by the adapter; temperature + max_tokens are forwarded.
    """
    try:
        from tools.config_manager import get_chatgpt_config
        from tools.model_router import build_model_client_for_provider

        chatgpt_cfg = get_chatgpt_config(config)
        model_id = str(chatgpt_cfg.get("default_model") or "gpt-5.2")
        client = build_model_client_for_provider(
            config, model_id, request_timeout_seconds=_REQUEST_TIMEOUT_S
        )
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
        log.debug("chatgpt session title generation failed: %s", exc)
        return ""


def _provider_is_chatgpt(config: Mapping[str, Any] | None) -> bool:
    if not config:
        return False
    try:
        from tools.config_manager import get_ai_provider

        return get_ai_provider(config) == "chatgpt"
    except Exception:
        return False


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
    persist only when non-empty. When ``config`` indicates the ChatGPT
    provider, titles go through the local openai-oauth proxy; otherwise the
    Ollama ``gemma4:31b-cloud`` path runs unchanged.
    """
    return await asyncio.to_thread(
        generate_session_title_sync, result, request, host=host, model=model, config=config
    )


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
    if _provider_is_chatgpt(config):
        return _chatgpt_title(config, prompt)
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
