# Provider Development Guide

How to add a new AI provider to BreachPilot. After the pluggable-provider
refactor, **Ollama is one optional provider, not the internal protocol** — the
engine talks to the canonical [`ModelClient`](#the-modelclient-contract)
contract over the provider registry, and every backend-specific behavior
lives inside its adapter.

Read alongside [providers.md](providers.md) (architecture overview) and
[config-reference.md](config-reference.md) (config keys).

## The 30-second summary

Adding provider #4 means exactly four things, **all of them in new code**:

1. Write one adapter: a `BaseProvider` subclass in `tools/providers/<id>_provider.py`.
2. Register its instance in `tools/providers/registry.py:_LazyDefaultRegistry._ensure()`.
3. Add a `providers.<id>` schema block + defaults in `tools/config/schema.py`.
4. Add tests (contract tests run automatically for any registered provider).

No edits to the exploit agent, swarm, run service, session titler, eval
harness, doctor, or WebUI — they all resolve providers through the registry.

## The ModelClient contract

`tools.providers.types.ModelClient` is the canonical model client of the
engine. Consumers call `.chat()` / `.stream()`; they never see a backend SDK.

```python
@dataclass
class ModelClient:
    name: str                     # concrete model id
    chat: Callable[..., Any]      # non-stream call
    stream: Callable[..., Any]    # streaming call
    model_id: str = ""            # defaults to name
    provider: str = ""            # adapter id; telemetry attribution (default "ollama")
```

Every non-stream `.chat()` returns the **BreachPilot model response format**
(the formalized "Ollama-shaped dict"):

```python
{
    "model": "<concrete model id>",
    "message": {
        "role": "assistant",
        "content": "<text>",
        "thinking": "<reasoning, '' when not supported>",
        "tool_calls": [  # optional
            {"id": "...", "type": "function",
             "function": {"name": "...", "arguments": "<json string>"}},
        ],
    },
    "usage": {"input_tokens": int, "output_tokens": int, "total_tokens": int},  # optional
}
```

Streaming yields chunk dicts of the same shape (one per text delta, final
chunk carrying `tool_calls` / `usage`). Build these with the helpers in
`tools/providers/types.py` (`chat_response`, `stream_chunk`,
`stream_tool_chunk`, `tool_call`, `usage_report`) — they are the single
source of the shape. Tool-call `arguments` are a JSON **string**;
`tools.exploit_agent.model_client` / `_normalize_tool_call` parse them
(malformed → `{}`), so your adapter must normalize your backend's
response into this shape **inside** your `raw_client.chat()`.

## The BaseProvider surface

```python
# tools/providers/base.py — the full adapter contract
class BaseProvider(ABC):
    id: str                                    # matches models.provider / providers.<id>
    display_name: str                          # UI label
    capabilities: ProviderCapabilities         # explicit, never inferred

    @abstractmethod
    def build_router(config, *, request_timeout_seconds=None,
                     provider_config=None) -> ModelRouter
    def build_client(config, alias="", *, request_timeout_seconds=None) -> ModelClient
    def list_models(config) -> list[ModelInfo]         # live discovery
    def title_model(config) -> str                     # cheap session-titling model
    def health(config) -> ProviderHealth               # doctor-compatible checks
    def is_configured(cfg) -> bool                     # ready enough to attempt a call
    def metadata(config) -> dict                       # serialized for GET /providers (no secrets)
    def provider_config(config) -> dict                # normalized config block
```

Default implementations cover `metadata`, `is_configured` (enabled flag or
non-empty `base_url`), the config-merge, and a baseline `list_models` (the
configured `default_model` / `models` list) — override only what differs.

### Rules the contract enforces

- **ALL backend-specific behavior stays inside the adapter**: SDK import,
  auth, endpoint URLs, response normalization, model discovery. Engine code
  imports nothing backend-shaped.
- **`list_models` failures raise `ProviderDiscoveryError(message,
  fallback_models=[...])`** — never leak a bare network error. The API's
  `GET /models/live` turns it into a 503 with `source: "registry"` and your
  fallback list, so every caller degrades identically. Redact secrets
  (API keys) from `message`.
- **Missing third-party SDK raises `ProviderMissingDependencyError`** with an
  ACTIONABLE message (name the pip extra and the alternative provider).
- **`health()` returns `ProviderHealth(checks=[...])`** where each check is a
  doctor-shaped dict `{name, ok, error?, hint?, subchecks?}`. Never raise
  from `health()`.
- **`metadata()` never leaks secrets.** Id, display name, capability dict,
  `configured` bool, `default_model` — that's the surface the WebUI renders.
- **The canonical chat kwarg is `context_window_tokens`.** Generic code may
  pass it on any provider; your adapter translates it (Ollama's
  `options.num_ctx` via `apply_context_window`) or drops it. Never accept
  `options={"num_ctx": ...}` from generic code.
- **Wrap MCP-adjacent code in `_EXC_GROUP_CATCH`** (`tools/exceptions.py`) if
  your adapter ever wraps MCP session calls — `except Exception` misses
  `BaseExceptionGroup`.

## Reference adapters

| Adapter | File | Backend |
|---|---|---|
| Ollama | `tools/providers/ollama_provider.py` | Ollama cloud/local (`ollama.Client` SDK; the ONLY generic `import ollama` site) |
| OpenCode Go | `tools/providers/opencode_go_provider.py` | OpenAI **Responses API** at `opencode.ai/zen/go/v1` (httpx, bearer key) |
| ChatGPT | `tools/providers/chatgpt_provider.py` | vendored openai-oauth loopback proxy (browser OAuth) |

`OpenCodeGoProvider` is the cleanest reference for a pure-HTTP Responses-API
provider; `ChatGptProvider` shows an adapter that owns local process
lifecycle (its manager only ever stops a proxy it started itself).

## Step-by-step: implementing provider #4

### 1. The adapter

```python
# tools/providers/example_provider.py
from __future__ import annotations

from typing import Any, Mapping

from .base import BaseProvider, make_model_client
from .types import ModelClient, ModelInfo, ProviderCapabilities, ProviderDiscoveryError, ProviderHealth


class ExampleProvider(BaseProvider):
    id = "example"
    display_name = "Example Cloud"
    capabilities = ProviderCapabilities(chat=True, streaming=True, tool_calls=True,
                                        embeddings=False, model_discovery=True, reasoning=True)

    def build_router(self, config=None, *, request_timeout_seconds=None, provider_config=None):
        cfg = dict(provider_config) if provider_config is not None else self.provider_config(config)
        models = [str(m) for m in (cfg.get("models") or [])] or [str(cfg.get("default_model", "example-mini"))]
        router = tools.model_router.ModelRouter()          # or your own register/get_client holder
        for model in models:
            router.register(model, self._client_for(cfg, model, request_timeout_seconds))
        return router

    def build_client(self, config=None, alias="", *, request_timeout_seconds=None):
        cfg = self.provider_config(config)
        return self._client_for(cfg, alias or str(cfg.get("default_model", "example-mini")),
                                request_timeout_seconds)

    def _client_for(self, cfg, model, timeout):
        raw = ExampleRawClient(api_key=..., base_url=cfg["base_url"], default_model=model)
        return make_model_client(model, alias=model, raw_client=raw, provider=self.id)

    def list_models(self, config=None):
        # configured short-circuit, else live probe, else ProviderDiscoveryError
        ...
```

`make_model_client` (in `base.py`) is the shared `ModelClient` factory — it
wraps your raw client in the telemetry + canonical-arg closure
(`tools/model_router.py:_build_model_client`). Your raw client only has to
speak `.chat(**kwargs)` → BreachPilot response dict / stream iterable.

### 2. Register it

```python
# tools/providers/registry.py — _LazyDefaultRegistry._ensure()
PROVIDERS.register(ExampleProvider())
```

Registration is lazy and idempotent-safe: re-registering the **same class**
overwrites; a **different class** claiming the same id raises `ValueError`.

### 3. Config schema

In `tools/config/schema.py`:

```python
CONFIG_SCHEMA["providers"] = {}   # schema key must exist (default {})

DEFAULT_CONFIG["example"] = {          # documented defaults under providers.<id>
    "enabled": False,
    "base_url": "https://api.example.com/v1",
    "api_key_env": "EXAMPLE_API_KEY",
    "request_timeout_seconds": 300,
    "default_model": "example-mini",
    "models": [],
    "context_window": 128000,
    "discover_cache_seconds": 300,
}
```

That's the whole config story: `models.provider: example` selects it, the
`providers.example` block configures it (a legacy top-level `example:` block
still resolves — `tools.config.loader.get_provider_config` is the ONE
normalization layer: `providers.<id>` first, legacy block fallback).

### 4. Tests

- The contract suite (`tests/test_provider_contract.py`) parameterizes over
  `PROVIDERS.all()` — your adapter is picked up automatically and must pass
  the shared surface tests (metadata shape, health-never-raises,
  discovery-error degradation, title_model, is_configured honesty).
- Add focused tests for your adapter's chat/translation/auth behavior,
  mocking HTTP/SDK (every test in `tests/` mocks subprocess/network).
- No-Ollama guarantee: the engine must import and run with the `ollama`
  package blocked — `tests/test_no_ollama_regression.py` also enforces that
  the ollama SDK is imported ONLY in `tools/providers/ollama_provider.py`
  (don't add generic ollama imports anywhere).

## Operator-facing checklist (per acceptance gate)

When your provider ships, verify the Ollama-free operational surfaces:

- `models.provider: <id>` in `config.yaml` (the config validator whitelists
  ids from the registry via `tools.config_manager.resolve_known_provider_ids`
  — automatic).
- Doctor (`python main.py --doctor`) probes ONLY your provider: no Ollama
  endpoints for non-ollama selections (generic providers use your
  `health()`).
- `GET /api/v1/providers` returns your `metadata()` row (UI picker comes
  from it); `GET /api/v1/models/live` dispatches your `list_models`.
- Telemetry attributes usage by `provider` (`model_telemetry.py`).
- Embeddings are independent: `embeddings.provider: none` runs the engine
  with zero Ollama traffic; skills degrade to deterministic matching and
  semantic memory to keyword storage.