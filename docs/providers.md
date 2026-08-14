# Model Providers

How the engine talks to LLM backends — the chat/generate path, the embeddings
path, and the research path — and the concrete edit points for adding a new
provider. Today every path is Ollama-coupled; the chat path is
provider-agnostic *by accident* (consumers already receive a `ModelClient`
and call `.chat()`), so most of the work of multi-provider is already done.

Read alongside [config-reference.md](config-reference.md) for the config keys
and [deployment.md](deployment.md) for cloud-vs-local setup.

## Architecture overview

Three distinct provider surfaces, each coupled to Ollama differently:

| Surface | Coupling point | Multi-provider today? |
|---|---|---|
| Chat/generate | `tools/model_router.py` — `_build_model_client()` instantiates `ollama.Client`; `ModelClient` is the de-facto interface every consumer receives | No — Ollama-only, but consumers are provider-agnostic by accident |
| Embeddings | `tools/semantic_memory.py` — raw `urllib` POST to `/api/embeddings` | No — raw HTTP, no abstraction |
| Research (web search/fetch) | `tools/web_researcher.py` — `ResearchProvider` base + `OllamaResearchProvider` / `SerpAPIResearchProvider` | Yes — clean base class to model the others after |

Flow of a chat call:

```
config.yaml (ollama.host, models.registry)
    │
    ▼
tools/config_manager.py          ← load_validated_config(), accessors
    │   get_ollama_host(), get_default_model(), get_model_registry()
    │
    ▼
tools/model_router.py            ← build_router() → _build_model_client()
    │   instantiates ollama.Client(host=..., timeout=...)
    │   wraps in ModelClient(name, chat, stream, model_id)
    │   ollama client auto-attaches Authorization: Bearer $OLLAMA_API_KEY
    │
    ▼
ModelRouter                       ← registry of alias → ModelClient
    │
    ▼
consumers (exploit loop, swarm agents, payload crafter, ...) → client.chat()
```

## Chat/generate path (current)

### The interface — `tools/model_router.py:156-199`

`ModelClient` is the de-facto provider interface — a thin dataclass holding
two callables:

```python
# tools/model_router.py:156-167
@dataclass
class ModelClient:
    name: str
    chat: Callable[..., Any]
    stream: Callable[..., Any]
    model_id: str = ""
```

`ModelRouter` (`model_router.py:169-199`) is a `dict[alias → ModelClient]`
with `get_client(alias)`, `register()`, `clients()`, and `random_client()`.
`get_client` reverse-lookup a concrete model id (e.g. `glm-5.2:cloud`) to
its alias so a stray `--model glm-5.2:cloud` resolves instead of failing
boot (`model_router.py:178-191`).

Every chat consumer receives a `ModelClient` and calls `.chat()` — they do
not know or care that the underlying client is `ollama.Client`. This is the
property that makes adding a chat provider a small change.

### The factory — `tools/model_router.py:290-377`

`_build_model_client()` is the **single place** an `ollama.Client` is
constructed for the chat/generate path:

```python
# tools/model_router.py:31
from ollama import Client as OllamaClient

# tools/model_router.py:290-316
def _build_model_client(model_name, host=OLLAMA_CLOUD_HOST, *, alias="", request_timeout_seconds=None):
    ...
    raw_client = OllamaClient(host=host, timeout=request_timeout_seconds)
    ...
    def chat(*args, **kwargs):
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        response = raw_client.chat(**raw_kwargs)   # ← the actual Ollama call
        record_model_usage(...)                      # telemetry
        return response
    def stream_chat(*args, **kwargs):
        kwargs["stream"] = True
        return chat(*args, **kwargs)
    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name)
```

`_normalize_chat_args` (`model_router.py:224-241`) coerces both
`client.chat(model, messages=...)` and `client.chat(messages=...)` call styles
into the kwargs the underlying SDK expects, and forces the configured model id
so consumers can pass an alias. The `chat` closure also records telemetry via
`record_model_usage` (source field, alias, model id, wall duration, error).

`build_router()` (`model_router.py:380-394`) iterates `models.registry` and
registers one `ModelClient` per alias, all pointing at the same `host`.

### Authentication — automatic

The `ollama` Python client reads `OLLAMA_API_KEY` from the env on `Client`
init and auto-attaches `Authorization: Bearer <key>` to every chat/generate
request. **App code never manually attaches it for the chat path.** The
env var is loaded from `.api_keys.json` (gitignored) into `os.environ` by
`tools/api_key_store.load_api_keys_into_env()` (`api_key_store.py:105-119`)
at boot. The config key `ollama.api_key_env` (`config.yaml:9`,
`config_manager.py:32`) only names the env var — the value lives in the env.

The manual `Authorization: Bearer` attachment only happens on the **raw-HTTP
paths** (embeddings, doctor, live-models route) that bypass the ollama client
— see Embeddings and Gotchas below.

### Consumer call sites

All of these receive a `ModelClient` and call `.chat()` — provider-agnostic:

| Consumer | File:line | Notes |
|---|---|---|
| Exploit agent loop | `tools/exploit_agent/ollama_client.py:70, 125` | streaming + non-streaming, wrapped by `_call_ollama_with_retry` (`ollama_client.py:19-48`) |
| Exploit agent entry | `tools/exploit_agent/loop.py:938` | the main `await _call_ollama_with_retry(client, model, ...)` |
| Router-wrapped chat | `tools/model_router.py:330` | the actual `raw_client.chat(**raw_kwargs)` inside the closure |
| Payload crafter | `tools/payload_crafter.py:709, 815` | script generation + LLM mutation |
| Semantic memory summarization | `tools/semantic_memory.py:358` | uses the routed model client (not the raw HTTP path) |
| Safety reviewer | `tools/safety_reviewer.py:97` | |
| Swarm: vuln agent | `tools/swarm/agents/vuln_agent.py:381` | `context.get("model_client")` |
| Swarm: critic agent | `tools/swarm/agents/critic_agent.py:254` | |
| Swarm: reflection agent | `tools/swarm/agents/reflection_agent.py:386` | |
| Peer-model consultation | `tools/mcp_tools/peer_models.py:125`, `tools/exploit_agent/reflection.py:376` | advisory only, no tool schemas |
| Attack planning | `tools/mcp_tools/attack_modules.py:975, 1081` | create/replan attack plan |

### Tool-schema conversion — Ollama-format-specific

`mcp_tools_to_ollama()` (`tools/mcp_session.py:911-935`) converts MCP tool
schemas into the Ollama function-call format
`{"type":"function","function":{...}}`. This is the one chat-adjacent piece
that is Ollama-shaped; a non-Ollama chat provider needs its own converter or
a normalize-inside-`ModelClient` path (see the recipe below).

## Embeddings path (current)

Embeddings do **not** go through the ollama Python client — they use raw
`urllib` HTTP against `/api/embeddings`. This is the most Ollama-specific
surface.

### The generator — `tools/semantic_memory.py:48-106`

`SemanticMemoryManager._generate_embedding()` POSTs directly:

```python
# tools/semantic_memory.py:58-79
req = urllib.request.Request(
    f"{self._ollama_host}/api/embeddings",
    data=json.dumps({"model": self._embedding_model, "prompt": text}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
_api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
if _api_key:
    req.add_header("Authorization", f"Bearer {_api_key}")
with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    embedding = data.get("embedding")   # list[float] or None on failure
```

Returns `None` on any failure (Ollama unreachable, network error, non-finite
values) — `semantic_memory.py:82-106`. Every caller handles `None`
gracefully so a down embeddings host degrades to a no-op, not a crash.

`embed()` (`semantic_memory.py:37-46`) is the public single-text wrapper that
`SkillEmbedder` and other consumers call.

### Host wiring — `embed_host` falls back to `host`

Embeddings default to a **local** daemon (`embed_host:
http://localhost:11434`) while chat goes to cloud — `nomic-embed-text` is
small enough to self-host and avoids per-call cloud pricing for the 138-skill
catalog embeds plus every memory/lesson write. When `embed_host` is absent it
falls back to `host` so a cloud-only install still works. The fallback is
read in three places:

- `tools/config_manager.py:998-1006` — `get_ollama_embed_host()` accessor
- `agent_loop.py:176-182` (Flow B) — `_ollama_cfg.get("embed_host") or _ollama_cfg.get("host")`
- `tools/exploit_agent/loop.py:478-486` (Flow A) — same pattern
- `tools/skill_embeddings.py:180-186` (skill ranking) — same pattern

### Embedding consumers

| Consumer | File:line | What it embeds |
|---|---|---|
| Semantic memory store/lesson/similar | `tools/semantic_memory.py:118` | mission memory + lessons, cosine similarity retrieval |
| Skill catalog ranking | `tools/skill_embeddings.py:82` | 138-skill catalog for contextual selection |
| Memory summarization | `tools/semantic_memory.py:358` | uses `client.chat()` (the routed model), not embed |

### Config keys

- `memory.embedding_model: nomic-embed-text` (`config.yaml:348`,
  `config_manager.py:371`) — model name passed to `/api/embeddings`
- `skills.semantic_model: nomic-embed-text` (`config.yaml:419`,
  `config_manager.py:443`) — same model, for skill embeddings

## Research path (current — already multi-provider)

The research subsystem (web search/fetch) **already has** a clean
provider abstraction. This is the precedent to model the chat and embeddings
abstractions after.

### The base class — `tools/web_researcher.py:235-307`

```python
# tools/web_researcher.py:235-238
class ResearchProvider(ABC):
    """Provider abstraction for web search and fetch."""
    name: str = "provider"

# Abstract methods (web_researcher.py:282-288)
async def _search(self, query, *, max_results) -> list[SearchResult]: ...
async def _fetch(self, url) -> FetchResult: ...
```

The base class handles backoff (`_check_backoff`/`_record_success`/
`_record_failure`, `web_researcher.py:290-306`) and wraps errors in
`ResearchProviderError` (`web_researcher.py:221-232`) with a stable error code
safe to show to models. `search()`/`fetch()` (`web_researcher.py:246-280`)
are the public entry points that call the abstract `_search`/`_fetch`.

### Concrete providers

- `OllamaResearchProvider` (`web_researcher.py:309-395`) — uses
  `ollama.web_search` / `ollama.web_fetch` module functions via dynamic import
  (`_ollama_module`, `web_researcher.py:347-355`). Requires `OLLAMA_API_KEY`.
- `SerpAPIResearchProvider` (`web_researcher.py:398+`) — SerpAPI-compatible;
  fetch is intentionally unsupported.

### Config

- `research.provider: ollama` (`config.yaml:182`) — active provider
- `research.fallback_provider: serpapi` (`config.yaml:183`) — fallback
- `research.ollama.api_key_env` (`config.yaml:194`) — key for Ollama provider
- `research.serpapi.api_key_env` (`config.yaml:199`) — key for SerpAPI

## Config reference

The provider-relevant config lives in two top-level blocks. Full type
tables are in [config-reference.md](config-reference.md); the summary:

**`ollama:` (`config.yaml:1-14`)** — model backend

| Key | Default | Consumed at |
|---|---|---|
| `host` | `https://api.ollama.com` | `config_manager.py:996`, `model_router.py:287-316`, `doctor.py:320` |
| `model` | `glm-5.2:cloud` | `config_manager.py:31` |
| `api_key_env` | `OLLAMA_API_KEY` | `api_key_store.py:49` |
| `embed_host` | `http://localhost:11434` | `config_manager.py:998-1006`, `exploit_agent/loop.py:478` |

**`models:` (`config.yaml:15-44`)** — model registry

| Key | Default | Consumed at |
|---|---|---|
| `registry` | kimi/deepseek/deepseek_flash/glm/minimax | `config_manager.py:1011`, `model_router.py:70-76` |
| `default_alias` | `glm` | `config_manager.py:1008` |
| `info.<alias>.context_window` | per-model | `model_router.py:202-221`, `exploit_agent/context.py:63-104` |
| `info.<alias>.label/description` | per-model | `model_router.py:130`, `api/routes/system.py:193-194` |

**Env vars** — `OLLAMA_API_KEY` is the one load-bearing secret; everything else
is target-lock plumbing. Full env table in
[config-reference.md §Environment variables](config-reference.md#environment-variables).

## Recipe: add a new chat/generate provider

The minimal change. Consumers stay untouched — they already receive a
`ModelClient` and call `.chat()`.

### 1. Config

Add a provider selector to `config.yaml`:

```yaml
ollama:
  host: https://api.ollama.com
  model: glm-5.2:cloud
  api_key_env: OLLAMA_API_KEY
  provider: ollama          # ← new: "ollama" (default) | "openai" | "anthropic" | ...
```

Add the default + validation in `tools/config_manager.py:CONFIG_SCHEMA`
(`config_manager.py:22-34`) and `ConfigValidator.validate()` (`config_manager.py:571-577`).
Add an accessor (`get_ollama_provider()`), mirroring `get_ollama_host()`
(`config_manager.py:995-996`).

### 2. Factory — branch in `_build_model_client`

The single edit point is `tools/model_router.py:290-377`. Either branch
inside it or split into `_build_ollama_client` / `_build_openai_client` and
dispatch:

```python
def _build_model_client(model_name, host=OLLAMA_CLOUD_HOST, *, alias="",
                        request_timeout_seconds=None, provider="ollama"):
    if provider == "ollama":
        raw_client = OllamaClient(host=host, timeout=request_timeout_seconds)
    elif provider == "openai":
        from openai import OpenAI
        raw_client = OpenAI(api_key=os.environ[...], base_url=host)
    else:
        raise ValueError(f"unknown provider: {provider}")

    def chat(*args, **kwargs):
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        if provider == "ollama":
            response = raw_client.chat(**raw_kwargs)           # ollama signature
        else:
            response = raw_client.chat.completions.create(    # openai signature
                model=model_name, messages=raw_kwargs["messages"],
                tools=_convert_tools_to_openai(raw_kwargs.get("tools")),
            )
        record_model_usage(...); return response
    ...
    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name)
```

Thread the `provider` value from config through `build_router()`
(`model_router.py:380-394`).

### 3. Tool-schema conversion

`mcp_tools_to_ollama()` (`tools/mcp_session.py:911-935`) builds
`{"type":"function","function":{...}}` — Ollama's format. A non-Ollama
provider either:
- needs its own `mcp_tools_to_<provider>()` converter and a branch where the
  tool list is assembled, **or**
- normalize the tool schema inside the `ModelClient.chat` closure so
  consumers keep passing the Ollama-shape and the closure adapts. The second
  option keeps every consumer untouched.

The response shape (tool calls, content blocks) also differs between
providers — the `chat` closure is the natural place to normalize the
response back into the shape `tools/exploit_agent/ollama_client.py` expects,
so the exploit loop's parsing (`_call_ollama_with_tools`,
`ollama_client.py:125+`) doesn't need changes.

### 4. Authentication

For Ollama the ollama client auto-attaches the bearer. For a new provider
the SDK typically takes `api_key=` at construction (see the `openai.OpenAI`
example above). Read the key from the env var named by `ollama.api_key_env`
(or a new `ollama.<provider>_api_key_env`) — follow the existing
`tools/api_key_store.py` pattern so the key loads from `.api_keys.json` at
boot.

### What stays untouched

- Every consumer in the table above — they call `.chat()` on a `ModelClient`.
- `ModelRouter` — it just holds `ModelClient`s; it doesn't know the provider.
- `build_router()` — only needs the new `provider=` kwarg threaded through.
- Telemetry — `record_model_usage` already takes a `source` field
  (`model_router.py:322`) so provider attribution works out of the box.

### Tests

- `tests/test_config_manager.py` — new `provider` key defaulting + validation.
- A focused test for `_build_model_client` with the new provider, mocking the
  non-Ollama SDK so no network calls happen (matching the existing mock
  pattern — every test in `tests/` mocks subprocess/network).

## Recipe: add a new embeddings provider

The embeddings path has no abstraction today — `_generate_embedding` is a
raw HTTP call inside `SemanticMemoryManager`. The minimal abstraction
mirrors `ResearchProvider`:

### 1. Define an `EmbeddingProvider` base

In `tools/semantic_memory.py` (or a new `tools/embedding_provider.py`),
modeled on `ResearchProvider` (`web_researcher.py:235-307`):

```python
class EmbeddingProvider(ABC):
    name: str = "provider"
    @abstractmethod
    def embed(self, text: str) -> list[float] | None: ...
```

### 2. Move the existing call into `OllamaEmbeddingProvider`

The current `_generate_embedding` body (`semantic_memory.py:48-106`) becomes
`OllamaEmbeddingProvider.embed()` verbatim — same raw `urllib` POST, same
`None`-on-failure contract, same `Authorization: Bearer` attachment.

### 3. Construct the provider in `SemanticMemoryManager.__init__`

`SemanticMemoryManager.__init__` (`semantic_memory.py:25-33`) takes a
provider instance instead of a host string. The three construction sites
(`agent_loop.py:176-182`, `exploit_agent/loop.py:478-486`,
`skill_embeddings.py:180-186`) build the provider from config.

### 4. Consumers stay untouched

Every embedding consumer already calls `.embed(text)` (the public wrapper at
`semantic_memory.py:37-46`) or `self._sm.embed(text)` (skill embeddings) —
they don't reach into the raw HTTP path. So only the factory + the
implementation class change.

### Config

```yaml
ollama:
  embed_host: http://localhost:11434
  embed_provider: ollama    # ← new: "ollama" (default) | "localai" | ...
```

## Recipe: add a new research provider

This one is already done — `ResearchProvider` (`web_researcher.py:235-307`)
is the abstract base. To add a new provider:

1. Subclass `ResearchProvider`, implement `_search` and `_fetch`
   (or raise `RESEARCH_PROVIDER_UNAVAILABLE` for fetch if unsupported, like
   `SerpAPIResearchProvider` does).
2. Add a config block under `research:` (e.g. `research.bravesearch:` with
   `api_key_env`) and a `ResearchSettings` dataclass (mirror
   `OllamaResearchSettings` / `SerpAPIResearchSettings`).
3. Add the provider to the selector in whatever factory builds the active
   provider from `research.provider` (see how `ollama`/`serpapi` are wired).
4. Backoff, error wrapping, and the public `search()`/`fetch()` entry points
   come free from the base class.

See [research.md](research.md) for the full research-subsystem walkthrough.

## Gotchas

- **`session_titler.py` constructs its own client.** `tools/api/session_titler.py:109, 142`
  builds a standalone `ollama.Client(host=host, timeout=...)` with a
  hardcoded model `TITLE_MODEL = "gemma4:31b-cloud"` (`session_titler.py:26`),
  **not** via the router. A new chat provider needs a parallel update here,
  or route the titler through `ModelRouter` so it inherits the provider
  automatically.
- **`doctor.py` does raw HTTP.** `tools/doctor.py:154, 181, 239` POSTs directly
  to `/api/tags` and `/api/generate` via `urllib` with a manually-attached
  `Authorization: Bearer` header to verify cloud model reachability. This
  path is Ollama-API-specific and won't work against a non-Ollama provider's
  health endpoint — it needs its own probe or a provider-keyed branch.
- **`tools/api/routes/system.py:303` live-models route** also does raw HTTP
  to `/api/tags` with a manual bearer — same caveat as doctor.
- **Manual auth is only for raw-HTTP paths.** The ollama Python client
  auto-attaches `Authorization: Bearer $OLLAMA_API_KEY` for the chat path, so
  app code only attaches it manually in `semantic_memory.py:75-77`,
  `doctor.py`, and `api/routes/system.py:305`. A new chat provider using its
  own SDK handles auth at construction (see the recipe).
- **`mcp_tools_to_ollama()` is Ollama-format-specific.** The tool-schema
  converter at `tools/mcp_session.py:911-935` emits
  `{"type":"function","function":{...}}`. A non-Ollama chat provider needs its
  own converter or an in-`ModelClient` normalization (see the chat recipe).
- **Two flows share `db.py`/`mission.py` schemas only.** Flow A
  (`main.py`/`app.py` → `tools/exploit_agent/`) and Flow B (`cli.py` +
  root-level `agent_loop.py`/`db.py`/`mission.py`) both construct
  `SemanticMemoryManager` with the `embed_host`→`host` fallback
  (`agent_loop.py:176-182` vs `exploit_agent/loop.py:478-486`). An embeddings
  provider change must update both construction sites.
- **No CI.** Before a PR adding a provider: run `python -m pytest tests/ -v`
  and `ruff check .`, and verify the README/provider config still matches
  reality (see [AGENTS.md](../AGENTS.md) rule 8).