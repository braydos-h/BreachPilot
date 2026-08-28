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
| Chat/generate | `tools/model_router.py` — `_build_model_client()` builds a `ModelClient` over either `ollama.Client` (provider `ollama`, default) or `ChatGptProxyClient` (provider `chatgpt`); `ModelClient` is the de-facto interface every consumer receives | **Yes** — `models.provider: ollama\|chatgpt`; consumers are provider-agnostic |
| Embeddings | `tools/semantic_memory.py` — raw `urllib` POST to `/api/embeddings` | No — raw HTTP, no abstraction (stays Ollama even under `provider: chatgpt`) |
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

`_build_model_client()` is the **single place** a chat client is constructed
for the chat/generate path. It takes an injectable `raw_client` so the Ollama
and ChatGPT paths share one closure (telemetry, `_normalize_chat_args`,
`_stream_with_telemetry`):

```python
# tools/model_router.py:31
from ollama import Client as OllamaClient

# tools/model_router.py (provider-aware seam)
def _build_model_client(model_name, host=OLLAMA_CLOUD_HOST, *, alias="",
                        request_timeout_seconds=None, raw_client=None,
                        provider="ollama"):
    ...
    if raw_client is None:                       # the Ollama path (default)
        raw_client = OllamaClient(host=host, timeout=request_timeout_seconds)
    # else: ChatGPT path uses the injected ChatGptProxyClient directly
    ...
    def chat(*args, **kwargs):
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        response = raw_client.chat(**raw_kwargs)   # ← Ollama or ChatGPT adapter
        record_model_usage(..., provider=provider) # telemetry (provider-attributed)
        return response
    def stream_chat(*args, **kwargs):
        kwargs["stream"] = True
        return chat(*args, **kwargs)
    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name)
```

When `raw_client is None` the Ollama construction is byte-identical to the
pre-provider code, so every test that `monkeypatch.setattr(model_router,
"OllamaClient", FakeClient)` keeps working. The ChatGPT path passes a shared
`ChatGptProxyClient` (see [ChatGPT provider](#chatgpt-provider-openai-oauth)).

`_normalize_chat_args` (`model_router.py:224-241`) coerces both
`client.chat(model, messages=...)` and `client.chat(messages=...)` call styles
into the kwargs the underlying client expects, and forces the configured model
id so consumers can pass an alias. The `chat` closure also records telemetry
via `record_model_usage` (source field, alias, model id, wall duration, error,
**provider**). The ChatGPT adapter drops Ollama-only kwargs (`options`,
`keep_alive`, `format`, `suffix`, `think`, `raw`) before the HTTP call.

`build_router()` (`model_router.py`) dispatches on `provider`:
- `ollama` (default): iterates `models.registry` and registers one
  `ModelClient` per alias, all pointing at the same `host` — unchanged.
- `chatgpt`: ensures the loopback proxy is running, discovers models from
  `/v1/models` (falling back to `chatgpt.default_model`), builds one shared
  `ChatGptProxyClient`, and registers one `ModelClient` per GPT model id
  (alias = model id) with `provider="chatgpt"`.

A second entry point, `build_model_client_for_provider(config, alias, ...)`,
is the root-cause shared helper for the call sites that previously built a
bare `_build_model_client(alias, host=...)` fallback (`run_service/service.py`,
`research_assistant.py`, `session_titler.py`, `eval_harness.py`,
`eval_benchmark.py`): it reads `models.provider` + the `ollama`/`chatgpt`
blocks and constructs the right client for one alias.

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
| Exploit agent entry | `scripts/runner_impl.py (per-round LLM call)` | the main `await _call_ollama_with_retry(client, model, ...)` |
| Router-wrapped chat | `tools/model_router.py:330` | the actual `raw_client.chat(**raw_kwargs)` inside the closure |
| Payload crafter | `tools/payload_crafter.py:709, 815` | script generation + LLM mutation |
| Semantic memory summarization | `tools/semantic_memory.py:358` | uses the routed model client (not the raw HTTP path) |
| Safety reviewer | `tools/safety_reviewer.py:97` | |
| Swarm: vuln agent | `tools/swarm/agents/vuln_agent.py:381` | `context.get("model_client")` |
| Swarm: critic agent | `tools/swarm/agents/critic_agent.py:254` | |
| Swarm: reflection agent | `tools/swarm/agents/reflection_agent.py:386` | |
| Peer-model consultation | `tools/mcp_tools/peer_models.py:125`, `tools/exploit_agent/reflection.py:376` | advisory only, no tool schemas |
| Attack planning | `tools/mcp_tools/attack_modules.py:975, 1081` | create/replan attack plan |

### Tool-schema conversion — already OpenAI-shaped

`mcp_tools_to_ollama()` (`tools/mcp_session.py:911-935`) converts MCP tool
schemas into `{"type":"function","function":{name,description,parameters}}` —
which is **byte-identical to the OpenAI tool schema** openai-oauth's
`/v1/chat/completions` accepts. No converter is needed for the ChatGPT
provider: the same tool list is forwarded unchanged. Tool-call *responses* come
back with `function.arguments` as a JSON **string**; `_normalize_tool_call`
(`tools/exploit_agent/tool_calls.py:29-38`) already JSON-parses it (malformed →
`{}`), so the exploit loop's parsing is provider-agnostic.

## ChatGPT provider (openai-oauth)

The opt-in `chatgpt` provider routes chat/generate through the operator's
ChatGPT account via a vendored copy of [`openai-oauth`](https://github.com/EvanZhouDev/openai-oauth)
(cloned at `oauth/` in the repo root). openai-oauth runs a **loopback
OpenAI-compatible HTTP proxy** (`127.0.0.1:10531/v1`) backed by browser OAuth
that reuses the Codex CLI credential file at `~/.codex/auth.json` (or
`$CODEX_HOME/auth.json`). The adapter lives in `tools/providers/chatgpt_provider.py`.

### Config

```yaml
models:
  provider: chatgpt          # ollama (default) | chatgpt
chatgpt:
  enabled: false
  base_url: http://127.0.0.1:10531/v1
  host: 127.0.0.1            # loopback-only unless you explicitly change it
  port: 10531
  auto_start: true
  local_repo: ./oauth
  runtime: auto              # auto = prefer bun (run from source), fall back to node+dist/cli.js
  request_timeout_seconds: 300
  default_model: gpt-5.2
  models: []                 # [] = discover from /v1/models
  context_window: 128000     # conservative; /v1/models returns no context metadata
  login_timeout_seconds: 300
  start_timeout_seconds: 30
  discover_cache_seconds: 300
  oauth_file: ""             # "" = auto-resolve ~/.codex/auth.json | $CODEX_HOME/auth.json
```

Absent `models.provider` = `ollama` (today's behavior). The `chatgpt` block is
warn-only validated (`config_manager.py`); a missing block is harmless.

### Authentication — browser OAuth, tokens never enter Python/config

`ChatGptProxyManager.is_authenticated()` checks **only the existence** of
`~/.codex/auth.json` / `$CODEX_HOME/auth.json` — it never opens, reads, or
prints the file. Login is "Sign in with ChatGPT": the manager shells out to
openai-oauth's own `login` CLI (run from source via `bun ./packages/openai-oauth/src/cli.ts`),
which prints an `OpenAI OAuth login URL:` and runs an OAuth callback server on
`localhost:1455`. The browser handles the consent; the resulting tokens are
written by openai-oauth directly to `~/.codex/auth.json`. **No OAuth access
token, refresh token, cookie, or `Authorization` header is ever copied into
`config.yaml`, stored in Python memory as a configured secret, or written to
logs.** The CLI menu launches the browser (`--open`); the WebUI backend uses
`--no-open` to capture the URL and surface a clickable link (backend-driven —
the browser SPA never handles raw tokens).

### Proxy lifecycle — check, reuse, else start; never kill what we didn't start

`ChatGptProxyManager.ensure_running()` (a singleton via `get()`, thread-locked):

1. If `not is_authenticated()` → return `{ok:False, reason:"not_authenticated"}`.
   **It never spawns when unauthenticated** (the CLI throws without a TTY).
2. `GET {base_url}/health` (2s). If ok → `_we_started=False`, reuse the
   pre-existing proxy. We will **not** stop a proxy we did not start.
3. If down and `auto_start`: run openai-oauth's own `serve --host --port
   --detach` (the `--detach` path spawns the detached worker and the CLI
   parent exits cleanly), then poll `/health` until `start_timeout_seconds`.
   On success `_we_started=True`. Idempotent (lock + cached `_base_url`).

`shutdown()` runs openai-oauth's `stop` CLI **only when `_we_started`** — it
POSTs to the worker's auth-token-gated control server and cleanly tears down
(no `taskkill`, no `psutil`, no Popen-tree kill). If we reused a pre-existing
proxy, `shutdown()` is a no-op. `atexit` registers a best-effort shutdown.
All subprocess calls use list args (no `shell=True`), `cwd=local_repo` (handles
paths with spaces), and `CREATE_NO_WINDOW` on Windows.

> **Why not Popen+kill `serve` directly?** `serve` forks a detached grandchild
> worker that a controller-`Popen` kill can't reach on Windows. Using
> openai-oauth's own `--detach`/`stop` CLI machinery is the only reliable
> cross-platform lifecycle.

### Model discovery

`discover_models(base_url)` does `GET /v1/models`, cached for
`discover_cache_seconds`. On failure it returns `[]` and `build_router` falls
back to `chatgpt.models` (if non-empty) then `chatgpt.default_model`. Each
discovered model id becomes a `ModelClient` (alias = model id). `/v1/models`
returns no context metadata, so `chatgpt.context_window` (default 128000) is
the conservative source of truth for the context compactor. The Ollama
`models.registry` is untouched and still used when `provider: ollama`.

### Runtime resolution

`runtime: auto` prefers `bun` on PATH (run from source: `bun ./packages/openai-oauth/src/cli.ts`);
else `node` if on PATH **and** `dist/cli.js` exists (a prior `bun run build`);
else a helpful `RuntimeError` pointing at `bun install` in `oauth/`.
`bun install` is the one-time setup step (best-effort in the setup scripts).
No global Codex CLI install is required.

### What stays Ollama

- **Embeddings** — `tools/semantic_memory.py` still POSTs to the Ollama
  `/api/embeddings` endpoint. Under `provider: chatgpt` the operator still
  needs a local Ollama for `nomic-embed-text` (or it degrades to a no-op
  gracefully, as today). ChatGPT handles chat/generate only.
- **`session_titler`** — uses `chatgpt.default_model` under the ChatGPT
  provider (GPT models expose no dedicated cheap title model in `/v1/models`).

### Security (preserved)

This is a provider integration, not an auth-scope change. No edits to
`scope_gate.py`, `safety_reviewer.py`, Flow B safety files,
`tools/mcp_shared._allowed_target_list`, `tools/mcp_tools/terminal._target_lock_block`,
or `tools/exploit_agent/policy.py`. The target-IP allowlist lock, permission
model, MCP target locks, and recon restrictions are untouched. The proxy is
loopback-only (`127.0.0.1`) unless the operator explicitly changes
`chatgpt.host`. See the doctor section below for the ChatGPT health checks.

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
- `scripts/runner_impl.py (embed host resolution)` (Flow A) — same pattern
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
| `embed_host` | `http://localhost:11434` | `config_manager.py:998-1006`, `scripts/runner_impl.py (embed host resolution)` |

**`models:` (`config.yaml:15-44`)** — model registry

| Key | Default | Consumed at |
|---|---|---|
| `provider` | `ollama` | `config_manager.py:get_ai_provider`, `model_router.build_router`, `run_service/service.py`, `doctor.py` |
| `registry` | kimi/deepseek/deepseek_flash/glm/minimax | `config_manager.py:1011`, `model_router.py:70-76` |
| `default_alias` | `glm` | `config_manager.py:1008` |
| `info.<alias>.context_window` | per-model | `model_router.py:202-221`, `exploit_agent/context.py:63-104` |
| `info.<alias>.label/description` | per-model | `model_router.py:130`, `api/routes/system.py:193-194` |

**`chatgpt:` (top-level, opt-in)** — ChatGPT provider (see
[ChatGPT provider](#chatgpt-provider-openai-oauth) above). Consumed at
`config_manager.py:get_chatgpt_config`, `tools/providers/chatgpt_provider.py`,
`model_router._build_chatgpt_router`, `doctor._check_chatgpt`,
`api/routes/system.py` (`/providers`, `/providers/chatgpt/*`). Full key table
in [config-reference.md §`chatgpt:`](config-reference.md).

**Env vars** — `OLLAMA_API_KEY` is the one load-bearing secret; everything else
is target-lock plumbing. Full env table in
[config-reference.md §Environment variables](config-reference.md#environment-variables).

## Recipe: add a new chat/generate provider

The minimal change. Consumers stay untouched — they already receive a
`ModelClient` and call `.chat()`.

### 1. Config

The implemented shape is a `provider` selector in the `models:` block plus a
sibling block for the new provider (mirroring how `chatgpt:` is wired):

```yaml
models:
  provider: ollama          # "ollama" (default) | "chatgpt" | <your new provider>
  registry: { ... }         # Ollama aliases — unchanged
  default_alias: glm
<yourprovider>:             # new top-level block
  enabled: false
  host: 127.0.0.1
  # ...provider-specific keys...
```

Add `"provider": "ollama"` to `CONFIG_SCHEMA["models"]` and the new top-level
block to `CONFIG_SCHEMA` in `tools/config_manager.py` (so `KNOWN_TOP_KEYS`
auto-includes it — no unknown-key warning). Add a warn-only validation branch
in `ConfigValidator.validate()` (mirror the `models.provider` ∈ {ollama,chatgpt}
check). Add accessors `get_ai_provider(config)` and `get_<provider>_config(config)`,
mirroring `get_ollama_host()` / `get_chatgpt_config()`
(`config_manager.py`).

### 2. Factory — inject a `raw_client` into `_build_model_client`

The implemented seam is an injectable `raw_client` (anything with a
`.chat(**kwargs)` returning an Ollama-shaped response), so the whole chat
closure (telemetry, `_normalize_chat_args`, `_stream_with_telemetry`) is reused
unchanged. Add a `provider` param to thread into `record_model_usage`:

```python
def _build_model_client(model_name, host=OLLAMA_CLOUD_HOST, *, alias="",
                        request_timeout_seconds=None, raw_client=None,
                        provider="ollama"):
    if raw_client is None:                       # Ollama path (default, byte-identical)
        raw_client = OllamaClient(host=host, timeout=request_timeout_seconds)
    # else: your provider path — pass a client whose .chat(**raw_kwargs)
    #       returns an Ollama-shaped dict/iterable (normalize inside it).

    def chat(*args, **kwargs):
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        response = raw_client.chat(**raw_kwargs)   # ← your client
        record_model_usage(..., provider=provider)
        return response
    ...
    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name)
```

Thread `provider` + your provider's config through `build_router()` (which
dispatches on `provider`), and add a branch in the shared
`build_model_client_for_provider(config, alias, ...)` helper so the fallback
call sites pick up the new provider automatically. The ChatGPT adapter
(`tools/providers/chatgpt_provider.py:ChatGptProxyClient`) is the reference:
it normalizes OpenAI responses back to the Ollama shape inside `.chat()`.

### 3. Tool-schema conversion — usually none needed

`mcp_tools_to_ollama()` (`tools/mcp_session.py:911-935`) already emits
`{"type":"function","function":{name,description,parameters}}` — the OpenAI
tool schema. Most OpenAI-compatible providers (including the ChatGPT proxy)
accept this verbatim, so no converter is needed: forward the same tool list.
If your provider uses a different schema, normalize it inside the
`ModelClient.chat` closure (or your `raw_client.chat`) so consumers keep
passing the Ollama-shape and the closure adapts — that keeps every consumer
untouched.

The response shape (tool calls, content blocks) differs between providers —
your `raw_client.chat` is the natural place to normalize the response back
into the shape `tools/exploit_agent/ollama_client.py` expects, so the exploit
loop's parsing (`_call_ollama_with_tools`, `ollama_client.py:125+`) and
`_normalize_tool_call` (JSON-string `arguments` → dict) don't need changes.
The ChatGPT adapter does exactly this.

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
- Telemetry — `record_model_usage` takes a `provider` field
  (`model_telemetry.py`, added to `PUBLIC_USAGE_FIELDS`) so usage is
  provider-attributed; `read_usage_records` still filters by alias, so adding
  the field is invisible to existing readers.

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
(`agent_loop.py:176-182`, `scripts/runner_impl.py (embed host resolution)`,
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

- **`session_titler.py` constructs its own client — now provider-aware.**
  `tools/api/session_titler.py` builds a standalone client (not via the
  router). Under `provider: ollama` it still uses a module-level `OllamaClient`
  (so `test_session_titler`'s `monkeypatch` stays green); under
  `provider: chatgpt` it builds a `ModelClient` for `chatgpt.default_model`
  via `build_model_client_for_provider` and drops Ollama-only `options`. A new
  chat provider needs a parallel branch here, or route the titler through
  `ModelRouter` so it inherits the provider automatically.
- **`doctor.py` does raw HTTP — Ollama path only.** `tools/doctor.py` POSTs
  directly to `/api/tags` and `/api/generate` via `urllib` with a
  manually-attached `Authorization: Bearer` header to verify cloud model
  reachability. This is Ollama-API-specific. Under `provider: chatgpt` the
  doctor instead runs `_check_chatgpt` (source/runtime/oauth/proxy/`/v1/models`
  sub-checks — **never reading token contents**) and the Ollama probes are
  skipped. A new chat provider needs its own `_check_<provider>` branch.
- **`tools/api/routes/system.py` live-models route** is now provider-aware:
  `provider: chatgpt` probes the proxy's `/v1/models`; `provider: ollama`
  stays on the raw-HTTP `/api/tags` path (unchanged, so `test_api_frontend`
  stays green). New `/providers` + `/providers/chatgpt/*` routes surface
  auth/proxy status and backend-driven login.
- **Manual auth is only for raw-HTTP paths.** The ollama Python client
  auto-attaches `Authorization: Bearer $OLLAMA_API_KEY` for the chat path, so
  app code only attaches it manually in `semantic_memory.py:75-77`,
  `doctor.py`, and `api/routes/system.py:305`. A new chat provider using its
  own SDK handles auth at construction (see the recipe).
- **`mcp_tools_to_ollama()` is already OpenAI-shaped.** The tool-schema
  converter at `tools/mcp_session.py:911-935` emits
  `{"type":"function","function":{...}}` — byte-identical to the OpenAI tool
  schema, so the ChatGPT provider forwards it unchanged. A provider with a
  different schema needs its own converter or an in-`ModelClient`/`raw_client`
  normalization (see the chat recipe).
- **Two flows share `db.py`/`mission.py` schemas only.** Flow A
  (`main.py`/`app.py` → `tools/exploit_agent/`) and Flow B (`cli.py` +
  root-level `agent_loop.py`/`db.py`/`mission.py`) both construct
  `SemanticMemoryManager` with the `embed_host`→`host` fallback
  (`agent_loop.py:176-182` vs `scripts/runner_impl.py (embed host resolution)`). An embeddings
  provider change must update both construction sites.
- **No CI.** Before a PR adding a provider: run `python -m pytest tests/ -v`
  and `ruff check .`, and verify the README/provider config still matches
  reality (see [AGENTS.md](../AGENTS.md) rule 8).