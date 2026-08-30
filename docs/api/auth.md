---
title: API Auth — Bearer Token, Loopback, CORS, WebSocket, Password Hashing
sources:
  - tools/api/auth.py
  - app.py
  - tools/api/routes/system.py
tests:
  - tests/test_api_auth.py
subsystem: api
status: maintained
---

# Auth

`tools/api/auth.py:1` — bearer token, loopback enforcement, WebSocket origin+auth, and PBKDF2 password hashing. v1 loopback-only (`tools/api/__init__.py:8`).

## Loopback Bind

`assert_api_loopback(host)` (`tools/api/auth.py:38`) rejects any host not in `{"127.0.0.1","localhost","::1"}` with `ValueError`. Enforced in `main._run_daemon` and re-validated defensively in `app.create_app` (`app.py:70`). No public-bind override in v1.

## Bearer Token

### Source

`load_or_create_token(token_file, env_override)` (`tools/api/auth.py:46`):

1. `BREACHPILOT_API_TOKEN` env (trimmed). If non-empty, returned and file is untouched.
2. `api.token_file` (default `.webui_secret_key`, gitignored) — read if exists and trimmed non-empty.
3. Otherwise `secrets.token_urlsafe(32)` (256-bit), `parent.mkdir(exist_ok=True)`, `write_text`, `chmod 0o600` best-effort (Windows: no-op).

Never logged; no endpoint returns it. `app.py:73` calls `load_or_create_token(api_cfg.get("token_file", ".webui_secret_key"), env_override=os.environ.get("BREACHPILOT_API_TOKEN",""))`.

### Enforcement

`BearerAuth` (`tools/api/auth.py:72`) — `HTTPBearer(auto_error=False)` + `hmac.compare_digest`.

```python
creds = await HTTPBearer(auto_error=False)(request)
if creds is None or creds.scheme.lower() != "bearer":  raise 401 Missing/Invalid Authorization
if not hmac.compare_digest(creds.credentials, self._token): raise 401 Invalid bearer token
```

Wired as a FastAPI dependency `_require_auth` in every route module except `system.health`:

- `tools/api/routes/system.py:49`
- `tools/api/routes/runs.py:37`
- `tools/api/routes/decisions.py:25`
- `tools/api/routes/events.py:50`
- `tools/api/routes/graph.py:43`
- `tools/api/routes/graph_explorer.py:55`
- `tools/api/routes/users.py:44`

`GET /api/v1/health` (`tools/api/routes/system.py:56`) has no dependency and always returns `200 {version:"v1", ready:true}`.

## CORS & Allowed Origins

`is_loopback_origin(origin, allowed_origins)` (`tools/api/auth.py:96`):

- Rejects `""` / `"null"`.
- Parses with `urlsplit`; rejects if scheme not `http|https`, host missing, `username`/`password` present, `query`/`fragment` present, path not `""`/`"/"`, port out of `1..65535`.
- Checks `host.lower()=="localhost"` or `ipaddress.ip_address(host).is_loopback`; non-loopback → `False`.
- If loopback, allow when `allowed_origins` empty, or `origin in allowed_origins`, or `host` in `_LOOPBACK_HOSTS`.

Factory validates `api.allowed_origins` is a `list[str]` of loopback origins or raises `ValueError` (`app.py:114`). `CORSMiddleware` allowlist is `allowed_origins + ["http://127.0.0.1","http://localhost","http://[::1]"]` with `allow_credentials=True` (`app.py:120`).

`PATCH /api/v1/config` re-validates the merged `api.allowed_origins` with the same predicate before writing (`tools/api/routes/system.py:152`).

## WebSocket Auth

`authenticate_websocket(ws, token, allowed_origins)` (`tools/api/auth.py:128`):

1. Origin check **before** accept: `origin = ws.headers.get("origin","")`; if `not is_loopback_origin(origin, allowed_origins)` → `close(4403, "Origin not allowed")`, return `None`.
2. `await ws.accept()`.
3. `first = await asyncio.wait_for(ws.receive_json(), timeout=5.0)`; `WebSocketDisconnect` → `None`; any other exception → `close(4401, "Auth message required")`.
4. `first` must be `dict` and `hmac.compare_digest(str(first.get("auth","")), token)` else `close(4401, "Invalid auth token")`.
5. `after = first.get("after", 0)` must be `int` (not `bool`) and `>=0` else `close(4400, "Invalid event cursor")`.
6. Returns the (mutated with normalized `after`) message.

Close codes (also documented in `docs/api.md`):

| Code | Meaning | Raised in |
|------|---------|-----------|
| 4403 | Origin not allowed | `tools/api/auth.py:140` |
| 4401 | Invalid/missing auth message (5 s timeout) | `tools/api/auth.py:143`, `:151` |
| 4400 | Invalid `after` cursor | `tools/api/auth.py:155` |
| 4404 | Run not found (after auth succeeds, route layer) | `tools/api/routes/events.py:159` |
| 1011 | Server not configured / stream failed | `tools/api/routes/events.py:153`, `:174` |

Non-bearer SSE `GET /api/v1/runs/{id}/events/stream` uses the normal HTTP bearer header (never query-string) — see `docs/api/websocket.md` and `tools/api/routes/events.py:99`.

## Password Hashing (multi-operator, D4)

When `api.multi_operator` is true, `tools/api/routes/users.py` is mounted and uses stdlib `hashlib.pbkdf2_hmac("sha256", password, salt, 200_000)` with 16-byte `secrets.token_bytes` salt (`tools/api/auth.py:34`).

| Symbol | Location | Signature |
|--------|----------|-----------|
| `hash_password(password, salt=None)` | `tools/api/auth.py:164` | `-> (hash_hex, salt_hex)`; `salt=None` generates fresh `16`-byte salt |
| `verify_password(password, hash, salt)` | `tools/api/auth.py:181` | `-> bool`, constant-time `hmac.compare_digest` |

Used only in `tools/api/routes/users.py:105`, `:123`. No roles/permissions system (AGENTS.md §E); loopback bind remains the trust boundary.

## Tests

`tests/test_api_auth.py` covers:

- `assert_api_loopback` for allowed (`127.0.0.1`, `localhost`, `::1`) vs rejected (`0.0.0.0`, `10.x`, domain) hosts
- `load_or_create_token` env override / file read / generation
- `is_loopback_origin` loopback vs `null`/non-loopback/explicit-allowlist
- HTTP protection: `health` no-auth, protected route requires/validates bearer, wrong token 401, `config` redaction, `PUT /secrets` name validation
