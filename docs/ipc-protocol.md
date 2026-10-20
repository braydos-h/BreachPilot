# Go ↔ Rust IPC protocol (authoritative)

Wire contract for the BreachPilot execution plane. `proto/exec.proto` is the
IDL source of truth; this document is the normative behavior spec.

## Transport

- **JSON v1 over loopback TCP** (default `127.0.0.1:18765`, override
  `BP_SIDECAR_ADDR`). The Rust `bp-sidecar` binary serves it; the Go
  `internal/ipc` client dials it.
- One JSON object per line (`\n` delimited), both directions.
- Unix-domain sockets on Linux production deployments are a drop-in
  transport change (same envelope); TCP loopback is the portable default.
- gRPC is an approved future upgrade path: the proto service
  `ExecSidecar` already defines it. Migration requires no envelope change
  (field names are identical).

## Envelope

Request: `{"version":"v1","id":"<unique>","op":"health|exec","payload":{...}}`
Response: `{"version":"v1","id":"<same>","ok":bool,"result":{...},"error":{"code","message"}}`

## Rules

1. **Version negotiation**: `version` must be `"v1"`. Anything else fails
   with `SANDBOX_INVALID`. Bumping the version requires a matching change
   in `proto/exec.proto`, `internal/ipc`, and `bp-sidecar` together.
2. **Error codes** (closed set): `SANDBOX_SCOPE_DENIED` (allowlist gate),
   `SANDBOX_TIMEOUT` (killed after deadline), `SANDBOX_SPAWN_FAILED`
   (binary missing / spawn error), `SANDBOX_INVALID` (bad envelope/op/args).
   Failures are fail-closed: no host fallback, ever.
3. **Timeouts**: client deadline (default 30s, per-call override) AND server
   execution timeout (`timeout_seconds`, clamped 1..3600) both apply; the
   server kills the whole process group on expiry.
4. **Cancellation**: closing the TCP connection abandons the call; the
   server-side process group is reaped on timeout. No orphan processes.
5. **Request IDs**: client-generated, echoed back, used for log correlation.
6. **Event ordering**: the broker (Go side) owns sequence numbers, not IPC.
   IPC calls are independent; ordering guarantees live in `internal/events`.
7. **Health**: `{"op":"health"}` must answer `{"ok":true}` within the client
   timeout or the sidecar is treated as down (sandbox-gated paths fail
   closed, API reports `sidecar_reachable:false`).

## Tests

- Rust: `bp-exec` unit tests (gate, timeout kill, spawn fail).
- Go: `internal/ipc` live contract tests (`TestLive*`) run against a real
  sidecar in CI (`ci-native.yml` ipc-contract job): health, scope-denied,
  spawn-failed, version-mismatch, unknown-op.
- Allowlist vectors are pinned identically in `internal/allowlist` and
  `bp-allowlist` tests; any matcher change must update both.
