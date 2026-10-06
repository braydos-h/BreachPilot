# Credential Vault

At-rest encryption for harvested credentials in `tools/credential_store.py`. The `password` and free-text `notes` fields of every `CredentialRecord` are Fernet-encrypted before they touch disk and decrypted on load. Raw vault files are blocked by workspace read tools because legacy records may still contain plaintext.

## Key resolution

Resolution order is fixed in `_Vault.__init__` (`tools/credential_store.py`):

| Priority | Source | Notes |
|---|---|---|
| 1 | `BREACHPILOT_VAULT_KEY` environment variable | Operator-carried urlsafe-base64 32-byte Fernet key. When set, no keyfile is read or created. `AI_NMAP_VAULT_KEY` honored as deprecated alias until 0.71 (canonical wins when both set, with warning). |
| 2 | Per-store keyfile from `_vault_key_path(store_dir)` | Auto-generated on first use via `Fernet.generate_key()`. One key per store directory. |

```python
key = _resolve_vault_key_env() or self._load_or_create_key()
# _resolve_vault_key_env(): BREACHPILOT_VAULT_KEY first, AI_NMAP_VAULT_KEY alias with DeprecationWarning
```

The per-store keyfile name is derived from the store path so each workspace gets its own key:

```python
digest = hashlib.sha256(str(Path(store_dir).resolve()).encode("utf-8")).hexdigest()[:32]
return keys_dir / f"{digest}.key"
```

`_vault_keys_dir()` returns `$BREACHPILOT_VAULT_DIR` when that variable is set, otherwise `~/.breachpilot/vault_keys`. When the home directory cannot be resolved, or the configured key directory resolves inside the shared workspace, key setup fails closed; the implementation never falls back to creating a live key in the workspace.

Keeping the live key outside the workspace tree is the point: the agent reads workspace files freely via `read_workspace_file` / `list_workspace`, so a key stored inside the workspace would degrade encrypted-at-rest secrets to plaintext.

## Keyfile permissions and location

- Live location: `$BREACHPILOT_VAULT_DIR/<sha256-of-store-dir>.key`, default `~/.breachpilot/vault_keys/<sha256-of-store-dir>.key`.
- The key directory is set to mode `0700`; the key file is created exclusively with mode `0600`, then opened by descriptor with no-follow checks before reading or writing. Key bytes are written only after private mode is applied.
- Per-store (not global): the `sha256` digest covers the resolved store path, so the HMAC tamper-evidence keeps its per-workspace property — a file copied from another store does not verify under this store's key.
- The 0600 mode protects against other non-root users on a shared host. It does not protect against the operator or root, who own the box (see Threat boundary below).

## Legacy `.vault_key` adoption

A legacy in-workspace `.vault_key` (`<store_dir>/.vault_key`) is adopted once, in `_load_or_create_key`:

1. Read the legacy keyfile.
2. Write the same key bytes to the out-of-tree keyfile (`0600`).
3. `unlink` the legacy file (moved, not copied), so no key material is left behind in AI-readable space.
4. Return the adopted key, so existing stores keep decrypting.

```text
<store_dir>/.vault_key  --move-->  ~/.breachpilot/vault_keys/<digest>.key
```

If the out-of-tree keyfile already exists, it wins and the legacy file is left alone by this path (no adoption needed).

## Plaintext fallback (fail-closed by default)

Writes fail closed by default. If the `cryptography` package is not importable, or no usable key can be established (empty keyfile, invalid key material, keyfile I/O error), `_Vault.enabled` stays `False` and `save()`/`add()` raise `RuntimeError` naming the cause instead of persisting secrets in cleartext. The store can still load legacy plaintext rows for migration, but workspace file tools do not expose raw vault contents.

Plaintext writes are only possible with explicit opt-in:

```bash
export BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1
```

With the opt-in set, the legacy loud-but-allowed fallback applies:

```python
_LOG = logging.getLogger("ai_bug_bounty.creds")
_Vault._warn_plaintext_fallback("cryptography package not installed -- ...")
```

- One-time `WARNING` via `_warn_plaintext_fallback` (guarded by `_plaintext_warned`), emitted on the `ai_bug_bounty.creds` logger so the app's configured handlers capture it.
- `encrypt` returns the input unchanged when disabled; writes remain refused unless explicit plaintext opt-in is set. `decrypt` returns its input unchanged when disabled or when the token is not valid ciphertext under the current key.
- Legacy plaintext files still load: a value that does not decrypt is treated as plaintext, so existing stores are never bricked. A wrong-key read surfaces *something* (possibly garbage) instead of losing the record — crypto errors never drop a record.

In plaintext-fallback mode no HMAC signature is possible, so on-disk `confirmed=True` is never trusted (see next section) — it is downgraded to `confirmed=False` with a `WARNING` on load.

## Record integrity: `confirm_credential` plus HMAC downgrade

A harvested credential is stored with `confirmed=False` and stays that way. The MCP agent cannot confirm a record: `cred_store_confirm` is a compatibility shim that always blocks. An authenticated operator can use the run credentials UI/API after reviewing successful reuse evidence. The store method is an internal control-plane operation; its `validated` argument is not proof by itself:

```python
store.confirm_credential(username="admin", target_host="10.0.0.50", validated=True)
```

| Method | Behavior |
|---|---|
| `CredentialStore.add(record)` | Forces `record.confirmed` to `False` (with a `WARNING` when the caller passed `True`). Dedupes on `(username, target_host, credential_type)`, then appends one signed JSONL line. `save()` does not force `False`, so legitimately confirmed records persist as `True`. |
| `CredentialStore.confirm_credential(*, username, target_host, credential_type=None, validated=False)` | Internal method called by the authenticated operator control plane. Refuses when `validated` is falsy; otherwise flips matching records, calls `save()`, and returns `True` only when a record was newly confirmed. MCP tools cannot invoke this with caller-supplied evidence. |
| `CredentialStore.credentials_for_host(host)` / `all_credentials()` / `hosts_with_credentials()` / `summary()` | Read-only views; `summary()` renders `target: user/type (confirmed=...)` lines. |
| `CredentialStore.encryption_enabled` / `store_path` | Introspection used by the MCP `cred_store` tools: vault `enabled` flag and the `credentials.jsonl` path. |

Every record carries an HMAC-SHA256 over its canonical fields, keyed by the vault key (`_Vault.signing_key`, the same Fernet key material):

- `_attach_sig` signs the on-disk payload (with ciphertext password and notes) before `sig` is attached, using canonical JSON (`sort_keys=True`, compact separators).
- `_verify_sig` uses `hmac.compare_digest`. With no signing key (plaintext fallback) or no `sig` present, no signature is valid.
- `_load` pops `sig` and verifies *before* decrypting password or notes — verifying after decryption would digest plaintext and never match.
- Any record whose `confirmed=True` does not verify (hand-edited file, file copied from another workspace, or anything written while encryption was disabled) is downgraded to `confirmed=False` with a `WARNING` naming `username@target_host`. Legacy unconfirmed records load unchanged.

So `confirmed=True` in memory always means this workspace's key signed the record after an authenticated operator action — never a value merely asserted by the agent or on disk.

## `DENY_BASENAME` and workspace reads

`_Vault.DENY_BASENAME = ".vault_key"`. A hand-placed or legacy keyfile and raw credential-store files must never be served to the model. Enforcement lives in `tools/kernel/workspace.py`:

- `is_vault_key_path(filename)` matches the basename (after normalizing separators and quotes), so no path spelling reaches the key.
- `read_workspace` refuses with `BLOCKED: '.vault_key' is a credential-store keyfile and is never served.` before any filesystem access.
- `read_workspace` and `read_workspace_bytes` refuse paths under `credentials/` and `credentials.jsonl`; descriptor reads also reject hard-linked files so a benign alias cannot expose a vault file.

The same basename set (`_VAULT_KEY_BASENAMES = frozenset({".vault_key"})`) backs listing-time hiding covered by `tests/test_credential_store.py` (`test_read_workspace_file_denies_vault_keyfile` and the `".vault_key" not in listed` assertions).

Implementation note: the exact `list_workspace` hide path was verified via tests and `tools/kernel/workspace.py` comments, not by reading the list implementation in this pass.

## Threat boundary

`add` forces `confirmed=False` and the HMAC backstop defeats anyone who does not hold the vault key: a hand-edited file, a foreign workspace, or a plaintext-fallback write cannot produce a signature the load-time verifier accepts, so a forged `confirmed=True` is downgraded.

This does not defend against trusted host-side code that already has access to the vault key. The key is outside the shared workspace and is not served by workspace tools; agent-provided confirmation claims are rejected. Authenticated operator confirmation remains an explicit trust decision.

Related controls:

- `LootStore` (`loot.jsonl`, `LootItem` with inline `content` capped at 5000 chars) is arbitrary loot storage and is not encrypted — credential passwords and notes go through the vault.
- `CredentialStore.save()` writes a unique `.credentials-<random>.tmp` file with exclusive, no-follow creation relative to a pinned parent-directory descriptor, fsyncs it, then atomically replaces `credentials.jsonl` through that same descriptor. A failed write cleans up the temporary file and leaves the previous store in place.

## Related documentation

- [Safety model](safety-model.md) — permission modes, target-IP lock, and the audit/evidence safety layer.
- [Database and mission persistence](database-mission.md) — the SQLite schemas the credential JSONL stores sit alongside.
- [Outcome judgment and evidence handling](outcome-evidence.md) — evidential versus execution status and the Flow A audit trail.

## Source map

- `tools/credential_store.py`
- `tools/kernel/workspace.py`
- `tools/run_service/execute.py`
- `tools/exploit_agent/runner/_impl.py`
