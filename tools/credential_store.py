"""Credential store for persistent loot and credential management across exploitation sessions.

Provides:
- CredentialRecord: structured credential entry
- CredentialStore: JSONL-backed persistent credential store with **at-rest Fernet
  encryption** of secret-bearing ``password`` and ``notes`` fields
- LootItem / LootStore: arbitrary loot storage

At-rest encryption (Tier 0 item 0.3, Phase B)
----------------------------------------------
Harvested credentials used to live in ``credentials.jsonl`` as plaintext on the
operator's host. ``CredentialStore`` encrypts the ``password`` and free-text
``notes`` fields of every record before it touches disk and decrypts them on
load, so the in-memory records stay plaintext while the file on disk holds
ciphertext. Legacy plaintext records still load for migration, but raw vault
files are not exposed through workspace read tools. The key is resolved, in
priority order, from:

  1. the ``BREACHPILOT_VAULT_KEY`` environment variable (a urlsafe-base64 32-byte
     Fernet key the operator carries out-of-band; ``AI_NMAP_VAULT_KEY`` honored
     as a deprecated alias until 0.71), else
  2. a 0600 keyfile OUTSIDE the workspace tree at
     ``$BREACHPILOT_VAULT_DIR/<sha256-of-store-dir>.key`` (default
     ``~/.breachpilot/vault_keys/``), auto-generated on first use
     (per-store key -- protects against other non-root users on a shared
     host; does not protect against the operator/root who own the box).
     Keeping the key outside the workspace tree (which the AI reads freely
     via ``read_workspace_file``/``list_workspace``) is what keeps
     encrypted-at-rest secrets from degrading to plaintext. A legacy
     in-workspace ``.vault_key`` is adopted once (moved, not copied) so
     existing stores keep decrypting.

If the ``cryptography`` package is not importable (or no vault key can be
established), the store **refuses to write** rather than persisting secrets in
plaintext: ``save()``/``add()`` raise ``RuntimeError`` naming the cause.
Explicit opt-in to insecure storage is available via
``BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1`` (warns loudly, never silent).
Legacy plaintext files still *load*: a value that does not decrypt under
the current key is treated as plaintext, so existing stores are never bricked
-- the fail-closed gate is on writes only.

``confirmed`` gating
---------------------
A harvested credential is stored with ``confirmed=False`` and stays that way.
The MCP agent cannot mark a credential confirmed: ``cred_store_confirm`` is a
compatibility shim that always refuses. An authenticated operator may confirm
through the run UI/API after reviewing successful reuse evidence. The internal
:meth:`CredentialStore.confirm_credential` method takes ``validated=True`` as a
control-plane assertion; that boolean is not evidence and is never accepted from
the agent-facing tool. The harvester never grants confirmation.

The ``confirmed`` flag is **tamper-evident at rest**: every record carries an
HMAC-SHA256 over its canonical fields, keyed by the vault key. On load, a
record whose ``confirmed=True`` does not verify under the current key (a
hand-edited file, a file copied from another workspace, or anything written
while encryption was disabled) is downgraded to ``confirmed=False`` and logged.
So ``confirmed=True`` in memory always means *this workspace's key signed it
after an authenticated operator action* -- never a value merely asserted by the
agent or on disk.

Threat-model boundary: ``add`` forces ``confirmed=False`` and the HMAC backstop
defeats hand-edited records, foreign-workspace files, and plaintext-fallback
forgeries. The key lives outside the worker-readable workspace and workspace
read tools deny vault paths. Trusted host-side code that already has the key can
still create valid signatures; the authenticated operator UI/API is the only
agent-independent confirmation path exposed by the application.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# Use the application's configured logger tree (``ai_bug_bounty``, set up by
# tools/logging_setup.setup_logging) so the plaintext-fallback WARNING is
# captured by the app's file/console handlers instead of being silently
# dropped by a stray ``breachpilot.creds`` logger that nothing configures.
_LOG = logging.getLogger("ai_bug_bounty.creds")


@dataclass
class CredentialRecord:
    timestamp: float
    source_host: str
    target_host: str
    username: str
    password: str
    credential_type: str  # password, hash, token, key
    source_action: str
    confirmed: bool = False
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_host": self.source_host,
            "target_host": self.target_host,
            "username": self.username,
            "password": self.password,
            "credential_type": self.credential_type,
            "source_action": self.source_action,
            "confirmed": self.confirmed,
            "notes": self.notes,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> CredentialRecord:
        return cls(
            timestamp=data.get("timestamp", time.time()),
            source_host=str(data.get("source_host", "")),
            target_host=str(data.get("target_host", "")),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            credential_type=str(data.get("credential_type", "password")),
            source_action=str(data.get("source_action", "")),
            confirmed=bool(data.get("confirmed", False)),
            notes=str(data.get("notes", "")),
        )


# ── At-rest Fernet vault ─────────────────────────────────────────────────────


def _vault_keys_dir() -> Path | None:
    """Directory holding vault keyfiles (outside every workspace tree).

    ``$BREACHPILOT_VAULT_DIR`` overrides (tests); default
    ``~/.breachpilot/vault_keys``. Returns ``None`` when the home directory
    cannot be resolved; in that case secure writes fail closed rather than
    placing the key in the worker-readable workspace.
    """
    override = os.environ.get("BREACHPILOT_VAULT_DIR", "").strip()
    if override:
        return Path(override)
    try:
        return Path.home() / ".breachpilot" / "vault_keys"
    except (RuntimeError, OSError, KeyError):
        return None


def _vault_key_path(store_dir: Path) -> Path | None:
    """Keyfile for ``store_dir`` — outside the workspace tree.

    Per-store key (sha256 of the resolved store path) so the HMAC
    tamper-evidence keeps its per-workspace property: a file copied from
    another store does not verify. Returns ``None`` when no out-of-tree key
    directory is available; a key must never be written into a workspace.
    """
    keys_dir = _vault_keys_dir()
    if keys_dir is None:
        return None
    try:
        digest = hashlib.sha256(str(Path(store_dir).resolve()).encode("utf-8")).hexdigest()[:32]
    except OSError:
        digest = hashlib.sha256(str(store_dir).encode("utf-8")).hexdigest()[:32]
    return keys_dir / f"{digest}.key"


#: Canonical vault-key env var. ``AI_NMAP_VAULT_KEY`` is honored as a
#: deprecated alias for one release (TODO 011/012, remove in 0.71).
VAULT_KEY_ENV = "BREACHPILOT_VAULT_KEY"
VAULT_KEY_ENV_LEGACY = "AI_NMAP_VAULT_KEY"


def _resolve_vault_key_env() -> str | None:
    """Return the vault key from env, preferring the canonical name.

    Reads ``BREACHPILOT_VAULT_KEY`` first; falls back to ``AI_NMAP_VAULT_KEY``
    with a ``DeprecationWarning`` + log line. When both are set, canonical wins.
    """
    import warnings

    canonical = os.environ.get(VAULT_KEY_ENV, "").strip() or None
    legacy = os.environ.get(VAULT_KEY_ENV_LEGACY, "").strip() or None
    if canonical:
        if legacy:
            _LOG.warning(
                "Both %s and deprecated %s are set -- using %s.",
                VAULT_KEY_ENV,
                VAULT_KEY_ENV_LEGACY,
                VAULT_KEY_ENV,
            )
        return canonical
    if legacy:
        warnings.warn(
            f"{VAULT_KEY_ENV_LEGACY} is deprecated; use {VAULT_KEY_ENV} (removal in 0.71).",
            DeprecationWarning,
            stacklevel=3,
        )
        _LOG.warning(
            "Using deprecated %s; migrate to %s (removal in 0.71).",
            VAULT_KEY_ENV_LEGACY,
            VAULT_KEY_ENV,
        )
        return legacy
    return None


#: Explicit opt-in for insecure plaintext vault storage. Default is fail-closed:
#: when secure storage is unavailable, writes are refused instead of persisted
#: in cleartext.
PLAINTEXT_VAULT_ENV = "BREACHPILOT_ALLOW_PLAINTEXT_VAULT"


def _plaintext_vault_allowed() -> bool:
    """True only when the operator explicitly opts into plaintext vault storage."""
    return os.environ.get(PLAINTEXT_VAULT_ENV) == "1"


class _Vault:
    """Fernet-based at-rest encryption for the credential store's secret field.

    See the module docstring for the key resolution order and threat model.
    ``enabled`` is False when ``cryptography`` is missing or a usable key cannot
    be established. By default that state is fail-closed: ``save()``/``add()``
    raise ``RuntimeError`` (via :meth:`assert_writable`) instead of persisting
    secrets in cleartext. Setting ``BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1`` opts
    back into the legacy loud plaintext fallback (one-time WARNING, never
    silent). Reads stay fail-open either way so legacy stores never brick.
    """

    _plaintext_warned = False

    #: Basename deny-listed in ``read_workspace_file``/``list_workspace``
    #: (defense in depth: the live key no longer lives under the workspace,
    #: but a hand-placed or legacy keyfile must never be served to the model).
    DENY_BASENAME = ".vault_key"

    def __init__(
        self,
        workspace: Path,
        *,
        workspace_root: Path | None = None,
        legacy_key_reader: Callable[[], str | None] | None = None,
        legacy_key_remover: Callable[[], None] | None = None,
    ) -> None:
        self.enabled = False
        self._fernet = None
        self._key_material: bytes | None = None
        self._refusal: str | None = None
        self._store_dir = Path(workspace)
        self._workspace_root = Path(workspace_root or workspace).absolute()
        self._legacy_keyfile = self._store_dir / ".vault_key"
        self._legacy_key_reader = legacy_key_reader or self._read_legacy_keyfile
        self._legacy_key_remover = legacy_key_remover or self._remove_legacy_keyfile
        self._keyfile: Path | None = None
        try:
            from cryptography.fernet import Fernet  # type: ignore

            self._Fernet = Fernet
        except ImportError:
            self._refuse_or_warn(
                "cryptography package not installed -- install 'cryptography' to enable at-rest Fernet encryption."
            )
            return
        key = _resolve_vault_key_env()
        if key is None:
            try:
                self._keyfile = _vault_key_path(self._store_dir)
                if self._keyfile is None:
                    raise OSError("vault key directory is unavailable")
                resolved_key = self._keyfile.resolve(strict=False)
                try:
                    resolved_key.relative_to(self._workspace_root.resolve())
                except ValueError:
                    pass
                else:
                    raise OSError("vault key directory must be outside the worker workspace")
                key = self._load_or_create_key()
            except OSError as exc:
                self._warn_plaintext_fallback(f"could not establish an out-of-workspace vault key: {exc!r}")
                self._refuse_or_warn(f"could not establish an out-of-workspace vault key: {exc!r}")
                return
        if not key:
            self._refuse_or_warn("no vault key could be established")
            return
        try:
            key_bytes = key if isinstance(key, bytes) else key.encode()
            self._fernet = Fernet(key_bytes)
            self._key_material = key_bytes
            self.enabled = True
        except Exception as exc:  # invalid key material -> fail closed
            self._refuse_or_warn(f"invalid vault key ({exc!r})")

    def _refuse_or_warn(self, detail: str) -> None:
        """Fail closed on secure-storage failure unless explicitly opted in.

        Default: record the refusal so ``assert_writable`` raises on any write
        attempt -- secrets are never persisted in cleartext silently. With
        ``BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1`` the legacy loud plaintext
        fallback applies (one-time WARNING, writes proceed).
        """
        if _plaintext_vault_allowed():
            self._warn_plaintext_fallback(
                f"{detail} -- proceeding in PLAINTEXT because {PLAINTEXT_VAULT_ENV}=1 is set."
            )
            return
        self._refusal = detail
        _LOG.error(
            "Credential-store secure storage unavailable: %s -- refusing "
            "plaintext writes (set %s=1 to explicitly allow insecure storage).",
            detail,
            PLAINTEXT_VAULT_ENV,
        )

    def assert_writable(self) -> None:
        """Raise RuntimeError when writes would persist secrets in plaintext."""
        if self.enabled or _plaintext_vault_allowed():
            return
        raise RuntimeError(
            f"credential-store secure storage unavailable ({self._refusal or 'unknown cause'}) -- "
            f"refusing plaintext write (set {PLAINTEXT_VAULT_ENV}=1 to explicitly allow insecure storage)"
        )

    @property
    def signing_key(self) -> bytes | None:
        """Key material for the record HMAC, or None when encryption is disabled.

        The HMAC is keyed by the same vault key as the Fernet encryption, so the
        ``confirmed`` flag is tamper-evident: a record whose ``confirmed=True``
        was not signed by this workspace's key (a crafted / hand-edited file, or
        a file from another workspace) is treated as untrusted on load.
        """
        return self._key_material

    @classmethod
    def _warn_plaintext_fallback(cls, detail: str) -> None:
        if not cls._plaintext_warned:
            _LOG.warning("Credential-store encryption DISABLED: %s", detail)
            cls._plaintext_warned = True

    def _load_or_create_key(self) -> str | None:
        """Return the 0600 keyfile's key, generating one on first use.

        The live keyfile lives OUTSIDE the workspace tree (see
        :func:`_vault_key_path`). A legacy in-workspace ``.vault_key`` is
        adopted once (moved, not copied) so existing stores keep decrypting
        and no key material is left behind in AI-readable space.
        """
        keyfile = self._keyfile
        if keyfile is None:
            raise OSError("vault key directory is unavailable")
        try:
            keyfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
            dir_flags |= getattr(os, "O_NOFOLLOW", 0)
            parent_fd = os.open(keyfile.parent, dir_flags)
            try:
                os.fchmod(parent_fd, 0o700)
                key_name = keyfile.name
                existing = self._read_key_at(parent_fd, key_name)
                if existing is not None:
                    return existing
                legacy = self._legacy_key_reader()
                key = legacy or self._Fernet.generate_key().decode()
                try:
                    self._create_key_at(parent_fd, key_name, key)
                except FileExistsError:
                    # Another process initialized the same per-store key.
                    # Reopen the winner without following a symlink.
                    existing = self._read_key_at(parent_fd, key_name)
                    if existing is None:
                        raise OSError("vault key disappeared during initialization")
                    return existing
                if legacy:
                    try:
                        self._legacy_key_remover()
                    except OSError:
                        pass
                return key
            finally:
                os.close(parent_fd)
        except OSError as exc:
            self._warn_plaintext_fallback(f"could not read/create keyfile {self._keyfile}: {exc!r}")
            return None

    @staticmethod
    def _read_key_at(parent_fd: int, name: str) -> str | None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("vault key must be a single-link regular file")
            os.fchmod(fd, 0o600)
            raw = os.read(fd, 65537)
            if len(raw) > 65536:
                raise OSError("vault key exceeds 64 KiB")
            return raw.decode("utf-8").strip() or None
        finally:
            os.close(fd)

    @staticmethod
    def _create_key_at(parent_fd: int, name: str, key: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            payload = key.encode("utf-8")
            while payload:
                written = os.write(fd, payload)
                if written <= 0:
                    raise OSError("short write while creating vault key")
                payload = payload[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_legacy_keyfile(self) -> str | None:
        """Read a legacy keyfile without following a symlink."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self._legacy_keyfile, flags)
        except FileNotFoundError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("legacy vault key is not a regular file")
            raw = os.read(fd, 65537)
            if len(raw) > 65536:
                raise OSError("legacy vault key exceeds 64 KiB")
            return raw.decode("utf-8").strip() or None
        finally:
            os.close(fd)

    def _remove_legacy_keyfile(self) -> None:
        self._legacy_keyfile.unlink()

    def encrypt(self, plaintext: str) -> str:
        """Return the at-rest form of ``plaintext`` (ciphertext, or plaintext if disabled)."""
        if not self.enabled or self._fernet is None:
            return plaintext
        try:
            return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        except Exception as exc:
            # Encryption was available when the write gate ran, so a failure
            # here must never turn into a plaintext persistence fallback.
            raise RuntimeError("credential encryption failed; refusing plaintext write") from exc

    def decrypt(self, token: str) -> str:
        """Return the plaintext form of ``token``; fall back to ``token`` if it is not ciphertext.

        Falling back (rather than raising) means legacy plaintext files and
        wrong-key/rotated-key reads still surface *something* instead of bricking
        the store. A wrong key yields garbage rather than the original secret,
        but the record is never lost.
        """
        if not self.enabled or self._fernet is None:
            return token
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except Exception:
            return token


class CredentialStore:
    """Persistent store for credentials and loot across sessions.

    The ``password`` field of each record is encrypted at rest (see ``_Vault``)
    and decrypted on load; in memory, records hold plaintext, so existing
    callers that read ``record.password`` are unchanged.
    """

    _MAX_STORE_BYTES = 64 * 1024 * 1024

    def __init__(self, workspace: Path, *, workspace_root: Path | None = None) -> None:
        requested = Path(workspace).absolute()
        self._storage_root = Path(workspace_root).absolute() if workspace_root is not None else requested
        try:
            self._storage_relative = requested.relative_to(self._storage_root)
        except ValueError as exc:
            raise ValueError("credential store must be inside its workspace root") from exc
        if any(part in {"", ".", ".."} for part in self._storage_relative.parts):
            raise ValueError("credential store path contains an unsafe component")
        self.workspace = self._storage_root.joinpath(*self._storage_relative.parts)
        # Create/open every path component relative to a pinned, no-follow root
        # directory. In MCP use the run workspace as workspace_root so a worker
        # cannot redirect an intermediate `credentials/<target>` directory.
        parent_fd = self._open_storage_dir(create=True)
        os.close(parent_fd)
        self._store_path = self.workspace / "credentials.jsonl"
        self._vault = _Vault(
            self.workspace,
            workspace_root=self._storage_root,
            legacy_key_reader=self._read_legacy_key,
            legacy_key_remover=self._remove_legacy_key,
        )
        self._records: list[CredentialRecord] = []
        self._load()

    @staticmethod
    def _dir_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)

    def _open_storage_dir(self, *, create: bool) -> int:
        """Open this store's directory without following workspace symlinks."""
        self._storage_root.mkdir(parents=True, exist_ok=True)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.open(self._storage_root, self._dir_flags() | nofollow)
        try:
            for component in self._storage_relative.parts:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                child_fd = os.open(component, self._dir_flags() | nofollow, dir_fd=current_fd)
                if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                    os.close(child_fd)
                    raise OSError("credential store path component is not a directory")
                os.close(current_fd)
                current_fd = child_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def _read_regular_file(self, filename: str, *, limit: int) -> bytes | None:
        """Read one store file relative to a pinned directory, rejecting links."""
        parent_fd = self._open_storage_dir(create=False)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            try:
                file_fd = os.open(filename, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise OSError("credential store path is not a regular file")
                chunks: list[bytes] = []
                remaining = limit + 1
                while remaining > 0:
                    chunk = os.read(file_fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                if len(data) > limit:
                    raise ValueError(f"credential store exceeds {limit} bytes")
                return data
            finally:
                os.close(file_fd)
        finally:
            os.close(parent_fd)

    def _read_legacy_key(self) -> str | None:
        raw = self._read_regular_file(".vault_key", limit=65536)
        return raw.decode("utf-8").strip() or None if raw is not None else None

    def _remove_legacy_key(self) -> None:
        parent_fd = self._open_storage_dir(create=False)
        try:
            os.unlink(".vault_key", dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to credential store")
            view = view[written:]

    # ── record integrity (HMAC over the confirmed flag) ─────────────────────
    #
    # ``confirmed=True`` is the gate the exploit loop trusts before it reuses a
    # credential at full access. To stop a crafted/hand-edited file -- or a file
    # copied in from another workspace -- from carrying a forged
    # ``confirmed=True`` into memory, every record is HMAC-signed on write and
    # verified on load. The HMAC is keyed by the vault key, so it is only
    # produced when at-rest encryption is enabled; in plaintext-fallback mode no
    # signature is possible, so ``confirmed=True`` read from disk is *never*
    # trusted and is downgraded to False on load.

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        """HMAC-SHA256 hex over canonical JSON of ``payload`` (which must NOT yet
        contain ``sig``). Returns ``""`` when no signing key is available (plaintext
        fallback); callers then omit the ``sig`` field entirely.
        """
        key = self._vault.signing_key
        if key is None:
            return ""
        body = json.dumps(payload, default=str, sort_keys=True, separators=(",", ":"))
        return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_sig(self, data: dict[str, Any], sig: str | None) -> bool:
        """True iff ``sig`` matches the record's HMAC under the current vault key.

        Constant-time via ``hmac.compare_digest``. With no signing key (plaintext
        fallback) or no signature present, no signature is valid, so every on-disk
        ``confirmed=True`` is treated as untrusted and downgraded on load.
        """
        key = self._vault.signing_key
        if key is None or not sig:
            return False
        expected = self._sign_payload(data)
        return hmac.compare_digest(expected, sig)

    def _attach_sig(self, payload: dict[str, Any]) -> None:
        """Sign ``payload`` in place, attaching ``sig`` when a key is available."""
        sig = self._sign_payload(payload)
        if sig:
            payload["sig"] = sig

    def _load(self) -> None:
        raw = self._read_regular_file("credentials.jsonl", limit=self._MAX_STORE_BYTES)
        if raw is None:
            return
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            # Verify the record's HMAC before trusting the ``confirmed`` flag.
            # The signature was computed over the on-disk fields (with the
            # CIPHERTEXT password) *before* ``sig`` was attached, so pop sig and
            # verify BEFORE decrypting the password into plaintext -- otherwise the
            # recomputed digest would cover the plaintext secret and never match.
            sig = data.pop("sig", None)
            sig_ok = self._verify_sig(data, sig)
            # Decrypt secret-bearing fields if written under encryption;
            # legacy plaintext falls through (decrypt returns it unchanged).
            if "password" in data:
                data["password"] = self._vault.decrypt(str(data["password"]))
            if "notes" in data:
                data["notes"] = self._vault.decrypt(str(data["notes"]))
            rec = CredentialRecord.from_json(data)
            if not sig_ok and rec.confirmed:
                # A confirmed=True we cannot authenticate was hand-edited, copied
                # from another workspace, or written under plaintext fallback. It
                # is downgraded so a stale/forged credential cannot masquerade as
                # validated. Legacy unconfirmed records load unchanged (the guard
                # only fires when confirmed was True).
                _LOG.warning(
                    "Downgrading untrusted confirmed=True credential for "
                    "%s@%s (no valid HMAC -- hand-edited, foreign workspace, or "
                    "plaintext-fallback write); re-confirm after a validated reuse.",
                    rec.username,
                    rec.target_host,
                )
                rec.confirmed = False
            self._records.append(rec)

    def save(self) -> None:
        # Fail closed: never persist secrets in cleartext unless explicitly opted in.
        self._vault.assert_writable()
        # Atomic replacement through one pinned directory descriptor. A worker
        # cannot redirect either the temporary file or the destination via a
        # symlink in the shared workspace.
        lines: list[str] = []
        for rec in self._records:
            payload = rec.to_json()
            payload["password"] = self._vault.encrypt(rec.password)
            payload["notes"] = self._vault.encrypt(rec.notes)
            self._attach_sig(payload)
            lines.append(json.dumps(payload, default=str) + "\n")
        data = "".join(lines).encode("utf-8")
        if len(data) > self._MAX_STORE_BYTES:
            raise ValueError(f"credential store exceeds {self._MAX_STORE_BYTES} bytes")
        parent_fd = self._open_storage_dir(create=False)
        temp_name = f".credentials-{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        created_temp = False
        try:
            file_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            created_temp = True
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise OSError("credential store temporary path is not a regular file")
                self._write_all(file_fd, data)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            os.replace(
                temp_name,
                "credentials.jsonl",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except BaseException:
            if created_temp:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(parent_fd)

    def add(self, record: CredentialRecord) -> None:
        # The harvester path must NEVER produce a confirmed credential:
        # confirmation is a deliberate post-reuse signal gated behind
        # ``confirm_credential(validated=True)``. A caller-supplied
        # ``record.confirmed=True`` would otherwise be persisted AND HMAC-signed
        # under this workspace's own vault key, so it would survive reload as a
        # trusted, signature-verified credential -- silently bypassing the
        # validated gate the exploit loop trusts before reusing a credential at
        # full access. Force it to False here so the *only* path to
        # ``confirmed=True`` remains ``confirm_credential`` (matching the module
        # docstring). ``save()`` deliberately does NOT force False, so records that
        # ``confirm_credential`` legitimately flips to True are persisted as True.
        if record.confirmed:
            _LOG.warning(
                "add() received confirmed=True for %s@%s -- forcing False "
                "(harvested credentials are never confirmed; use "
                "confirm_credential(validated=True) after a validated reuse).",
                record.username,
                record.target_host,
            )
            record.confirmed = False
        for existing in self._records:
            if (
                existing.username == record.username
                and existing.target_host == record.target_host
                and existing.credential_type == record.credential_type
            ):
                return
        # Fail closed before appending: a refused write must leave neither
        # memory nor disk holding a secret that cannot be persisted safely.
        self._vault.assert_writable()
        payload = record.to_json()
        payload["password"] = self._vault.encrypt(record.password)
        payload["notes"] = self._vault.encrypt(record.notes)
        self._attach_sig(payload)
        data = (json.dumps(payload, default=str) + "\n").encode("utf-8")
        parent_fd = self._open_storage_dir(create=False)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            file_fd = os.open("credentials.jsonl", flags, 0o600, dir_fd=parent_fd)
            try:
                file_info = os.fstat(file_fd)
                if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1:
                    raise OSError("credential store must be a single-link regular file")
                # Existing stores may have been created with a permissive umask.
                # Do not append secrets unless restrictive permissions were
                # successfully applied and verified on the opened inode.
                os.fchmod(file_fd, 0o600)
                file_info = os.fstat(file_fd)
                if file_info.st_mode & 0o077:
                    raise PermissionError("credential store permissions are not private")
                if file_info.st_size + len(data) > self._MAX_STORE_BYTES:
                    raise ValueError(f"credential store exceeds {self._MAX_STORE_BYTES} bytes")
                self._write_all(file_fd, data)
            finally:
                os.close(file_fd)
        finally:
            os.close(parent_fd)
        self._records.append(record)

    def confirm_credential(
        self,
        *,
        username: str,
        target_host: str,
        credential_type: str | None = None,
        validated: bool = False,
    ) -> bool:
        """Mark a harvested credential ``confirmed=True`` after a validated reuse.

        This is the *only* path to ``confirmed=True``: ``add`` stores unconfirmed
        records. Confirmation is a deliberate post-reuse signal, not something the
        harvester grants, so the caller MUST pass ``validated=True`` to assert it
        actually authenticated with the credential (e.g. via lateral_exec /
        dump_credentials). A bare confirm without ``validated=True`` is refused --
        it flips no flags and persists nothing -- so a careless call cannot
        promote an unvalidated credential. Returns True iff at least one record
        was newly confirmed.
        """
        if not validated:
            _LOG.warning(
                "confirm_credential refused for %s@%s: validated=False (caller did "
                "not assert the credential was reused successfully).",
                username,
                target_host,
            )
            return False
        changed_records: list[CredentialRecord] = []
        for rec in self._records:
            if rec.confirmed:
                continue
            if rec.username != username or rec.target_host != target_host:
                continue
            if credential_type is not None and rec.credential_type != credential_type:
                continue
            rec.confirmed = True
            changed_records.append(rec)
        if changed_records:
            try:
                self.save()
            except BaseException:
                for rec in changed_records:
                    rec.confirmed = False
                raise
        return bool(changed_records)

    def credentials_for_host(self, host: str) -> list[CredentialRecord]:
        return [r for r in self._records if r.target_host == host or r.source_host == host]

    def all_credentials(self) -> list[CredentialRecord]:
        return list(self._records)

    def hosts_with_credentials(self) -> list[str]:
        hosts = {r.target_host for r in self._records}
        hosts.update(r.source_host for r in self._records)
        return sorted(hosts)

    def summary(self) -> str:
        lines = ["CREDENTIAL STORE SUMMARY:", f"  Total records: {len(self._records)}"]
        for r in self._records:
            lines.append(f"  {r.target_host}: {r.username}/{r.credential_type} (confirmed={r.confirmed})")
        return "\n".join(lines)

    # ── introspection used by the MCP cred_store tools ──────────────────────

    @property
    def encryption_enabled(self) -> bool:
        return self._vault.enabled

    def assert_writable(self) -> None:
        """Raise RuntimeError when a write would persist secrets in plaintext."""
        self._vault.assert_writable()

    @property
    def store_path(self) -> Path:
        return self._store_path


@dataclass
class LootItem:
    timestamp: float
    source_host: str
    loot_type: str
    description: str
    content: str = ""
    path: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_host": self.source_host,
            "loot_type": self.loot_type,
            "description": self.description,
            "content": self.content[:5000],  # Bound inline content
            "path": self.path,
        }


class LootStore:
    """Persistent store for arbitrary loot (files, configs, data)."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._store_path = workspace / "loot.jsonl"
        self._items: list[LootItem] = []
        self._load()

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        for line in self._store_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                self._items.append(
                    LootItem(
                        timestamp=data.get("timestamp", time.time()),
                        source_host=str(data.get("source_host", "")),
                        loot_type=str(data.get("loot_type", "")),
                        description=str(data.get("description", "")),
                        content=str(data.get("content", "")),
                        path=str(data.get("path", "")),
                    )
                )
            except (json.JSONDecodeError, TypeError):
                continue

    def add(self, item: LootItem) -> None:
        self._items.append(item)
        with self._store_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item.to_json(), default=str) + "\n")

    def loot_for_host(self, host: str) -> list[LootItem]:
        return [i for i in self._items if i.source_host == host]

    def summary(self) -> str:
        lines = ["LOOT STORE SUMMARY:", f"  Total items: {len(self._items)}"]
        for i in self._items:
            lines.append(f"  [{i.loot_type}] {i.source_host}: {i.description[:60]}")
        return "\n".join(lines)
