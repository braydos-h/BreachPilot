"""Workspace path helpers — pure, no I/O beyond Path checks.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). Both flows and
``tools.persistent_session_manager`` import from here; ``tools.mcp_shared``
re-exports for backwards compat.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from datetime import datetime, timezone
from errno import ELOOP
from pathlib import Path


def _is_inside_workspace(workspace: Path, target: Path) -> bool:
    """True if ``target`` (resolved) is equal to or nested under ``workspace``.

    Ponytail: single source for the predicate previously duplicated in
    ``tools.mcp_shared`` and ``tools.persistent_session_manager``.
    Handles ``OSError`` (broken symlink / permission) and treats the
    workspace root itself as inside (equality check).
    """
    try:
        root = workspace.resolve()
        resolved = target.resolve()
    except OSError:
        return False
    try:
        resolved.relative_to(root)
        return True
    except ValueError:
        return resolved == root


def _resolve_workspace_file(workspace: Path, filename: str, suffix: str | None = None) -> Path:
    """Resolve a workspace file by absolute path, relative path, or basename.

    Mirrors ``tools.mcp_shared._resolve_workspace_file`` verbatim (Phase 2
    move, no behavior change). See that function for the full docstring.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    raw = str(filename or "").strip().strip("\"'")
    if not raw:
        return root / "__missing__"

    normalized = raw.replace("\\", "/")
    raw_path = Path(raw)
    candidates: list[Path] = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    elif "/" in normalized:
        candidates.append(root / normalized)

    safe_name = Path(normalized).name.lstrip("/").lstrip("\\")
    if safe_name:
        candidates.append(root / safe_name)

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not _is_inside_workspace(root, resolved):
            continue
        if resolved.is_file() and (suffix is None or resolved.name.endswith(suffix)):
            return resolved

    if not safe_name:
        return root / "__missing__"

    matches: list[Path] = []
    for candidate in root.rglob(safe_name):
        if not candidate.is_file() or (suffix is not None and not candidate.name.endswith(suffix)):
            continue
        try:
            resolved_cand = candidate.resolve()
        except OSError:
            continue
        if _is_inside_workspace(root, resolved_cand):
            matches.append(resolved_cand)
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime if p.exists() else 0)

    return root / safe_name


def _find_file(workspace: Path, filename: str) -> Path | None:
    resolved = _resolve_workspace_file(workspace, filename)
    if not resolved.exists() or not resolved.is_file():
        return None
    root = workspace.resolve()
    try:
        if not _is_inside_workspace(root, resolved.resolve()):
            return None
    except OSError:
        return None
    return resolved


def _attempt_dir(workspace: Path) -> tuple[Path, str]:
    workspace.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    # Do not accept an existing directory or symlink on a random-name
    # collision. The sandbox can write to this tree, so every attempt path
    # must be one the host created itself.
    for _ in range(8):
        attempt_id = f"{stamp}_{secrets.token_hex(4)}"
        attempt_dir = workspace / attempt_id
        try:
            attempt_dir.mkdir()
        except FileExistsError:
            continue
        return attempt_dir, attempt_id
    raise FileExistsError("could not allocate a unique workspace attempt directory")


def write_workspace_file(workspace: Path, relative_path: str, data: bytes, *, mode: int = 0o600) -> Path:
    """Create a new regular file beneath the workspace without following links.

    Parent components are traversed from a pinned workspace directory fd with
    ``O_NOFOLLOW``. The leaf uses ``O_EXCL`` so a worker-created symlink or
    existing file cannot redirect or replace a host-side write.
    """
    rel = Path(relative_path)
    if rel.is_absolute() or not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError("workspace file path must be a non-empty relative path without traversal")
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    # Open the configured workspace path itself without following a symlink.
    # The descriptor then pins the root while all child components are opened
    # relative to it, even if an untrusted worker mutates the shared tree.
    root_fd = os.open(workspace, dir_flags | nofollow)
    current_fd = root_fd
    try:
        for component in rel.parts[:-1]:
            child_fd = os.open(component, dir_flags | nofollow, dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = child_fd
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(rel.parts[-1], file_flags, mode, dir_fd=current_fd)
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise OSError("workspace output is not a regular file")
            view = memoryview(data)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError("short write to workspace artifact")
                view = view[written:]
        finally:
            os.close(file_fd)
    except OSError as exc:
        if exc.errno == ELOOP:
            raise OSError("refusing to follow a symlink in the workspace path") from exc
        raise
    finally:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
    return root.joinpath(*rel.parts)


def write_workspace_script(workspace: Path, name_hint: str, script_text: str) -> Path:
    """Save generated Python source with a bounded basename and no-follow I/O.

    Workspace contents are writable from the sandbox worker. Generated scripts
    therefore use a flat, random filename and the descriptor-relative writer;
    no worker-created directory or leaf can redirect the host-side write.
    The stem stays within ``run_python_file``'s 80-character filename limit.
    """
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name_hint or ""))[:60].strip("._-")
    filename = f"{safe_stem or 'attack_module'}_{secrets.token_hex(8)}.py"
    return write_workspace_file(workspace, filename, script_text.encode("utf-8"))


def _read_workspace_file_fd(root: Path, target: Path, *, limit: int, reject_hardlinks: bool = False) -> bytes:
    """Read a canonical workspace path without following raced symlinks."""
    rel = target.relative_to(root)
    if not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError("workspace file path is invalid")
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, dir_flags | nofollow)
    current_fd = root_fd
    try:
        for component in rel.parts[:-1]:
            child_fd = os.open(component, dir_flags | nofollow, dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = child_fd
        read_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | nofollow | getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(rel.parts[-1], read_flags, dir_fd=current_fd)
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("workspace input is not a regular file")
            if reject_hardlinks and info.st_nlink > 1:
                raise PermissionError("hard-linked workspace files are not served")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(file_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    except OSError as exc:
        if exc.errno == ELOOP:
            raise OSError("refusing to follow a symlink in the workspace path") from exc
        raise
    finally:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)


def read_workspace_bytes(workspace: Path, filename: str, *, limit: int) -> tuple[Path, bytes]:
    """Read a workspace file through descriptor-relative no-follow opens."""
    raw = str(filename or "").strip()
    if not raw:
        raise ValueError("empty filename")
    if is_vault_key_path(raw):
        raise PermissionError("credential-store keyfiles are never served")
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    target = Path(raw)
    if not target.is_absolute():
        target = root / target
    resolved = target.resolve()
    if not _is_inside_workspace(root, resolved):
        raise PermissionError("file is outside the workspace")
    if _is_credential_store_path(root, resolved):
        raise PermissionError("credential-store files are never served through workspace reads")
    if is_vault_key_path(str(resolved)):
        raise PermissionError("credential-store keyfiles are never served")
    content = _read_workspace_file_fd(root, resolved, limit=limit, reject_hardlinks=True)
    if len(content) > limit:
        raise ValueError(f"file exceeds {limit} bytes")
    return resolved, content


# Vault keyfiles must never be served to the model: the live key lives
# outside the workspace tree, but a hand-placed or legacy in-workspace
# ``.vault_key`` would otherwise hand the Fernet key over on request
# (encrypted-at-rest secrets = plaintext). Check both the requested and
# resolved basenames so an in-workspace symlink alias cannot serve the key.
_VAULT_KEY_BASENAMES = frozenset({".vault_key"})


def _is_credential_store_path(root: Path, target: Path) -> bool:
    """Identify raw credential-store files, including resolved symlink aliases."""
    try:
        relative = target.relative_to(root)
    except ValueError:
        return False
    return bool(relative.parts) and (relative.parts[0] == "credentials" or relative.name == "credentials.jsonl")


def is_vault_key_path(filename: str) -> bool:
    """True when ``filename`` names a vault keyfile (deny-listed from reads)."""
    name = str(filename or "").strip().replace("\\", "/").split("/")[-1].strip("\"'")
    return name in _VAULT_KEY_BASENAMES


def read_workspace(workspace: Path, filename: str) -> str:
    """Read a file inside the run workspace by path (Phase 3 kernel move).

    Workspace-contained only: absolute paths escaping the workspace (and
    unreadable/missing files) are refused. Previously this read any
    operator-box path, letting a prompt-injected filename exfiltrate
    /etc/shadow, cloud credentials, or OAuth tokens into the model context.
    Vault keyfiles (``.vault_key``) are deny-listed by requested and resolved
    basename: serving one through a symlink alias would hand the
    credential-store Fernet key to the model.
    """
    raw = str(filename or "").strip()
    if not raw:
        return "BLOCKED: empty filename."
    if is_vault_key_path(raw):
        return f"BLOCKED: {Path(raw).name!r} is a credential-store keyfile and is never served."
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    target = Path(raw)
    if not target.is_absolute():
        target = root / raw
    try:
        resolved = target.resolve()
    except OSError as exc:
        return f"BLOCKED: could not read {Path(filename).name!r}: {exc}"
    if not _is_inside_workspace(root, resolved):
        return f"BLOCKED: {Path(filename).name!r} is outside the workspace."
    if _is_credential_store_path(root, resolved):
        return "BLOCKED: raw credential-store files are never served; use the credential tools."
    if is_vault_key_path(str(resolved)):
        return "BLOCKED: resolved target is a credential-store keyfile and is never served."
    if not resolved.exists() or not resolved.is_file():
        return f"FILE_NOT_FOUND: {Path(filename).name}"
    try:
        content = _read_workspace_file_fd(root, resolved, limit=120_000, reject_hardlinks=True)
        text = content.decode("utf-8", errors="replace")
    except OSError as exc:
        return f"BLOCKED: could not read {filename!r}: {exc}"
    if len(text) > 120_000:
        text = text[:120_000] + "\n[truncated]"
    return text
