"""Private handoff of an accepted config snapshot to an MCP child.

API runs must not reopen the mutable operator config file after accepting a
run. This module writes a short-lived private YAML snapshot. Literal config
secrets are represented by environment variable references in that file and
are sent separately in the child environment.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

_SECRET_REF_KEY = "__breachpilot_mcp_secret_env_ref__"
_SECRET_ENV_PREFIX = "BREACHPILOT_MCP_CONFIG_SECRET_"
_SECRET_ENV_NAME = re.compile(r"^BREACHPILOT_MCP_CONFIG_SECRET_[0-9]{4,}$")
_SECRET_KEY_PARTS = (
    "api_key",
    "client_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "secret_key",
    "password",
    "passwd",
    "secret",
)
_NON_SECRET_REFERENCE_SUFFIXES = ("_env", "_file", "_path")
_URL_LEADING_CONTROLS_AND_SPACE = "".join(chr(codepoint) for codepoint in range(0x21))


class McpConfigSnapshotError(RuntimeError):
    """Raised when a private MCP snapshot cannot be created or resolved."""


@dataclass(frozen=True)
class PrivateMcpConfigSnapshot:
    """Paths and child-only environment values for one MCP context."""

    config_path: Path
    secret_env: dict[str, str] = field(repr=False)


def _is_secret_value(path: tuple[str, ...], key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith(_NON_SECRET_REFERENCE_SUFFIXES):
        return False
    if (
        any(lowered == part or lowered.endswith(f"_{part}") for part in _SECRET_KEY_PARTS)
        or lowered.endswith("_token")
        or lowered in {"key", "token", "auth"}
    ):
        return True
    return len(path) == 1 and path[0].lower() == "webhook_notify" and lowered == "url"


def _contains_url_userinfo(value: str) -> bool:
    """Return whether a URL string embeds user information in its authority."""
    # urllib.parse intentionally removes embedded CR/LF/TAB before parsing.
    # Normalize those characters before detecting the authority delimiter so
    # credentials split across a control character cannot evade redaction.
    candidate = value.lstrip(_URL_LEADING_CONTROLS_AND_SPACE).replace("\r", "").replace("\n", "").replace("\t", "")
    if "://" not in candidate and not candidate.startswith("//"):
        return False
    try:
        return urlsplit(candidate).username is not None
    except ValueError:
        # A malformed URL with an authority delimiter can still contain a
        # credential. Keep it out of the snapshot artifact; the child will
        # report any parse/configuration error after resolving the reference.
        return "@" in candidate


def _to_yaml_values(value: Any) -> Any:
    """Normalize in-memory YAML-compatible containers without stringifying secrets."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _to_yaml_values(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_yaml_values(item) for item in value]
    return value


def _reference_secrets(config: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    child_env: dict[str, str] = {}

    def reference_secret(value: str) -> dict[str, str]:
        env_name = f"{_SECRET_ENV_PREFIX}{len(child_env):04d}"
        child_env[env_name] = value
        return {_SECRET_REF_KEY: env_name}

    def visit(value: Any, path: tuple[str, ...]) -> Any:
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                child_path = (*path, key)
                contains_url_credentials = isinstance(item, str) and _contains_url_userinfo(item)
                is_secret_field = _is_secret_value(path, key)
                if is_secret_field and not isinstance(item, str):
                    raise McpConfigSnapshotError("MCP config secret values must be strings.")
                if is_secret_field and isinstance(item, str) and item:
                    output[key] = reference_secret(item)
                elif contains_url_credentials and isinstance(item, str):
                    output[key] = reference_secret(item)
                else:
                    output[key] = visit(item, child_path)
            return output
        if isinstance(value, (list, tuple)):
            list_output: list[Any] = []
            for item in value:
                if isinstance(item, str) and item and _contains_url_userinfo(item):
                    list_output.append(reference_secret(item))
                else:
                    list_output.append(visit(item, path))
            return list_output
        return _to_yaml_values(value)

    return visit(config, ()), child_env


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


@contextmanager
def private_mcp_config_snapshot(
    config: Mapping[str, Any], *, excluded_paths: tuple[Path, ...] = ()
) -> Iterator[PrivateMcpConfigSnapshot]:
    """Create and clean an owner-only config file for one MCP context.

    The file and containing directory are checked against the run workspace
    and reports paths so this artifact cannot enter worker-visible storage.
    POSIX permissions are enforced as 0600/0700; failures abort startup.
    """
    try:
        temp_root = Path(tempfile.gettempdir()).resolve()
        for excluded_path in excluded_paths:
            if _is_within(temp_root, excluded_path.resolve()):
                raise McpConfigSnapshotError("Private MCP config location overlaps a protected run path.")
        private_dir = Path(tempfile.mkdtemp(prefix="breachpilot-mcp-config-", dir=temp_root))
    except OSError:
        raise McpConfigSnapshotError("Private MCP config location is unavailable.") from None
    try:
        os.chmod(private_dir, 0o700)
        config_path = private_dir / "accepted-config.yaml"
        resolved_config_path = config_path.resolve()
        for excluded_path in excluded_paths:
            protected = excluded_path.resolve()
            if _is_within(resolved_config_path, protected):
                raise McpConfigSnapshotError("Private MCP config location overlaps a protected run path.")

        try:
            sanitized, secret_env = _reference_secrets(config)
            payload = yaml.safe_dump(_to_yaml_values(sanitized), sort_keys=True, allow_unicode=True)
        except McpConfigSnapshotError:
            raise
        except Exception:
            # YAML representer exceptions can include fragments of the value.
            raise McpConfigSnapshotError("Accepted MCP config could not be serialized safely.") from None

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(config_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(config_path, 0o600)

        if os.name == "posix":
            if stat.S_IMODE(private_dir.stat().st_mode) != 0o700:
                raise McpConfigSnapshotError("Private MCP config directory permissions are not restrictive.")
            if stat.S_IMODE(config_path.stat().st_mode) != 0o600:
                raise McpConfigSnapshotError("Private MCP config file permissions are not restrictive.")

        yield PrivateMcpConfigSnapshot(config_path=config_path, secret_env=secret_env)
    except OSError:
        raise McpConfigSnapshotError("Private MCP config snapshot could not be created securely.") from None
    finally:
        shutil.rmtree(private_dir)


def resolve_mcp_config_secret_refs(config: Mapping[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    """Resolve private snapshot references before digest verification."""

    def visit(value: Any) -> Any:
        if isinstance(value, Mapping):
            if _SECRET_REF_KEY in value:
                if set(value) != {_SECRET_REF_KEY}:
                    raise McpConfigSnapshotError("MCP config snapshot contains an invalid secret reference.")
                env_name = value[_SECRET_REF_KEY]
                if not isinstance(env_name, str) or _SECRET_ENV_NAME.fullmatch(env_name) is None:
                    raise McpConfigSnapshotError("MCP config snapshot contains an invalid secret reference.")
                secret = env.get(env_name)
                if not secret:
                    raise McpConfigSnapshotError("MCP config snapshot secret reference is unavailable.")
                return secret
            return {str(key): visit(item) for key, item in value.items()}
        if isinstance(value, list):
            return [visit(item) for item in value]
        return value

    result = visit(config)
    if not isinstance(result, dict):
        raise McpConfigSnapshotError("MCP config snapshot must contain a mapping.")
    return result


__all__ = [
    "McpConfigSnapshotError",
    "PrivateMcpConfigSnapshot",
    "private_mcp_config_snapshot",
    "resolve_mcp_config_secret_refs",
]
