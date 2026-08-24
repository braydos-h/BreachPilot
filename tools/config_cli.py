"""CLI configuration and startup API-key helpers."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from pathlib import Path
from uuid import uuid4

import yaml

from tools.api_key_store import DEFAULT_API_KEY_FILE, bootstrap_api_keys
from tools.attack_ui import AttackUi
from tools.kernel.config import load_config  # canonical; re-export for back-compat

ui = AttackUi(plain=False)


def add_target_to_allowlist(path: Path, target_ip: str) -> bool:
    """Persist a target (IP, domain, or wildcard domain) in ``exploit.allowed_targets``.

    Returns ``True`` when the config file was changed and ``False`` when the
    normalized address was already present.  The replacement is atomic so an
    interrupted new-session flow cannot leave a partial YAML file behind.

    Bare IP addresses are normalized via ``ipaddress.ip_address`` for
    deduplication; domains and ``*.wildcard`` entries are persisted verbatim
    (the allowlist matcher ``is_target_in_allowlist`` handles all forms).
    Raises ``ValueError`` for a target that is neither a valid IP nor a
    valid domain (so genuinely malformed input is still rejected).
    """
    target = target_ip.strip()
    # Normalize IPs; preserve domains/wildcards verbatim (lowercased for
    # case-insensitive deduplication -- DNS is case-insensitive). Reject
    # anything that is neither a valid IP nor a valid FQDN.
    try:
        normalized_target = str(ipaddress.ip_address(target))
    except ValueError:
        from tools.validation_utils import is_fqdn

        if not is_fqdn(target):
            raise ValueError(f"Invalid target (not an IP or domain): {target!r}")
        normalized_target = target.lower()
    source = path.read_text(encoding="utf-8") if path.exists() else ""
    config = load_config(path)

    exploit = config.setdefault("exploit", {})
    if not isinstance(exploit, dict):
        raise ValueError("config exploit section must be a YAML mapping.")

    allowed_targets = exploit.setdefault("allowed_targets", [])
    if not isinstance(allowed_targets, list) or not all(isinstance(item, str) for item in allowed_targets):
        raise ValueError("config exploit.allowed_targets must be a list of strings.")

    normalized_existing: set[str] = set()
    for entry in allowed_targets:
        try:
            normalized_existing.add(str(ipaddress.ip_address(entry.strip())))
        except ValueError:
            # Existing host, wildcard, and CIDR entries remain valid allowlist
            # entries; only bare IP addresses are normalized for deduplication.
            normalized_existing.add(entry.strip().lower())

    if normalized_target in normalized_existing:
        return False

    allowed_targets.append(normalized_target)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    updated_source = _add_allowed_target_to_yaml(source, allowed_targets)
    try:
        temporary_path.write_text(
            updated_source
            if updated_source is not None
            else yaml.safe_dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return True


def _add_allowed_target_to_yaml(source: str, allowed_targets: list[str]) -> str | None:
    """Update only ``exploit.allowed_targets`` while retaining YAML comments.

    ``PyYAML`` intentionally discards comments when it loads a document. The
    normal project config is a block-style mapping, so make the small textual
    edit directly and use a full YAML serialization only for unusual layouts.
    """
    exploit_match = re.search(r"(?m)^exploit:\s*(?:#.*)?(?:\r?\n|$)", source)
    if exploit_match is None:
        return None

    next_section = re.search(r"(?m)^[^\s#][^:\r\n]*:\s", source[exploit_match.end() :])
    section_end = exploit_match.end() + next_section.start() if next_section is not None else len(source)
    section = source[exploit_match.end() : section_end]
    allowlist_match = re.search(
        r"(?m)^(?P<indent>[ \t]+)allowed_targets:\s*(?P<value>[^\r\n]*)(?P<newline>\r?\n|$)",
        section,
    )
    if allowlist_match is None:
        # No setting yet: append it to the existing exploit block using the
        # indentation of another setting (or the conventional two spaces).
        setting_match = re.search(r"(?m)^(?P<indent>[ \t]+)[^#\s][^:\r\n]*:", section)
        indent = setting_match.group("indent") if setting_match else "  "
        insertion = _format_allowed_targets(allowed_targets, indent)
        separator = "" if not section or section.endswith(("\n", "\r")) else "\n"
        return source[:section_end] + separator + insertion + "\n" + source[section_end:]

    indent = allowlist_match.group("indent")
    value = allowlist_match.group("value")
    value_without_comment = value.split("#", 1)[0].strip()
    if value_without_comment.startswith("["):
        comment = value[len(value.split("#", 1)[0]) :].strip()
        header = f"{indent}allowed_targets:" + (f" {comment}" if comment else "")
        replacement = (
            header + allowlist_match.group("newline") + _format_allowed_targets(allowed_targets, indent) + "\n"
        )
        return (
            source[: exploit_match.end() + allowlist_match.start()]
            + replacement
            + source[exploit_match.end() + allowlist_match.end() :]
        )

    # Block-style lists are already comment-preserving; append after their
    # indented value block, immediately before the next exploit setting.
    value_start = exploit_match.end() + allowlist_match.end()
    value_end = _yaml_block_end(source, value_start, len(indent))
    separator = "" if source[:value_end].endswith(("\n", "\r")) else "\n"
    return source[:value_end] + separator + f"{indent}  - {allowed_targets[-1]}\n" + source[value_end:]


def _format_allowed_targets(allowed_targets: list[str], indent: str) -> str:
    """Render a block-style allowlist with the supplied mapping indentation."""
    rendered = yaml.safe_dump(
        allowed_targets,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    ).rstrip()
    return "\n".join(f"{indent}  {line}" for line in rendered.splitlines())


def _yaml_block_end(source: str, start: int, base_indent: int) -> int:
    """Find the first line outside a block-style mapping value."""
    position = start
    for line in source[start:].splitlines(keepends=True):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            indentation = len(line) - len(line.lstrip(" \t"))
            if indentation <= base_indent:
                return position
        position += len(line)
    return len(source)


def bootstrap_startup_api_keys(args: argparse.Namespace, *, prompt: bool = False) -> None:
    """Load saved provider API keys and optionally prompt for missing values."""

    config = load_config(args.config)
    result = bootstrap_api_keys(
        config,
        store_path=Path(getattr(args, "api_key_file", DEFAULT_API_KEY_FILE)),
        prompt=prompt and not bool(getattr(args, "no_api_key_prompt", False)),
        force_prompt=bool(getattr(args, "setup_api_keys", False)),
    )
    if result.loaded:
        ui.info(f"Loaded provider API key(s) from {result.store_path}: {', '.join(result.loaded)}")
    if result.saved:
        ui.info(f"Saved provider API key(s) to {result.store_path}: {', '.join(result.saved)}")
    if result.missing and (prompt or bool(getattr(args, "setup_api_keys", False))):
        ui.warning(
            "Missing provider API key(s): "
            + ", ".join(result.missing)
            + ". MCP research tools that require provider APIs will stay disabled."
        )
