"""Adaptive exploit generation MCP tools (split from god file)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import get_default_db
from tools.experience_store import ExperienceStore
from tools.exploit_mutator import ExploitMutator
from tools.kernel.workspace import read_workspace_bytes, write_workspace_file
from tools.mcp_tools.registry import ToolContext, _get_model_client
from tools.payload_crafter import CraftedPayload
from tools.validation_utils import validate_target_or_ip

_GENERATION_ID_RE = re.compile(r"(?:gen|mut)-[0-9]+-[0-9a-f]{8}\Z")
_MAX_SCRIPT_BYTES = 1024 * 1024
_MAX_SIDECAR_BYTES = 64 * 1024
_MAX_LINEAGE_DEPTH = 64


def _read_generation(workspace: Path, generation_id: str) -> tuple[str, dict[str, Any]]:
    """Read a generated payload using workspace containment and no-follow I/O."""
    if not _GENERATION_ID_RE.fullmatch(generation_id):
        raise ValueError("invalid generation id")
    _, script_bytes = read_workspace_bytes(workspace, f"exploits/{generation_id}.py", limit=_MAX_SCRIPT_BYTES)
    _, sidecar_bytes = read_workspace_bytes(workspace, f"exploits/{generation_id}.json", limit=_MAX_SIDECAR_BYTES)
    script = script_bytes.decode("utf-8")
    sidecar = json.loads(sidecar_bytes.decode("utf-8"))
    if not isinstance(sidecar, dict):
        raise ValueError("generation sidecar must be a JSON object")
    if sidecar.get("generation_id", generation_id) != generation_id:
        raise ValueError("generation sidecar id does not match its filename")
    return script, sidecar


def _write_generation_file(workspace: Path, generation_id: str, suffix: str, content: bytes) -> Path:
    """Create a generation artifact without following worker-created links."""
    if not _GENERATION_ID_RE.fullmatch(generation_id):
        raise ValueError("invalid generated generation id")
    if suffix not in {".py", ".json"}:
        raise ValueError("invalid generation artifact type")
    return write_workspace_file(workspace, f"exploits/{generation_id}{suffix}", content)


def register_adaptive_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def craft_exploit(
        target_ip: str, service_name: str, version: str = "", os_hint: str = "", module_name: str = ""
    ) -> str:
        """Generate a custom exploit script tailored to a specific target service.

        Uses the ExploitMutator with experience-aware PayloadCrafter to produce a
        Python exploit script. The script is saved with metadata (generation_id,
        mutation strategy, confidence) for future mutation and lineage tracking.

        Args:
            target_ip: IPv4 address of the target host.
            service_name: Service to target (e.g., 'ssh', 'http', 'smb', 'rdp').
            version: Service version string (e.g., 'OpenSSH 8.9p1').
            os_hint: OS hint (e.g., 'linux', 'windows').
            module_name: Optional attack module name for context-aware generation.

        Returns:
            generation_id, file path, confidence score, mutation strategy,
            and first 500 characters of the generated script.

        Example:
            craft_exploit("192.168.1.100", "ssh", "OpenSSH 8.9p1", "linux", "RegreSSHion")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not service_name or not service_name.strip():
            return "ERROR: service_name is required."

        # Check config gate
        adaptive_cfg = (config or {}).get("adaptive_exploits", {})
        if not adaptive_cfg.get("enabled", True):
            return "BLOCKED: adaptive_exploits is disabled in config.yaml."

        try:
            exploits_dir = workspace / "exploits"
            exploits_dir.mkdir(parents=True, exist_ok=True)

            # Build experience store (lightweight JSONL fallback if DB unavailable)
            experience_store: ExperienceStore | None = None
            try:
                experience_store = ExperienceStore(get_default_db())
            except Exception:  # ponytail: bare except intentional
                experience_store = None

            # §13 code_generator role: PoC synthesis routes to
            # models.roles.code_generator when set.
            client, model_name = _get_model_client(config, role="code_generator")
            max_mutations = int(adaptive_cfg.get("max_mutations", 5))

            mutator = ExploitMutator(
                workspace=exploits_dir,
                experience_store=experience_store,
                client=client,
                model=model_name,
                max_mutations=max_mutations,
            )

            payload: CraftedPayload = mutator.craft_initial(
                target_ip=target_ip,
                service_name=service_name,
                version=version,
                os_hint=os_hint,
                module_name=module_name,
            )

            # Save script
            script_path = _write_generation_file(
                workspace, payload.generation_id, ".py", payload.script.encode("utf-8")
            )

            # Save sidecar metadata
            sidecar = {
                "generation_id": payload.generation_id,
                "parent_id": payload.parent_id,
                "mutation_strategy": payload.mutation_strategy,
                "confidence": payload.confidence,
                "metadata": payload.metadata,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            sidecar_path = _write_generation_file(
                workspace, payload.generation_id, ".json", json.dumps(sidecar, indent=2, default=str).encode("utf-8")
            )

            lines = [
                "CRAFT_EXPLOIT_RESULT: generated",
                f"GENERATION_ID: {payload.generation_id}",
                f"SCRIPT_PATH: {script_path}",
                f"SIDECAR_PATH: {sidecar_path}",
                f"CONFIDENCE: {payload.confidence:.2f}",
                f"MUTATION_STRATEGY: {payload.mutation_strategy}",
                f"TARGET: {target_ip}",
                f"SERVICE: {service_name} {version}",
                f"OS_HINT: {os_hint}",
                f"MODULE: {module_name or 'none'}",
                "",
                "SCRIPT_PREVIEW (first 500 chars):",
                payload.script[:500],
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Exploit crafting failed — {exc}"

    @mcp.tool()
    @audit_tool
    def mutate_exploit(script_id: str, failure_output: str) -> str:
        """Mutate a previously generated exploit script based on failure feedback.

        Loads the script and its sidecar metadata by generation_id, then applies
        a mutation strategy (parameter_tweak, encoding_change, delivery_swap,
        context_aware) to produce an improved variant. The mutated script is saved
        with parent linkage for lineage tracking.

        Args:
            script_id: The generation_id of the previous exploit (e.g., 'gen-1712345678-abc12345').
            failure_output: The error output or failure reason from the previous execution.

        Returns:
            New generation_id, mutation strategy used, new file path, and first 500 chars
            of the mutated script.

        Example:
            mutate_exploit("gen-1712345678-abc12345", "ConnectionResetError: target closed connection")
        """
        if not script_id or not _GENERATION_ID_RE.fullmatch(script_id):
            return "ERROR: script_id must be a valid generated exploit id."
        if not failure_output or not failure_output.strip():
            return "ERROR: failure_output is required."

        # Check config gate
        adaptive_cfg = (config or {}).get("adaptive_exploits", {})
        if not adaptive_cfg.get("enabled", True):
            return "BLOCKED: adaptive_exploits is disabled in config.yaml."

        try:
            exploits_dir = workspace / "exploits"
            exploits_dir.mkdir(parents=True, exist_ok=True)

            # Workspace contents are writable from the sandbox. Read scripts
            # and metadata via descriptor-relative no-follow opens so a worker
            # cannot substitute a symlink to host files.
            script_text, sidecar = _read_generation(workspace, script_id)

            # Reconstruct CraftedPayload
            previous_payload = CraftedPayload(
                generation_id=sidecar.get("generation_id", script_id),
                parent_id=sidecar.get("parent_id"),
                script=script_text,
                mutation_strategy=sidecar.get("mutation_strategy", "generate"),
                metadata=sidecar.get("metadata", {}),
                confidence=float(sidecar.get("confidence", 0.5)),
            )

            # Determine attempt number from lineage
            attempt_number = 1
            current_id = script_id
            seen_ids = {script_id}
            while len(seen_ids) < _MAX_LINEAGE_DEPTH:
                parent_id = sidecar.get("parent_id")
                if not isinstance(parent_id, str) or not _GENERATION_ID_RE.fullmatch(parent_id):
                    break
                if parent_id in seen_ids:
                    break
                try:
                    _parent_script, parent_sidecar = _read_generation(workspace, parent_id)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    raise ValueError("exploit lineage is incomplete or unsafe") from exc
                seen_ids.add(parent_id)
                attempt_number += 1
                sidecar = parent_sidecar
            # If the chain is longer than the bounded walk, fail closed rather
            # than undercounting attempts and bypassing the mutation ceiling.
            if len(seen_ids) == _MAX_LINEAGE_DEPTH and isinstance(sidecar.get("parent_id"), str):
                if _GENERATION_ID_RE.fullmatch(sidecar["parent_id"]):
                    return "ERROR: Exploit lineage exceeds the supported depth."

            # Build experience store
            experience_store: ExperienceStore | None = None
            try:
                experience_store = ExperienceStore(get_default_db())
            except Exception:  # ponytail: bare except intentional
                experience_store = None

            # §13 code_generator role (see craft_exploit above).
            client, model_name = _get_model_client(config, role="code_generator")
            max_mutations = int(adaptive_cfg.get("max_mutations", 5))

            mutator = ExploitMutator(
                workspace=exploits_dir,
                experience_store=experience_store,
                client=client,
                model=model_name,
                max_mutations=max_mutations,
            )

            mutated = mutator.mutate_on_failure(
                payload=previous_payload,
                failure_output=failure_output,
                attempt_number=attempt_number,
            )

            if mutated is None:
                return (
                    f"MUTATE_EXPLOIT_RESULT: max_mutations_reached\n"
                    f"SCRIPT_ID: {script_id}\n"
                    f"ATTEMPT: {attempt_number}\n"
                    f"MAX_MUTATIONS: {max_mutations}\n"
                    f"REASON: Exceeded maximum mutation attempts. Try a different approach or module."
                )

            # Save mutated script
            new_script_path = _write_generation_file(
                workspace, mutated.generation_id, ".py", mutated.script.encode("utf-8")
            )

            # Save updated sidecar
            new_sidecar = {
                "generation_id": mutated.generation_id,
                "parent_id": mutated.parent_id,
                "mutation_strategy": mutated.mutation_strategy,
                "confidence": mutated.confidence,
                "metadata": mutated.metadata,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            new_sidecar_path = _write_generation_file(
                workspace,
                mutated.generation_id,
                ".json",
                json.dumps(new_sidecar, indent=2, default=str).encode("utf-8"),
            )

            lines = [
                "MUTATE_EXPLOIT_RESULT: mutated",
                f"GENERATION_ID: {mutated.generation_id}",
                f"PARENT_ID: {mutated.parent_id}",
                f"SCRIPT_PATH: {new_script_path}",
                f"SIDECAR_PATH: {new_sidecar_path}",
                f"CONFIDENCE: {mutated.confidence:.2f}",
                f"MUTATION_STRATEGY: {mutated.mutation_strategy}",
                f"ATTEMPT_NUMBER: {attempt_number}",
                "",
                "SCRIPT_PREVIEW (first 500 chars):",
                mutated.script[:500],
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Exploit mutation failed — {exc}"

    # ───────────────────────────────────────────────────────────────────────
