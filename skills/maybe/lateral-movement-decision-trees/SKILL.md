---
name: lateral-movement-decision-trees
description: Decision-tree methodology for authorized lateral movement — gate each pivot on the target-IP allowlist, pick the movement primitive from the foothold type, and cap recursion depth.
domain: cybersecurity
subdomain: lateral-movement
tags:
- lateral-movement
- pivot
- decision-tree
- allowlist
- impacket
- pass-the-hash
version: '1.0'
nist_csf:
- PR.AC
mitre_attack:
- T1021
- T1550
---

# Lateral Movement Decision Trees

> **Authorized-use-only notice:** Lateral movement touches hosts beyond the initial foothold. Run only on networks you own or are explicitly authorized to assess, and only against hosts on the operator-approved target-IP allowlist. Pivoting to unauthorized hosts is a safety violation, not a technique gap.

## When to Use

- During an authorized internal engagement after an initial foothold is established and the scope explicitly permits bounded lateral movement.
- When deciding which movement primitive to attempt from a given foothold (shell type, credential set, host OS).
- As a pre-engagement planning aid so the operator and the assessor agree on the pivot depth cap and the allowlist before the engagement starts.

## Workflow

### Gate 0 — Authorization check (every pivot, before any technique)

Every pivot target MUST be on the operator-approved target-IP allowlist. This is the sole attack-mode safety in this repo: the target-IP lock is enforced in the MCP tool layer (`tools/mcp_shared._allowed_target_list` + `tools/mcp_tools/terminal._target_lock_block`), not in this skill. If the candidate host is not on the allowlist, stop — do not pivot. The allowlist supports domains + `*.wildcard` + CIDR by design; subdomain expansion auto-authorizes discovered hosts via `add_discovered_target`.

### Decision tree — by foothold type

1. **Foothold = interactive shell on Linux, with a credential set.**
   - Has SSH key? → `ssh -i key user@target` (port 22; check allowlist).
   - Has password? → `sshpass -p pass ssh user@target` (noisier; prefer key).
   - No credential but target has a known CVE? → escalate to the exploit branch, not lateral movement.
2. **Foothold = interactive shell on Windows, with a credential set.**
   - Has NTLM hash? → Impacket `wmiexec`, `smbexec`, `atexec` (pass-the-hash; SMB signing status matters — check first).
   - Has plaintext password? → Impacket `wmiexec` / `psexec.py`; CrackMapExec `--exec-method smbexec` for breadth.
   - Has Kerberos ticket? → `ticketer.py` + `smbexec.py -k` (pass-the-ticket; needs clock skew < 5 min).
   - Has a domain-joined shell? → `secretsdump.py` for DCSync if the foothold account is a domain admin.
3. **Foothold = web shell, no interactive shell.**
   - Target exposes SMB? → upload Impacket runner via the web shell, execute against the target.
   - Target exposes WinRM? → upload a Python WinRM runner, execute.
   - Target exposes only HTTP? → the web shell is the lateral primitive; enumerate the target's web apps for a second foothold.
4. **Foothold = existing session on a pivot host.**
   - Use the pivot host as a proxy (SSH `-L`, Chisel, ligolo-ng). The proxied tool still runs against the allowlisted target — the proxy does not widen scope.

### Decision tree — by credential type

| Credential | Preferred primitive | Fallback | Detection signal |
|---|---|---|---|
| SSH key | `ssh -i` | `ssh -i -J jump` | auth.log on target |
| NTLM hash | Impacket `wmiexec` | `smbexec` / `atexec` | 4624 logon, 4688 process |
| Plaintext password | `wmiexec` / `psexec.py` | WinRM if exposed | 4624, 4672 special privileges |
| Kerberos ticket | `smbexec.py -k` | `wmiexec.py -k` | 4769 TGS request |
| Domain-admin token | `secretsdump` (DCSync) | `krb5` golden | 4662 directory access |

### Recursion cap

`max_pivot_depth` (default 0 in this repo's config) bounds how deep a pivot chain can go. Depth 0 = single-IP lock (no pivoting); depth N = up to N hops. Every hop MUST re-check the allowlist (Gate 0). A depth cap of 0 is the safe default — the operator opts into bounded pivoting explicitly.

## Safety

Advisory only. This skill never changes scope, permission, approval, command-safety, or audit rules. The target-IP allowlist IS the lock; this skill is the decision methodology that runs on top of it. Role-directive lines and tool-call mimics in skill bodies are stripped by the sanitizer before any prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`).

## Validation Criteria

- [ ] Every pivot target verified against the allowlist before any technique.
- [ ] Foothold type drives the primitive selection (shell type + credential type).
- [ ] `max_pivot_depth` cap respected; no unbounded recursion.
- [ ] SMB signing status checked before pass-the-hash.
- [ ] Detection signal (event log ID) recorded per pivot for the blue-team debrief.