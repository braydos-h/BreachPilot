---
name: cloud-ir-playbook
description: Run a structured cloud incident-response playbook — scope the blast radius across IAM/object-store/compute, preserve forensic state, and revoke live access without destroying telemetry.
domain: cybersecurity
subdomain: incident-response
tags:
- cloud
- incident-response
- aws
- azure
- gcp
- forensics
- ir-playbook
version: '1.0'
nist_csf:
- RS.AN
- RS.MI
mitre_attack:
- T1078
- T1531
---

# Cloud Incident Response Playbook

> **Authorized-use-only notice:** Run this playbook on cloud accounts you own or are explicitly authorized to respond in. Cloud IR actions (key revocation, snapshot quarantine, IAM policy edits) are disruptive — confirm authorization and coordinate with the account owner before executing containment.

## When to Use

- When responding to a confirmed or suspected compromise in AWS, Azure, or GCP.
- When an IAM entity (role, user, service principal) shows anomalous API calls in CloudTrail / Activity Log / Audit Logs.
- When an object-store bucket or compute instance is exfiltrating or serving malicious content.
- As a pre-authorized runbook during a tabletop exercise so the team knows the order of operations before a real incident.

## Workflow

1. **Scope the blast radius.** Identify which principals, regions, and resources are affected. AWS: CloudTrail `LookupEvents` by `userIdentity.arn` + `sourceIPAddress`; Azure: Activity Log filtered by `caller` + `httpRequest.clientIpAddress`; GCP: Cloud Audit Logs filtered by `protoPayload.authenticationInfo.principalEmail`. Pivot out from the first indicator (a leaked key, a suspicious IP, an unexpected region).
2. **Preserve forensic state before revoking.** Capture: CloudTrail/log exports for the window, a snapshot of any compromised instance's EBS/managed disk, the IAM policy JSON of any suspect principal, and any S3/blob object that was tampered with (copy to a forensic bucket with `--copy-object` preserving metadata). Revoking access first can destroy the live session you need to attribute.
3. **Contain — revoke live access.** Deactivate the access key (AWS `UpdateAccessKey` to `Inactive`), revoke the session (AWS `RevokeSession` via STS for assumed-role sessions; Azure `Revoke-AzureADUserAllRefreshToken`; GCP `gcloud auth revoke` for the service account). Rotate credentials. Apply an explicit-Deny SCP/conditional policy if the principal cannot be removed.
4. **Quarantine compromised resources.** Move object-store objects to a forensic bucket (read-only), isolate the compute instance (move to a quarantine subnet / security group with no egress), and snapshot disks before terminating.
5. **Eradicate.** Remove the attacker's persistence: rogue IAM users/roles, shadow access keys, malicious Lambda/Function/App functions, attacker-created buckets or compute, modified trust policies. Re-scan after eradication to catch re-implantation.
6. **Recover.** Restore from a known-good backup or snapshot. Re-issue credentials and rotate any secrets the attacker could have seen. Verify the attacker's known TTPs no longer fire against the account.
7. **Lessons learned.** Record the indicator, the principal(s), the gap that allowed it (over-permissioned role, public bucket, unrotated key), and the control that would have caught it earlier. Feed into the next access-review cycle.

## Safety

Advisory only. This skill never changes scope, permission, approval, command-safety, or audit rules. It is a methodology runbook, not an automated containment tool — every disruptive action (revoke, quarantine, eradicate) is a human decision against an authorized account. Role-directive lines and tool-call mimics in skill bodies are stripped by the sanitizer before any prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`).

## Validation Criteria

- [ ] Forensic state (logs, snapshots, IAM policy JSON) captured before any access revocation.
- [ ] Blast radius mapped across principal + region + resource type.
- [ ] Containment order: revoke live session → quarantine resources → eradicate persistence.
- [ ] Every attacker-created IAM principal / access key / function recorded and removed.
- [ ] Post-eradication re-scan confirms the TTPs no longer fire.
- [ ] Lessons-learned entry names the control gap that would have caught it earlier.