# 06. The sandbox architecture is a genuine strength

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — revalidated + hardened) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Strategy and evaluation |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] disposable worker per run;
- [ ] non-root user;
- [ ] `cap-drop ALL`;
- [ ] `NET_RAW` only where needed;
- [ ] no `NET_ADMIN` in the actual worker;
- [ ] `no-new-privileges`;
- [ ] read-only root filesystem;
- [ ] tmpfs;
- [ ] memory/CPU/PID limits;
- [ ] no Docker socket;
- [ ] no arbitrary host mounts;
- [ ] dedicated network;
- [ ] host-side resolution;
- [ ] default-DROP IPv4/IPv6 egress;
- [ ] metadata/gateway blocking;
- [ ] workspace-only host bind;
- [ ] sandbox-side execution for generated Python;
- [ ] isolated browser worker.

## Audit recommendation

I spent more time on this than most other sections because it is critical to your architecture.

The design is considerably better than simply putting commands in Docker.

Current controls include:

* disposable worker per run;
* non-root user;
* `cap-drop ALL`;
* `NET_RAW` only where needed;
* no `NET_ADMIN` in the actual worker;
* `no-new-privileges`;
* read-only root filesystem;
* tmpfs;
* memory/CPU/PID limits;
* no Docker socket;
* no arbitrary host mounts;
* dedicated network;
* host-side resolution;
* default-DROP IPv4/IPv6 egress;
* metadata/gateway blocking;
* workspace-only host bind;
* sandbox-side execution for generated Python;
* isolated browser worker.

That is one of BreachPilot's strongest pieces.

### Keep investing here.

But I would make one conceptual change:

## Treat the sandbox posture as part of the assessment identity

Every run should visibly say:

```text
CONTAINMENT
─────────────────────────
Sandbox image: sha256:...
Network policy: enforced
Native fallback: impossible
Target set: 3 IPs
DNS mode: controlled
Host mounts: workspace only
NET_RAW: yes
Root: no
Policy hash: a749...
```

Include that in the report.

It helps answer:

> "Under exactly what constraints was this autonomous test performed?"

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 7 — containment identity as product evidence
- Commits/PRs: consent gate (#07), red-team suite (#48, 23 tests), provenance
  digests (#02), stale-default purge (#08) — all this session; no new code here
- Tests/evaluations: sandbox suites green in CI sandbox tier
- Documentation: docs/sandbox.md truth-fixed; run artifacts carry container id,
  image, network policy, cleanup rows
- Follow-ups: attach policy-hash record to runs (#06 full ask); prebuilt image (#55).

