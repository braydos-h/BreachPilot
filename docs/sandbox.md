# Disposable Execution Sandbox

The sandbox is BreachPilot's **isolation boundary** for offensive execution.
Every attack command — arbitrary terminal commands, generated Python, exploit
tools, Metasploit — runs inside a hardened, disposable Docker worker instead
of on the operator host.

The worker boundary covers command execution. The MCP `write_python_file` tool
creates a new file under the run workspace only. It accepts a bare filename,
uses a unique attempt directory, refuses absolute and nested paths, and does not
overwrite an existing file. The kernel writer traverses from a pinned workspace
directory descriptor and refuses symlink traversal. Workspace reads remain
contained and vault keyfiles/listings are redacted. See
[safety-model.md](safety-model.md) for the per-operation contracts.

```
LLM/MCP tool → BreachPilot policy/scope checks → disposable sandbox → target
```

This document distinguishes the two layers the rest of the safety docs refer
to, lists the exact security invariants, and documents residual risks.

## The two layers

> Commands are scope-checked at the application layer, while the sandbox network boundary independently enforces the effective destination allowlist.

| Layer | Controls | Role |
|---|---|---|
| **Application controls** (defense-in-depth) | ScopeGate, `@require_allowlist` decorators, destination parsing (`command_analyzer`, `_target_lock_block`), mission policy, `exploit.forbidden_actions` | Decide *what may be attempted*, inspect command strings and targets (best-effort: shell is too expressive for exhaustive static extraction) |
| **Isolation boundary** (containment) | Disposable worker container, cap-drop + no-new-privileges, read-only rootfs, resource limits, netns egress firewall, host filesystem isolation | Decide *what can physically be reached or damaged* |

**Docker alone does not make exploitation safe.** The application layer can be
confused by encoded destinations, by destinations that never appear on the
command line, or by dynamic resolution inside a script. The sandbox network
policy is independent of the command string: it authorizes concrete IPs/CIDRs
at the packet level and DROPs everything else.

## Lifecycle

One worker per attack run/session (`tools/sandbox/manager.py`):

1. **create** — `docker create` + `start` a hardened worker (never reuse
   existing containers; containers are labeled `breachpilot=true`,
   `run_id=<id>`)
2. **configure network policy** — an ephemeral `NET_ADMIN` sidecar sharing the
   worker's network namespace installs a default-DROP `iptables`/`ip6tables`
   ruleset authorizing ONLY the effective target allowlist (plus pinned research
   hosts only when `allow_research_hosts` is explicitly enabled; default off)
   (before the first agent command)
3. **mount run workspace** — `exploit_workspace/<run>/` binds at `/workspace`
   (the only host path the worker can see)
4. **execute** — all attack tools run inside the worker
5. **collect evidence** — artifacts persist via `/workspace` (reports, audit,
   WebUI artifact viewer, loot all read the same run workspace)
6. **terminate processes** — `docker stop` (inner `timeout` TERM→KILL per
   command is the first bound)
7. **destroy** — container + dedicated bridge network removed on normal
   completion, exception, timeout, cancellation, and interpreter shutdown
   (atexit). Teardown is idempotent query-then-delete: `network inspect`
   resolves the canonical ID (name vs ID confusion), "No such network /
   container" maps to success (delete-after-delete succeeds), "has active
   endpoints" (container still detaching) retries with backoff after a
   best-effort forced disconnect, and any other error audits incomplete
   cleanup without ever falling back to host execution.

Stale exited BreachPilot-labeled containers and empty labeled networks are
swept at MCP server startup (running workers of concurrent sessions are kept).

## Worker hardening

Enforced in `tools/sandbox/docker_backend.py::_build_create_args` (unit-tested):

- `--cap-drop ALL` with no capability added back. `NET_RAW` stays disabled
  because `AF_PACKET` sockets can bypass IP firewall rules. **`NET_ADMIN` is
  never granted to the worker** — the firewall sidecar alone receives it.
  Nmap uses connect scans (`-sT`) inside the worker.
- `--security-opt no-new-privileges`, non-root user (`--user sandbox`),
  `--privileged` never.
- `--read-only` rootfs (default) + `--tmpfs /tmp`; `/workspace` is the only
  writable bind.
- `--memory`/`--memory-swap`/`--cpus`/`--pids-limit` per config.
- Dedicated per-run bridge network (`network_mode` is never `host`; `pid_mode`
  and `ipc_mode` are never `host`; no devices).
- **No** `/var/run/docker.sock`, no SSH agent sockets, no home-directory
  mounts, no arbitrary host paths.

## Network containment (fail closed)

`tools/sandbox/policy.py` derives the concrete egress allow set from the same
allowlist sources the application layer uses (`exploit.allowed_targets` +
`EXPLOIT_TARGET*` env vars):

- **IPs / CIDRs** — authorized verbatim.
- **FQDNs** — resolved **host-side** by BreachPilot, validated against the
  allowlist, resolved IPs added to the firewall authorization, and the
  domain→IP mapping recorded in the audit trail. The worker never performs
  arbitrary DNS-driven egress.
- **`*.wildcard` domains** — authorize nothing statically; only their
  dynamically discovered, separately allowlist-validated resolved IPs apply.
- **`localhost`/`127.0.0.1`** — sandbox loopback only (container `lo`). Host
  loopback is reachable ONLY with the explicit dev opt-in
  `sandbox.network.map_host_loopback: true`; production attack mode must not
  enable it.
- **Everything else is DROPped**: arbitrary internet hosts, host LAN devices,
  cloud metadata (`169.254.169.254`, link-local, AWS IMDS IPv6, Alibaba),
  the Docker bridge gateway (path to host-published services and the Docker
  daemon), and unrelated containers. Worker DNS packets are blocked in both
  `controlled` and `none` modes. `controlled` installs host-resolved,
  allowlist-pinned names in worker `/etc/hosts`; `none` disables those mappings.

Policy-denied packets route through `NAI-DROP`, whose terminal rule is
`-A NAI-DROP -j DROP`; this preserves the default-deny behavior while giving
the trusted sidecar one cumulative packet counter to read. Policy refreshes
flush only `NAI-OUTPUT` with `iptables-restore --noflush`, so they do not reset
that counter. IPv6 has the same default-deny and counting behavior.

### Why a sidecar, not worker NET_ADMIN

`tools/sandbox/network.py` runs `iptables-restore`/`ip6tables-restore` from an
ephemeral `--rm` sidecar container that shares the **worker's** network
namespace and holds the only `NET_ADMIN` grant. Docker drops the grant when
the sidecar exits. A short-lived NET_ADMIN sidecar also reads the firewall
counter after the worker is stopped; the worker itself runs `--cap-drop ALL` with no capability
added back, so agent commands — even as root inside the container — cannot
modify the firewall or open `AF_PACKET` sockets that bypass its IP rules. Nmap
uses connect scans (`-sT`) inside the worker. Rules are (re-)applied at each
command boundary when the authorization fingerprint changes (dynamic target
pickup), always host-driven.

The run result's `scope_violations_network` value is the sum of IPv4 and IPv6
`NAI-DROP` packet counters. It measures **blocked off-scope egress packets**,
including repeated retries; it does not count unique actions and does not mean
packets escaped containment. The sideband measurement is written outside the
worker's `/workspace` mount after teardown. Failed reads, interrupted worker
lifecycle, failed sideband writes, and overlapping commands produce `null`,
never a default zero. A measured zero means both firewall families were read
successfully after a complete run.

## Fail-closed behavior (with one boot-time fallback)

Any failure DURING an active session **blocks offensive execution** and
returns a structured `SANDBOX_*` result block (never a per-command host
fallback):

| Code | Trigger |
|---|---|
| `SANDBOX_UNAVAILABLE` | Docker daemon died after boot, worker start failed |
| `SANDBOX_POLICY_FAILED` | netns firewall could not be installed |
| `SANDBOX_SCOPE_DENIED` | target outside allowlist, or empty allowlist with `require_explicit_allowlist: true` |
| `SANDBOX_WORKSPACE_FAILED` | workspace missing/symlink/path escape |
| `SANDBOX_UNSUPPORTED` | operation has no sandbox-safe implementation (documented; never auto-host) |

Invariant: `require_explicit_allowlist: true` + empty effective allowlist ⇒
**DENY all target-touching execution** (enforced in `tools/kernel/allowlist.py`,
the sandbox scope gate, and the empty netns policy simultaneously).

Network firewall enforcement and fail-closed behavior are mandatory. The
configuration parser rejects `network.enforce: false` and
`network.fail_closed: false`; a firewall install failure blocks execution
(`SANDBOX_POLICY_FAILED`), writes a blocked audit row, and destroys partial
resources. There is no unfirewalled degraded mode.

There is no host-execution fallback. `SandboxConfig.from_config` rejects
`sandbox.enabled: false` and `sandbox.fallback_native: true`; the latter key is
retained only for configuration compatibility and accepts `false` only. If
Docker or the worker image is unavailable at startup, the server records a
`blocked` posture and attack execution returns structured `SANDBOX_*` blocks
until containment is available. The historical function name
`resolve_manager_with_fallback` remains for import compatibility, but it
always returns a sandbox manager and an empty notice; it never selects native
execution. The session posture recorded at startup does not change if Docker
later becomes available or unavailable.

## What runs where

| Tool | Runs |
|---|---|
| `run_exploit_terminal`, `run_as_root` (container root), `git_clone` | sandbox |
| Generated Python (`run_python_file`) | sandbox (never the operator's interpreter) |
| nmap / masscan / rustscan | sandbox |
| curl / wget | sandbox |
| sqlmap / nikto / gobuster-class scanners | sandbox |
| Metasploit (`msfconsole`) / msfvenom | sandbox |
| Impacket / SMB tooling | sandbox |
| hashcat / john | sandbox when the worker image provides them (GPU passthrough is out of scope; document CPU-only runs) |
| Exploit scripts / general terminal commands | sandbox |
| Browser ops (`browser_*`: navigate/observe/screenshot/JS) | sandbox browser worker (`breachpilot-sandbox:browser`: base worker + Playwright/Chromium; one Chromium op per docker exec, strict fail-closed — never host fallback) |
| MCP recon TCP tools (`check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint`) | sandbox worker; DNS is pinned before Nmap argv, worker errors fail closed |
| MCP UDP recon (`run_udp_recon`) | unsupported; no worker or host scan starts because the worker drops `NET_RAW` |
| MCP passive OSINT (`run_osint_recon`) | operator process; fixed public providers only, bounded time and resolver concurrency, no active target connection |
| Direct in-process `ReconPipeline` callers | operator process (legacy scanner/socket path; scope checks do not place this traffic inside the worker firewall) |
| PoC verifier (`poc_verifier`) compile gate | host docker (isolated, network `none` — pre-existing separate mechanism) |

Tools absent from the worker image surface as missing-tool warnings from
preflight; extend a derived image (`FROM breachpilot-sandbox:latest`) for
mission-specific tooling. Do not add host fallbacks.

### Planned families

`tools/sandbox/family_audit.py` also carries `PLANNED_FAMILIES` — tool
families whose architecture exists but whose execution is not implemented
(empty today: the **browser** family graduated to `SANDBOXED_FAMILIES` when
the Playwright backend landed — Chromium runs one op per docker exec inside
the worker netns via `SandboxPlaywrightLauncher`, obeying the effective
target allowlist with no host fallback). Planned families emit no audit rows
and never count as audit problems (see `tests/test_browser_sandbox_family.py`).
Design: [docs/browser-agent-design.md §8](browser-agent-design.md).

To run the browser agent contained, point the worker at the browser variant
(a strict superset of the base image, so terminal/Python execution is unchanged):

```bash
docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox
```

## Worker image

`docker/sandbox/Dockerfile` — Debian slim + python3, nmap, curl/wget,
netcat, git, iproute2, iptables (needed by the firewall sidecar), openssh
client, and recon helpers. No secrets, API keys, repo credentials, or user
configuration are baked in. Rebuild/upgrade independently:

```bash
docker build -t breachpilot-sandbox:latest docker/sandbox
```

### Optional Docker daemon lifecycle

Set `sandbox.auto_manage_docker: true` to keep Docker stopped while BreachPilot
is idle and have the sandbox session start it on demand. The controller never
claims or stops a daemon that was already running. On exit it stops Docker only
when BreachPilot started it and `docker ps` reports no running containers, so
other local workloads are left alone. On Linux it uses `sudo -n`; run
`sudo -v` before starting BP if your sudo policy requires a password. If the
service cannot be started, execution remains blocked until the sandbox is
available.

The feature is enabled in the shipped local `config.yaml`, but it is disabled
by default in the schema for deployments that should never manage a host
daemon. `bp --doctor` and the WebUI daemon do not start Docker; only an exploit
MCP sandbox session acquires it.

## Secrets & environment

The worker never receives the host environment. It gets a fixed set of sandbox
markers, an allowlist of run-context keys (`EXPLOIT_TARGET*`, model host), and
operator-configured `sandbox.env_passthrough` names. Audit payloads are
secret-free by construction and existing redaction (`tools/kernel/audit.py`)
still applies to command text.

## Auditing

Every sandbox execution writes to the host-owned `exploit_audit.jsonl` outside
the worker's writable `/workspace` bind. RunService stores it at
`reports/<run_id>/exploit_audit.jsonl`; direct and benchmark callers store it
beside their worker workspace. The worker cannot truncate, replace, or append
to this operator audit file. Rows contain a `sandbox` context: run id,
container id, image, user, env keys, network-authorization
decision (authorized destinations, explicit blocks, resolved domains,
unresolved targets, fingerprint), exit code, timeout, duration, and a cleanup
audit row on destroy.

## WebUI / API

`GET /api/v1/system/sandbox` (bearer-auth) reports enabled/backend/image/user,
rootfs mode, the effective posture (`mode`: `contained` or `blocked`, from
the recorded startup decision — a session's posture never flips mid-run even
if Docker state changes afterwards), the deprecated compatibility field
`fallback_native` (always `false`), the failure reason (`fallback_reason`),
live Docker reachability, worker-image presence (`image_present`, null when
unknowable), network policy posture, resource limits, and cleanup flags.
Invalid legacy settings (`enabled: false` or `fallback_native: true`) are
reported as `blocked`. The WebUI home screen renders a contained status line
or a blocked warning with a remediation action. The System UI (Settings →
Advanced → Sandbox) renders the same with a build hint when the worker image
is missing.

`GET /api/v1/runs/{run_id}/sandbox` (bearer-auth) summarizes a run's sandbox
activity for the run page's Sandbox tab, derived read-only from run artifacts:
container identity and config echo (exploit_audit.jsonl `sandbox` rows), the
last network-authorization policy (authorized/blocked destinations, resolved
domains, fingerprint), execution status counts (cleanup rows excluded), and
the last five SANDBOX_* blocked commands with reason codes (from tool_result
events). Both endpoints are read-only — the WebUI never exposes Docker
exec/remove controls; sandbox lifecycle belongs to the run engine.

## Doctor

`python main.py --doctor` checks the Docker CLI, daemon, and worker image.
Unavailable containment is reported as a failed check because attack
execution will be blocked until Docker and the image are ready.

## Configuration

Canonical defaults are generated from `CONFIG_SCHEMA`: see [generated/safety-defaults.md](generated/safety-defaults.md) (via `scripts/generate_safety_defaults.py`). The yaml below echoes those values — do not hand-edit defaults here without updating the schema.

```yaml
sandbox:
  enabled: true                # mandatory; false is rejected
  backend: docker
  image: breachpilot-sandbox:latest
  fallback_native: false       # deprecated compatibility key; true is rejected
  user: sandbox
  read_only_rootfs: true
  env_passthrough: []          # extra host env var names the worker may receive
  resources:
    memory_mb: 4096
    cpus: 2
    pids: 512
    timeout_seconds: 300       # per-command default
    output_max_bytes: 2000000
    tmpfs_size_mb: 256         # /tmp tmpfs size (MB, min 64)
  network:
    enforce: true              # mandatory; false is rejected
    fail_closed: true          # mandatory; false is rejected
    allow_dns: controlled      # pinned host mappings; worker DNS packets blocked in both modes
    map_host_loopback: false   # dev-only host-loopback mapping
    extra_allow_cidrs: []      # operator-authorized extra CIDRs
    allow_gateway: false       # keep false (gateway = path to Docker daemon)
    allow_research_hosts: false # pinned github/gitlab egress, opt-in only (default deny)
  cleanup:
    remove_on_exit: true
    remove_stale_on_startup: true
  multi_net_raw: false         # true is rejected; raw sockets bypass the IP firewall
```

The worker's `/tmp` is a tmpfs sized by `sandbox.resources.tmpfs_size_mb` (default 256m, minimum 64m; invalid values fall back to the default, never to host execution). Raise it when staging msfvenom payloads or spilling large wordlists to `/tmp`; the `rw,noexec,nosuid` flags stay fixed regardless of size.

## Threat model coverage

| Threat | Mitigation |
|---|---|
| Reach unauthorized public IP | netns default-DROP egress; only allowlist ACCEPTs |
| Reach another LAN host | same (RFC1918 is not blanket-allowed; authorization is the boundary) |
| Reach cloud metadata | explicit DROPs for 169.254.169.254, link-local, IMDS IPv6, Alibaba |
| Access Docker daemon | no docker.sock mount; bridge gateway DROPped |
| Read host filesystem | only validated workspace bound; read-only rootfs; no privileged |
| Fork bomb / resource abuse | pids-limit, memory/swap, cpus, per-command timeout |
| Background processes outliving run | `docker stop` + container destruction on exit/atexit |
| Persistence from worker commands | worker has no host writes outside workspace; disposable container/network. `write_python_file` also writes only under the run workspace. |
| Bypass destination parsing | policy independent of command string (destinationless script test) |
| Python socket hidden egress | same firewall (integration-tested) |
| Encoded IPs | enforcement at packet layer (integration-tested with hex-decoded IP) |
| DNS destination switch | host-side controlled resolution; resolved IPs validated + audited |
| Reach host services via gateway | gateway DROPped unless explicitly configured |
| Tamper with firewall from inside | NET_ADMIN lives only in the ephemeral sidecar |

## Residual risks (documented, not hidden)

- **Docker itself** is the trust base: a Docker daemon/container-escape
  vulnerability defeats the boundary. Keep Docker updated; the sandbox raises
  the bar but is not a VM.
- **`map_host_loopback: true`** intentionally maps sandbox loopback targets to
  the host gateway — dev/lab only.
- Network enforcement and fail-closed behavior are mandatory; explicit false
  values are rejected during configuration parsing.
- **`allow_research_hosts: true`** (opt-in only, default false) authorizes pinned research
  egress (github.com et al.) — a fixed, auditable list; leave false for
  target-only/air-gapped missions.
- **`extra_allow_cidrs`** widens the boundary by configuration; operator
  responsibility.
- **Raw packet scans** are unavailable because `NET_RAW` is not granted. Nmap
  uses connect scans so raw Ethernet frames cannot bypass the IP firewall.
- **Direct in-process `ReconPipeline` callers remain outside the worker
  boundary.** This legacy library API can run Nmap, RustScan, Masscan, socket
  probes, and secondary enumerators from the operator process; its scope
  checks do not install the worker firewall. The target-active MCP TCP recon
  tools, `start_autonomous_campaign`, `run_campaign_step`, Flow A campaign
  runs, and `spawn_subagent(phase="recon")` use the shared
  `sandbox_recon_host` adapter. It validates and pins the destination before
  worker execution and fails closed if the worker is unavailable; these paths
  do not fall back to the in-process pipeline.
- **Domain discovery still has bounded host-side egress.** Campaign domain
  expansion fetches certificate-transparency results from `crt.sh` and
  resolves a capped set of candidate subdomains from the operator process.
  This is separate from target TCP scanning, which remains inside the worker.
- **Windows/macOS** run via Docker Desktop; the netns firewall applies inside
  the Linux VM. If strong containment cannot be guaranteed on a platform, the
  sandbox fails closed (`SANDBOX_*`) rather than falling back to host
  execution.
- On-container root (`run_as_root`) is container-root only — confined by
  cap-drop, no-new-privileges, the netns firewall, and the workspace bind.
