# Deployment

How to stand up BreachPilot on a fresh operator box: supported platforms,
dependency installation, provider setup, nmap privileges, the WebUI build, and
running the API daemon as a service. Ends with runtime state layout, backup
guidance, and a production hardening checklist.

> [!WARNING]
> Attack mode ships as `full_access` (auto-approve, no content/scope
> inspection) with an unrestricted operator-box filesystem. Deploy only on a
> **throwaway lab VM** against targets you own or are explicitly authorized to
> test. See [`README.md`](../README.md#safety-and-containment) and
> [`docs/safety-model.md`](safety-model.md).

## Supported platforms

| Platform | Status | Notes |
|---|---|---|
| **Linux** | **Primary** | `./install.sh` one-shot bootstrap; full Kali arsenal (searchsploit, Metasploit, hydra, impacket) |
| Windows | Legacy / secondary | `install.bat` one-shot bootstrap; Python-only exploit tooling (no Kali arsenal) |
| macOS | Best-effort | `scripts/setup-linux.sh` covers it; untested as a primary platform |

The exploit agent's system prompt is OS-aware: Windows attackers get
Python-only exploits, Linux attackers get the full Kali toolkit
(README.md:262-263, config.yaml:90-95).

## Prerequisites

- **Python 3.11+** — `pyproject.toml:11` (`requires-python = ">=3.11"`).
  Note `main.py --doctor` rejects 3.10 and below (README.md:113).
- **`nmap`** on `PATH` (or set `nmap.path` in `config.yaml:63`).
- **Chat provider credentials** — the checked-in config selects OpenCode Go
  (`OPENCODE_GO_API_KEY`). Ollama is an optional chat provider; see
  [Ollama model availability](#ollama-model-availability) when selecting it.
- **Node.js + npm** — needed to build the SPA from a source checkout when
  `webui/dist/` is absent. Published Python wheels include the prebuilt SPA.
- Optional Linux arsenal: Metasploit, searchsploit/exploitdb, impacket, tmux.

## Install (step by step)

Checkout or pinned-tag install (what works today):

```bash
git clone https://github.com/braydos-h/BreachPilot.git
cd BreachPilot
./install.sh
```

or pinned to the published tag (reproducible, no history needed):

```bash
curl -fsSL https://github.com/braydos-h/BreachPilot/archive/refs/tags/v0.49.2.tar.gz -o breachpilot-v0.49.2.tar.gz
tar -xzf breachpilot-v0.49.2.tar.gz && cd BreachPilot-0.49.2 && ./install.sh
```

Versioned release assets (`install-<version>.sh` + `.sha256` + Sigstore
attestation, verified with `scripts/verify-installer.sh` before executing)
do not exist yet — the only GitHub release is the asset-less `beta` /
`v0.49.2` prerelease, so `releases/download/…` URLs 404 today. The release
workflow freezes those assets per tag on publish; from the first
asset-bearing release on, the bootstrap above becomes the pinned release
asset + checksum + attestation flow. The release-truth CI job curls every
URL in this section so a 404 can never ship again.

Dev path (`main|bash`) is dev-only with a warning — the easy path must be a
pinned artifact (today: the `v0.49.2` tag tarball; once published: the
versioned release asset), not mutable `main`. The release workflow publishes
both `install-<tag>.sh` and `install-<tag>.ps1` with separate checksums and
build attestations. Before running the Windows installer, download the
matching `.sha256` file and verify with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify-installer.ps1 .\install-v0.68.4.ps1
```

The verifier requires GitHub CLI attestation support by default. Use
`-ChecksumOnly` only when checksum-only verification is acceptable.

### Windows (one-click)

Windows is a supported secondary platform with Python-only exploit tooling.
**New users: double-click `install.bat` in Explorer** — no PowerShell
knowledge needed. From a terminal:

```powershell
# Easiest path (recommended for new users):
.\install.bat          # provider-aware setup, dependencies, WebUI, --doctor, launcher
.\START.bat            # after install: double-click to launch (WebUI at http://127.0.0.1:8765)
# Options: install.bat --check  (audit only), --yes (non-interactive), --help, --uninstall

# Manual alternative (if you prefer to do it step by step):
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"   # optional: dev extras (ruff + pytest + coverage)
python main.py --setup-api-keys
python main.py --doctor
python main.py --self-test
```

`install.bat` wraps `install.ps1` and is idempotent. The installer reads the
selected chat and embedding providers before deciding whether Ollama or model
pulls are needed. With the checked-in OpenCode Go + `embeddings.provider: none`
configuration it skips Ollama installation and model pulls for chat/embeddings;
research is configured separately and selects Ollama with SerpAPI fallback.
Configure `OPENCODE_GO_API_KEY`
through `python main.py --setup-api-keys` or the process environment before
`--doctor`. It also installs a `breachpilot` command to
`%USERPROFILE%\.local\bin` that always runs from the repo root. Uninstall with
`install.bat --uninstall`. `START.bat` is a double-click launcher that passes
args through (e.g. `START.bat --menu`).

### Linux (./install.sh one-shot)

```bash
# Fresh machine (no checkout needed): downloads the newest version into
# ~/.local/share/breachpilot. Safe to pipe: HTTPS-only, pinned repo/branch.
curl -fsSL https://raw.githubusercontent.com/braydos-h/BreachPilot/main/install.sh | bash
bp                        # launch from any directory; opens http://127.0.0.1:8765

# From an existing checkout:
./install.sh

# Full Kali arsenal (metasploit/searchsploit/hydra/impacket):
./install.sh --full
# (legacy env equivalent: INSTALL_KALI_TOOLS=1 ./install.sh)

# Option A: make (thin wrappers, Makefile)
make install         # venv + pip install -r requirements.txt (Makefile:14-16)
make install-dev     # venv + pip install -e ".[dev]" (Makefile:18-20)
make doctor          # python main.py --doctor (Makefile:22-23)
make self-test       # python main.py --self-test (Makefile:29-30)
make run             # python main.py (Makefile:47-48)
make test-one F=tests/test_scope_gate.py   # focused test (Makefile:44-45)
make clean           # rm -rf .venv + caches (Makefile:59-62)

# Option B: lightweight alternative (venv + deps + external-tool checks +
#           best-effort `ollama pull` + --doctor)
./scripts/setup-linux.sh

# Manual equivalent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

`./install.sh` is the primary path (OS prereqs + provider-aware optional
Ollama setup + venv + WebUI + `--doctor` + `bp`/`breachpilot` launchers;
`./install.sh --full` for the full Kali arsenal). With the checked-in config,
the active chat provider is OpenCode Go and provider-aware Flow A embeddings
are disabled, so installer Ollama/model setup is skipped. Research is a
separate surface and the checked-in config selects Ollama first with SerpAPI
fallback. On Linux, both installers key Ollama setup to
`models.provider`; if only `embeddings.provider` selects Ollama, install and
configure Ollama separately. The Windows PowerShell installer checks both
provider settings. `scripts/setup-linux.sh` is the lightweight
alternative: it checks for `nmap`, `ollama`, `tmux`, `searchsploit`,
`msfconsole`, `hydra`, and `impacket` and prints install hints for anything
missing (setup-linux.sh:42-48). It never installs or runs anything against a
target — host prep only.

#### Installer CLI (`./install.sh --help`)

| Option | Effect |
|---|---|
| `--update` | Atomic update of a managed install: newest Release → tag → `main`; staged build + validation, then swap with automatic rollback. Refuses dev checkouts unless `--allow-dev`. |
| `--version VERSION` | Pin an exact tag/branch/SHA instead of resolving newest. |
| `--install-dir PATH` | Managed-install location (default `~/.local/share/breachpilot`). |
| `--repair` | Recreate venv, reinstall deps, fix launchers/PATH, rebuild stale WebUI. Config + data untouched. |
| `--check` | Read-only diagnostics (platform/core/services/tools matrix). Changes nothing. |
| `--doctor` | Run `python main.py --doctor` against the install. |
| `--uninstall` | Remove app files + launchers + PATH block. Preserves user data (below). |
| `--minimal` / `--standard` / `--full` | Profiles: core only / +WebUI+recon (default) / +Kali+scanners+models. |
| `--with-kali-tools` / `--without-kali-tools`, `--with-scanners` / `--without-scanners` | Feature flags (override the profile). |
| `--with-chatgpt` | Opt-in ChatGPT provider runtime (bun + vendored openai-oauth). |
| `--skip-models` | Skip model pulls (same as `SKIP_MODEL_PULL=1`). |
| `--no-path` | Skip launchers and shell rc edits. |
| `--dry-run` / `--yes` / `--verbose` / `--quiet` | Preview / non-interactive / debug / minimal output. |

Exit codes: 0 ok · 1 failure · 2 bad args · 3 unsupported platform ·
4 preflight · 5 download/version · 6 validation · 7 update/rollback.

#### Version resolution

1. Explicit `--version`. 2. Latest stable GitHub Release. 3. Newest git tag.
4. Default branch (`main`) as a documented fallback. This repo currently
publishes no Releases, so the live path is tags → `main`. The installer
prints `Repository / Version / Commit / Install path / Source` for every
managed install and never silently installs an older version. Tarballs are
structure-validated after extraction; the exact commit SHA is recorded in
`.install-info`. No published checksums exist today, so authenticity rests on
HTTPS + the pinned `github.com/braydos-h/BreachPilot` origin — stated openly
in the script header, not hidden.

#### Update + rollback design

`--update` never touches the live tree until the new tree is proven:

1. Preflight (disk, network, sudo, Python ≥ 3.11). 2. Resolve newest ref.
3. Download the tarball into a `mktemp` staging dir; reject empty files,
invalid gzip, `..`/absolute paths; verify `main.py` + `pyproject.toml` +
`requirements.txt` + `tools/`. 4. Copy user data (below) into the staged
tree. 5. Full build inside staging (venv, pinned pip install, WebUI,
sandbox image). 6. Full validation (tree, imports, config parse, launcher,
WebUI bundle, `--doctor --json` core checks). 7. `cp -a` backup of the live
install. 8. Atomic swap (live aside → staged in). 9. Post-activation
validation (active provider/model checks, launchers, fresh `.install-info`; an
Ollama check runs only when the selected configuration needs it). 10. Drop the
backup only on success.

Any failure after step 7 restores the backup automatically (including on
SIGINT/SIGTERM via trap). A failed update leaves the previous installation
usable. `--update` inside a git checkout without `.install-info` is refused
— that directory is your development repo, not a managed install.

#### Persistent user data

These are copied into staged builds on update, staged out of the tree on
uninstall (restored to `<parent>/breachpilot-user-data`), and never
overwritten by a fresh install: `config.yaml`, `.env`, `secr.json`,
`.webui_secret_key`, `mission.yaml`, `reports/`, `research_workspace/`,
`exploit_workspace/`, `swarm_workspace/`, `api_runtime.db`, `logs/`.
Venvs, `__pycache__`, and `.install-info` are never carried across versions.
`--uninstall` removes managed app files, `~/.local/bin/{breachpilot,bp}`,
and the guarded PATH block only — system packages (Python, git, node, nmap)
are left alone.

#### Supported platforms

| Platform | Status |
|---|---|
| Kali Linux (x86_64/arm64) | Primary — full arsenal via `--full` |
| Debian / Ubuntu / Mint / Pop (x86_64/arm64) | Supported — Kali-only pkgs degrade to hints |
| macOS + Homebrew (x86_64/arm64) | Best-effort — no Metasploit/exploitdb |
| Other Linux / other arch | Refused with a clear message (exit 3) |

Requirements: Python ≥ 3.11 (`requires-python`, pyproject.toml:11), git,
curl, tar, Node 20.19+ (20.x), 22.12+ (22.x), or 24+ for the complete locked
WebUI build/test toolchain (Vite and installer checks accept Node 18+), Docker
(sandbox worker image only, default-on and fail-closed). nmap is core (doctor fails without it);
scanners/credentials/exploit binaries are optional per-tool. The installer
determines sudo needs upfront and never prompts mid-run after long work.

Troubleshooting: rerun with `--verbose`; read
`~/.local/state/breachpilot/install.log` (XDG_STATE_HOME respected, secrets
never logged — `GITHUB_TOKEN`/`OLLAMA_API_KEY` are redacted by construction).
Validate with `bp --doctor`. Installer tests: `pytest tests/test_install_sh.py`
(hermetic — isolated HOME, no host writes).

## Dependency installation: requirements.txt vs pyproject extras

- **`requirements.txt`** — header says "Synced from pyproject.toml": runtime
  deps **plus** the optional `ollama` extra **plus** the full `dev` extra
  (pytest, pytest-asyncio, pytest-xdist, pytest-timeout, coverage, ruff, mypy,
  build, twine), so `pip install -r requirements.txt` equals
  `pip install -e ".[ollama,dev]"`. Use this for a local checkout.
- **`pyproject.toml`** — separates runtime (`dependencies`, pyproject.toml:27-41)
  from optional extras (`[project.optional-dependencies]`: `ollama`,
  `browser`, `dev` — pyproject.toml:43-63). Use `.[dev]` or `.[ollama]` when
  packaging or when you want only a slice of the tooling.

**Keep the two in sync.** If you add a runtime dependency, add it to
`requirements.txt` **and** `pyproject.toml:dependencies`; extras go in both
files' extra stanzas (AGENTS.md "Toolchain notes"; getting-started.md:62).

```bash
python -m pip install -r requirements.txt    # local checkout (recommended)
python -m pip install -e ".[dev]"            # packaging / lint / coverage
```

## Ollama model availability

This section describes the optional Ollama chat provider. The checked-in
`config.yaml` selects OpenCode Go for chat; when you select Ollama, its
`ollama.host` setting defaults to the cloud endpoint and can point to a local
daemon instead.

| Setting | Default | Purpose |
|---|---|---|
| `ollama.host` (config.yaml:2) | `https://api.ollama.com` | Chat/generate endpoint |
| `ollama.model` (config.yaml:3) | `glm-5.2:cloud` | Default model spec |
| `ollama.api_key_env` (config.yaml:4) | `OLLAMA_API_KEY` | Env var for the cloud bearer token |
| `ollama.embed_host` (config.yaml:5) | `http://localhost:11434` | Local embeddings endpoint; falls back to `host` when absent |

- **Ollama Cloud:** when Ollama is the selected chat provider, export `OLLAMA_API_KEY` (or store via
  `python main.py --setup-api-keys` → `secr.json`, gitignored). Missing key
  surfaces as a 401 on the first chat. The ollama Python client auto-attaches
  `Authorization: Bearer $OLLAMA_API_KEY` to every request, so the host swap
  is the entire wiring — no probe, no local→cloud fallback (config.yaml:1-5).
- **Local daemon:** set `ollama.host: http://localhost:11434` and pull a
  local-weight model (e.g. `ollama pull gemma3:27b` — never a `:cloud` spec:
  cloud pulls only register a pointer). The `--doctor` model check runs a
  1-token generation to verify; local models report an `ollama pull <spec>`
  hint if missing (README.md:170-172). Cloud specs are verified with
  `ollama run <spec>` instead.
- **Embeddings are independent of chat.** The checked-in `config.yaml` sets
  `embeddings.provider: none`, which makes provider-aware Flow A memory/skill
  consumers issue no embedding requests and use keyword/tag fallbacks. Frozen
  Flow B still uses legacy Ollama semantic memory when enabled. The schema
  fallback when this key is omitted is `ollama`; if selected, `nomic-embed-text` uses
  `ollama.embed_host` (local by default), and the provider-aware installer can
  offer the model setup.

There is no `.env` auto-load — keys come from process environment variables or
`secr.json` (README.md:143-160).

## nmap requirements

`nmap` must be installed and on `PATH` (or set `nmap.path`, config.yaml:58).

- **Windows:** plain nmap works; `nmap.sudo`/`priv_fallback` are no-ops.
  Install from https://nmap.org/download.html or `winget install Insecure.Nmap`
  (`install.bat` offers this via winget when you approve).
- **Linux:** `-O`/`-sS` scans need root. Either set `nmap.sudo: true` (runs
  `sudo -n`), run as root, or leave `nmap.priv_fallback: true` (default) to
  auto-downgrade those flags instead of failing when unprivileged
  (config.yaml:57-60, README.md:138-139).
  `nmap.sudo` uses `sudo -n` (non-interactive), so it needs a NOPASSWD rule
  for nmap — enabling `nmap.sudo: true` without one fails every `-O`/`-sS`
  scan. Add a sudoers.d exception, e.g.:

  ```bash
  echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/breachpilot-nmap
  ```

  Verify the path first with `command -v nmap` and keep `nmap.priv_fallback:
  true` unless privileged scans must hard-fail instead of downgrading.
## WebUI build

The SPA is a Vite + React + TypeScript app under `webui/`. It is **not**
pre-built in the source repository — `webui/dist/` is gitignored and created
on demand. Release wheels install that build under the Python environment's
data prefix at `webui/dist`; `tools.paths.get_webui_dist_dir()` resolves it
when the app is launched outside a checkout.

- In a source checkout, the first `python main.py --web` run executes
  `npm ci && npm run build` in `webui/` when `webui/dist/index.html` is
  missing, then serves the SPA at `/` and opens `http://127.0.0.1:8765`.
- Release wheels contain the SPA under the install data prefix; both the
  `breachpilot --web` bootstrap and `create_app` resolve that copy through
  `tools.paths.get_webui_dist_dir()`, so an installed wheel serves it without
  Node.js or a repository checkout. `--rebuild` still needs the source tree
  and Node/npm. Build manually with `cd webui && npm install && npm run build`.
- Manual rebuild: `npm install`, `npm run dev` (port 5173, strictPort), `npm
  run build`, `npm run preview` (webui/package.json:6-10; webui.md:81-95).
- The built UI talks to `/api/v1` REST + WebSocket with bearer-token auth; see
  [`docs/api.md`](api.md) and [`docs/webui.md`](webui.md).

## Running as a service / daemon

`--demon` (alias `--daemon`) starts the local WebUI API daemon without the
SPA; `--web` additionally builds/serves the SPA and opens a browser.

```bash
python main.py --demon              # API on http://127.0.0.1:8765 (no SPA)
python main.py --daemon --api-port 9000   # alias, custom port
python main.py --web                # build + serve SPA + open browser
```

- Flags: `--demon`/`--daemon` (main.py:423-426), `--api-host`/`--api-port`
  (main.py:427-428).
- Config: `api.host` (default `127.0.0.1`), `api.port` (8765),
  `api.token_file` (`.webui_secret_key`), `api.allowed_origins`
  (config.yaml:444-449).
- Docs at `http://127.0.0.1:8765/docs`; OpenAPI at `/openapi.json`
  (main.py:546-547).
- Re-entrancy: a second daemon start detects the running instance and exits 0
  (main.py:497-525).

**Daemon-ize with the OS, not a flag:**

```powershell
# Windows: NSSM or a scheduled task
nssm install BreachPilot "C:\Users\BH\Documents\GitHub\BreachPilot\.venv\Scripts\python.exe" "C:\Users\BH\Documents\GitHub\BreachPilot\main.py" --daemon
```

```bash
# Linux: systemd unit
[Unit]
Description=BreachPilot WebUI API daemon
After=network.target

[Service]
WorkingDirectory=/opt/BreachPilot
ExecStart=/opt/BreachPilot/.venv/bin/python main.py --daemon
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Loopback-only binding security note

The API daemon is **loopback-only by design in v1 — there is no public-bind
override** (config.yaml:444-449). `--api-host` accepts only
`127.0.0.1`/`localhost`/`::1` and exits with code 2 otherwise (main.py:515-518),
and `create_app` re-validates via `assert_api_loopback` (tools/api/auth.py:30-36,
docs/api.md:73). Never tunnel it to a public interface; use a VPN if remote
access is required. The MCP HTTP servers have a separate two-person rule
(`--allow-public-bind` + `MCP_ALLOW_PUBLIC_BIND=1`, docs/mcp-tools.md:19).

## Directory layout for runtime state

All runtime state is gitignored (`.gitignore:22-26,37`):

| Path | Content | Created by |
|---|---|---|
| `reports/<run_id>/` | Per-run reports, logs, eval trees (`reports/eval/<run_id>/`) | CLI/daemon runs, `--eval` |
| `reports/api_runtime.db` | WebUI daemon run/decision state (SQLite) | `--demon`/`--daemon` |
| `reports/<run_id>/exploit_audit.jsonl` | Host-owned SHA256-chained audit trail, outside the worker mount | Attack runs |
| `exploit_workspace/<ip>/<attempt_id>/` | Per-attempt exploit files and outputs | Attack runs |
| `exploit_workspace/loot/` | Loot workspace (`exploit.loot_workspace`, config.yaml:89) | Attack runs |
| `research_workspace/<mission_id>/` | Flow B mission data (SQLite) | `cli.py` missions |
| `swarm_workspace/` | Swarm artifacts | Swarm runs |
| `webui/dist/` | Built SPA | First `--web` run |
| `.webui_secret_key` | Auto-generated API bearer token | First daemon boot |
| `secr.json` | Provider API keys | `--setup-api-keys` |

These directories are excluded from version control on purpose — treat them as
data, never as source.

## Backup / migration

To move or preserve an operator box, copy the runtime data **without** the
venv and build artifacts:

```bash
# What to keep (copy whole, preserving structure):
reports/              # run reports + api_runtime.db (daemon state)
exploit_workspace/    # audit chains + loot (tamper-evident records)
research_workspace/   # Flow B mission data
swarm_workspace/      # swarm artifacts
secr.json             # provider keys (encrypt this copy separately)

# What to regenerate, don't back up:
.venv/                # python -m venv + pip install -r requirements.txt
webui/dist/           # first --web run rebuilds it
.webui_secret_key     # regenerated; or re-set BREACHPILOT_API_TOKEN
```

Migration notes:

- `reports/api_runtime.db` is daemon state; if it is copied mid-run, the
  daemon's startup `recover_interrupted()` marks live runs `interrupted` and
  expires pending decisions (docs/api.md:170) — expected after a move.
- The API daemon is **single active run**; running two daemons against one
  copied `api_runtime.db` is unsupported.
- `secr.json` and `.webui_secret_key` hold credentials — back them up encrypted
  or regenerate them (`.webui_secret_key` is `0o600` where supported,
  docs/api.md:75).

## Production hardening checklist

Deployment-time verification for a box you intend to run for a while:

**Target allowlist (the one attack-mode lock)**

- [ ] `exploit.require_explicit_allowlist: true` (config.yaml:86)
- [ ] `exploit.allowed_targets` contains only authorized hosts/domains/CIDRs
      (config.yaml:87-88); runtime `--target` is unioned via
      `EXPLOIT_TARGET`, so confirm each run's target, don't rely on it
- [ ] Callback/C2 listener hosts added explicitly to `allowed_targets`
      (README.md:252)
- [ ] Understand the lock is a destination guard, not a sandbox
      (README.md:254-258); run on a throwaway VM
- [ ] `exploit.permission` set deliberately — `full_access` is the shipped
      default; `read_only` for propose-only recon, `approve_only` for a
      per-action banner (README.md:235-240, config.yaml:64)
- [ ] `exploit.forbidden_actions` / `disallowed_assets` reviewed (opt-out
      categories, config.yaml:89-90)

**Token auth (WebUI daemon)**

- [ ] Bearer token set explicitly via `BREACHPILOT_API_TOKEN` (precedes the
      auto-generated `.webui_secret_key`; docs/api.md:75, docs/api.md:935)
- [ ] `.webui_secret_key` perms `0o600` where supported
- [ ] `api.allowed_origins` left `[]` or loopback-only entries
      (config.yaml:449; non-loopback entries rejected by the config validator,
      docs/config-reference.md:24)
- [ ] `GET /health` is the only unauthenticated route (docs/api.md:12)

**Loopback bind**

- [ ] `api.host: 127.0.0.1` (config.yaml:446) — v1 refuses public binds
      (main.py:515-518, tools/api/auth.py:30-36); never port-forward it
- [ ] MCP HTTP servers run loopback-only unless the two-person rule
      (`MCP_ALLOW_PUBLIC_BIND`) is consciously invoked (docs/mcp-tools.md:19)
- [ ] `engine_mcp.host: 127.0.0.1` (config.yaml:56)

**Secrets & environment**

- [ ] `OLLAMA_API_KEY` (and optionally `NVD_API_KEY`, `GITHUB_TOKEN`,
      `SERPAPI_API_KEY`) set in the environment or `secr.json`, never in
      tracked files (README.md:151-157; `.gitignore:37-42`)
- [ ] No `.env`/`secr.json`/`.webui_secret_key` in git (`git status` clean of
      those paths)

**Operational**

- [ ] `python main.py --doctor` exits 0 and `python main.py --self-test`
      passes on the deploy target (README.md:164-172)
- [ ] Command timeouts in place (300s terminal / 300s python / 600s msf) —
      these are unconditional operational guards (README.md:260-263)
- [ ] `reports/` + `exploit_workspace/` backed up off-box (audit chain is the
      evidence record)
- [ ] Linux: `nmap.sudo`/`priv_fallback` decided for the deploy account
      (config.yaml:57-60)

## Deployment decision table

| Scenario | Recommendation |
|---|---|
| Windows operator, no Kali tools | `install.bat` (or venv + `requirements.txt`); Python-only exploits; embed host `http://localhost:11434` |
| Linux operator, full Kali arsenal | `./install.sh` (primary; `INSTALL_KALI_TOOLS=1 ./install.sh` for searchsploit/Metasploit/hydra/impacket; `scripts/setup-linux.sh` is the lightweight alternative); decide `nmap.sudo` |
| OpenCode Go chat (checked-in default) | Configure `OPENCODE_GO_API_KEY`; checked-in embeddings are disabled (`none`), while the schema fallback is Ollama |
| Ollama Cloud chat | Select `models.provider: ollama`, then configure `ollama.host: https://api.ollama.com` + `OLLAMA_API_KEY` |
| Air-gapped / local LLM | `ollama.host: http://localhost:11434`, pull local-weight models (e.g. `ollama pull gemma3:27b`) + `nomic-embed-text`; never a `:cloud` spec (cloud pulls only register a pointer); no API key needed |
| Headless service (API only) | `--daemon` (optionally `--api-port`), daemonized via systemd/NSSM; skip the SPA |
| SPA served locally | `--web` (builds `webui/dist/` once; requires Node/npm at build time only) |
| Long multi-hour campaigns | `--long-session` (config.yaml:319-326: real context window, 600s LLM timeout, checkpoints) |
| Benchmarking | `--eval` → `reports/eval/<run_id>/` (config.yaml:305-310) |
| Flow B research missions | `cli.py` + `mission.yaml`; state in `research_workspace/` (SQLite) |

## Release version bump

One command moves the advertised version everywhere — no hand-editing pins:

```bash
python scripts/bump-version.py 0.69.0
```

It updates `pyproject.toml` (`[project] version`), `tools/cli_args.py`
(`__version__`, re-exported by `main.py`), `webui/package.json` (`version`), and every installer pin
(`releases/download/vX.Y.Z` / `install-vX.Y.Z`) in `install.sh` and
`scripts/verify-installer.sh` (`README.md` / `docs/deployment.md` re-adopt
exact pins once release assets publish — today they install from the
published tag tarball because no release assets exist yet),
then verifies with the docs-truth `versions` check. Verify-only mode
(`python scripts/bump-version.py --check`) is the CI gate: the `lint` job
runs it plus `python scripts/docs_truth_audit.py --check versions`, and the
`release` workflow additionally refuses a tag whose `vX.Y.Z` disagrees with
the tree version — so bump (and commit) before tagging.

Why pinned versions instead of a `latest` redirect: the release workflow
freezes a versioned asset per tag (`install-<tag>.sh`), and a
`releases/latest/download/...` URL cannot address a versioned asset name.
From the first asset-bearing release on, the quick-start therefore pins the
exact version (managed by the bump script) and the checksum step verifies
that exact asset. Until then the quick-start pins the published tag tarball
instead, and the release-truth CI job (`scripts/check_release_urls.py`)
curls every install-section URL so a 404 can never ship again.

## Further reading

- [`docs/getting-started.md`](getting-started.md) — setup, first commands, dev loop
- [`docs/api.md`](api.md) — WebUI API daemon, auth, WS handshake
- [`docs/webui.md`](webui.md) — the SPA and its build/dev loop
- [`docs/safety-model.md`](safety-model.md) — permission model, allowlist, audit
- [`README.md`](../README.md) — config reference and CLI surface
