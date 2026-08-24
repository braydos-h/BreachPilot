---
title: Attack Modules — Overview
package: tools/attack_modules
files: [base.py, registry.py, modules/*.py (15 modules)]
---

# Attack Modules — Overview

Pre-packaged exploit payloads the AI can call. Single-source discovery via `pkgutil.iter_modules` (`registry.py:21`).

## Base types (`base.py`)

| Symbol | Kind | Line | Notes |
|---|---|---|---|
| `ModuleContext` | dataclass | 13 | Input to `run(ctx)`; fields below |
| `ModuleResult` | dataclass | 75 | Typed shape; `to_dict()`/`to_result(d)` adapters |
| `AttackModule` | ABC | 236 | 15+ subclasses via `registry` |
| `ApplicabilityReport` | dataclass | 46 | `{score, reasons, penalties}` |
| `ModuleStatus` | Literal | 42 | `info|script_generated|success|failed|blocked` |

`ModuleContext` fields (`base.py:13`):

| Field | Type | Default | Purpose |
|---|---|---|---|
| `target_ip` | `str` | required | Target |
| `target_os` | `str|None` | | OS hint |
| `services` | `list[dict]` | `[]` | `{service, port, version}` |
| `cves` | `list[str]` | `[]` | CVE ids |
| `workspace` | `Path` | `exploit_workspace` | Per-attempt dir |
| `credentials` / `parameters` / `config` | ... | `[]`/`{}`/`None` | Post-exploit + config |
| `sessions`/`findings`/`hypotheses`/`evidence_refs` | ... | ... | Capability-upgrade compact state |
| `access_achieved` / `privilege_level` / `phase` | ... | ... | Runtime gating |

`ModuleResult` (`base.py:75`) carries `status, module, script, note, suggested_command/msf, shell_type, privilege_level, credentials_found, evidence/references, failure_class, retryable, confidence, produced_artifacts, follow_ups, unlocked_capabilities, extra`. `to_dict()` drops empty optionals; `to_result(d)` adapts legacy dict returns, merging `credentials`↔`credentials_found` (`base.py:169`).

## `AttackModule` (`base.py:236`)

| Attribute | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | `""` | Unique id |
| `description` | `str` | `""` | |
| `target_services` | `list[str]` | `[]` | Service names |
| `target_ports` | `list[int]` | `[]` | Ports |
| `required_cves` | `list[str]` | `[]` | CVEs |
| `target_versions` | `dict[str,list[str]]` | `{}` | Version pattern bonus +25 |
| `target_os_hint` | `list[str]` | `[]` | OS gate +30 |
| `destructive_ics` | `bool` | `false` | Requires `ics.allow_write && destructive_ics` |
| `requires` / `produces` | `list[str]` | `[]` | Artifact composition |
| `read_only` | `bool` | `false` | Doesn't mutate target |
| `cost` | `str` | `medium` | |
| `phase_hint` | `str` | `""` | Advisory |

Methods: `applicability(ctx)→int` (`base.py:285` – 0-100, ICS gate first, then +30 per service, +20 per port, +40 per CVE, +25 version bonus, +30 OS hint, capped 100), `applicability_explain(ctx)→ApplicabilityReport` (`:345`), `capability_record()→dict` (`:399`), `run(ctx)→dict` abstract, `_info_result(ctx, note, evidence, references, …)` (`:426`), `generate_python_script(ctx)`, `generate_dynamic_script(ctx, mutator)` (`:469` – uses `PayloadCrafter` via `registry._module_primary_service` for write/read coherence), `to_json()`.

## Module families (15 files, verified via `modules/` glob)

| File | Modules (all verified via AST) | Count |
|---|---|---|
| `ad.py` | `ADCSEnum, BloodHoundCollect, ResponderRelay, GoldenTicket, SMBSigningCheck` | 5 |
| `auth_creds.py` | `CredentialSpray, PasswordSpray, HashCrack, ASREPRoast, Kerberoasting, DCSyncAttack, ADLDAPEnum` | 7 |
| `crypto_jwt.py` | `JWTTamper` | 1 |
| `deserialize.py` | `DeserializeAttack` | 1 |
| `detection.py` | `DetectionCoverageProbe, LogSourceEnum, OPSECPostureReport` | 3 |
| `ics_iot.py` | `ModbusEnum, DNP3Enum, S7Enum, BACnetEnum, HMIDefaultCred, IoTDefaultCred, ModbusWriteCoil, ModbusWriteRegister, S7PlcStop, S7PlcStart` | 10 |
| `network_smb.py` | `SMBGhost, EternalBlue, SMBRelay, SMBNullSession, PassTheHash, DumpHashes` | 6 |
| `orchestrator_phases.py` | `TokenImpersonation, ServiceMisconfiguration, LateralMovement, ValidateFinding, LocalExploitSuggester` | 5 |
| `persistence.py` | `LinuxPersistence, WindowsPersistence, WebShellPersistence` | 3 |
| `privesc.py` | `LinuxPrivescCheck, WindowsPrivescCheck, SUIDEnumeration, KernelExploitCheck, ContainerBreakout, CloudPrivesc, K8sPrivesc, IMDSExploit, DockerSockEscape, S3BucketTakeover` | 10 |
| `services.py` | `RDPBlueKeep, FTPAnonymous, RedisExploit, ElasticsearchExploit, LDAPAnonymous, RDPExploit` | 6 |
| `ssh.py` | `SSHBruteForce, RegreSSHion, OpenSSHCVECheck` | 3 |
| `supply_chain.py` | `ExposedVCS, CICDMisconfig, DependencyConfusion, ArtifactExposure, SupplyChainRecon` | 5 |
| `synthesis.py` | `CVEToExploit, DiffPatchAnalysis, FuzzToExploit, WeaponizedExploit` | 4 |
| `web.py` | `Log4jRCE, BasicAuthBuster, APIFuzzer, WebShellUpload, SQLInjection, XSSScanner, SSTIProbe, GraphQLIntrospect, RaceRequest, TimingOracle, RequestSmuggling, SSRFProbe, XXEProbe, LFITraversal` | 14 |

Total: ~83 module classes across 15 files (verified via AST walk). See `registry.md` for discovery/ranking.

## Capability metadata (`base.py:279-399` + `registry.py:221-239`)

`requires`/`produces` name artifact kinds (`credentials`, `foothold`, `admin_priv`, `hash_artifact`, `user_list`, …) via `_artifact_present` (`base.py:58`). `capability_record()` is the machine-readable superset of `to_json()` for `query_capabilities`/`get_capability_details`; `find_producers(artifact_kind)` / `missing_prerequisites(mod, ctx)` in `registry.py`.

## ICS destructive gate

`destructive_ics=True` (4 write modules in `ics_iot.py`: `ModbusWriteCoil/WriteRegister`, `S7PlcStop/Start`) → `applicability` returns 0 unless `tools.attack_modules.modules.ics_iot._ics_write_allowed()` (`ics.allow_write && ics.destructive_ics`). `run()` also re-checks defense-in-depth.

## Config keys

| Key | Effect |
|---|---|
| `ics.allow_write` / `destructive_ics` | Write ICS visibility |
| `adaptive_exploits.enabled` / `max_mutations` | `generate_dynamic_script` |
| `memory.semantic_enabled` | Cross-mission learning in mutator |
| `recon.*` | `exploit_search` sources (NVD etc. separate) |

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_attack_modules.py` | yes | `applicability`, score caps, to_json |
| `tests/test_attack_modules_api.py` | yes | MCP `run_attack_module` wiring |
| `tests/test_new_modules.py` | yes | `web.py` new modules (XSS/SSTI etc.) |
| `tests/test_module_lint.py` | yes | `name` uniqueness, required fields |
| `tests/test_version_aware_ranking.py` | yes | `target_versions` +25 |
| `tests/test_module_capability_metadata_a.py` | yes | `capability_record` + `find_producers` |
| `tests/test_module_capability_metadata_b.py` | yes | `requires`/`produces` semantics |
| `tests/test_ics_iot_modules.py` / `test_ics_exploit.py` | yes | ICS gate + scripts |
| `tests/test_persistence_modules.py` | yes | Persistence scripts |
| `tests/test_supply_chain_modules.py` | yes | Supply-chain recon |
| `tests/test_ssrf_xxe_lfi_modules.py` | yes | SSRF/XXE/LFI |
| `tests/test_detection_modules.py` | yes | Detection coverage |
