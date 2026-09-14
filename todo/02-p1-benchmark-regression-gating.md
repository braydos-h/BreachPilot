# P1 — Repair benchmark regression gating

Owner: _unassigned_  
Tracking issue/PR: _not created_  
Status: Blocked by green `main`

## Goal

Turn XBEN into a scheduled regression check that compares candidates against a
deliberately versioned baseline while exercising the same sandbox path used in
production.

## Assessed gaps

- `benchmark.yml` checks for a `schedule` event but has no schedule trigger.
- The live benchmark uses a save-baseline path instead of a regression-check
  path, so it can overwrite the standard it should compare against.
- Only four scenario directories were present: DVWA, Juice Shop,
  Metasploitable2, and vulnerable Kubernetes.
- A host-loopback victim is not naturally reachable from the worker's network
  namespace; disabling the sandbox would make the benchmark less representative.

## Tasks

- [ ] Add an actual scheduled trigger at an appropriate low-traffic time.
- [ ] Keep manual dispatch for diagnosis and deliberate baseline maintenance.
- [ ] Change routine benchmark execution to:
  candidate run → compare with versioned baseline → reject material regression.
- [ ] Move baseline updates into an explicit, reviewable workflow or command.
- [ ] Require the baseline change and its justification to appear in the same
  pull request when behavior expectations intentionally change.
- [ ] Create an isolated benchmark network shared by victim services and the
  sandbox worker.
- [ ] Pass only explicitly scoped, routable victim addresses to the worker.
- [ ] Confirm benchmark commands traverse the normal MCP, allowlist, and
  sandbox execution path.
- [ ] Preserve per-trial artifacts and oracle evidence on success and failure.
- [ ] Add scenario metadata for vulnerability family, expected objective,
  verification oracle, timeout, seeds, and required environment.
- [ ] Expand gradually to 10–15 high-quality scenarios covering the principal
  reasoning failure modes and attack families.
- [ ] Add a concise benchmark summary to pull requests and scheduled runs.

## Initial scenario priorities

- Credential discovery followed by correct credential reuse.
- Competing attack branches where only one is productive.
- A tempting false-positive path that must not be called compromise.
- Repeated tool failure requiring bounded replanning rather than looping.
- Multi-step exploitation that requires independent post-condition evidence.
- A policy-rejected action that must be replaced with an in-scope approach.

## Acceptance criteria

- The benchmark runs on its declared schedule.
- Routine runs cannot modify the committed/versioned baseline.
- Significant regressions fail the benchmark check.
- Baseline changes are deliberate, reviewed, and reproducible.
- Victims and sandbox workers communicate over an isolated, explicitly scoped
  test network without disabling the sandbox.
- The initial suite covers at least 10 well-defined scenarios before broad
  capability expansion resumes.

