# CI pyramid — fast feedback, honest gates

Every code change gets a ~5–10 minute deterministic answer. Slower,
stochastic, and live-infrastructure answers arrive on their own cadence
and never masquerade as PR-green.

## Tier 1 — PR fast path (~5–10 min, `ci.yml`)

Required on every push/PR; all mocked/offline:

- `tests` (Python 3.11–3.13, `-m "not integration and not live_llm"`)
- `lint` (ruff check + format, shellcheck, MCP bare-except guard, god-file
  budget, config/YAML sync, requirements sync, doctor JSON, docs-truth audit)
- `types` (mypy whole-tree + strict hot files + debt gate)
- `package` (sdist + wheel build, twine check, installed-wheel smoke)
- `webui` (npm ci + build + vitest)
- `audit` (pip-audit + constraints-pin check)
- `coverage` (fail-under=80)
- `eval-unit` (in `eval.yml`, mocked eval/benchmark unit tests)

## Tier 2 — PR integration (~15–25 min, `ci.yml`)

Real containment, still deterministic:

- `sandbox` (build worker image + 7 sandbox test files against real Docker)
- `browser` (mocked browser unit + live-Chromium loopback integration)

## Tier 3 — Nightly autonomous lab (`eval.yml` schedule + `benchmark.yml`)

Stochastic and live: full oracle suite, repeated trials/seeds, multiple
models, sandbox-escape regressions, long sessions. Missing backend writes
an explicit `SKIPPED` report (`write_skipped_eval_report`) — never green.

## Tier 4 — Release gate (manual, pre-0.69)

Full matrix + 5–10 stochastic trials per scenario, installer matrix,
SBOM/signing/provenance, upgrade/rollback smoke. Enforced by #80; see
`todo/06-data-security-and-release/80-*.md`.

## Rules

- Full-suite verification is CI's job; locally run slices only
  (`-n 0`/`-n 2`, one file at a time, never bare `pytest tests/`).
- `SKIPPED`/`INFRA_ERROR` evaluation is never reported as success at any tier.
