# Release Checklist (Acceptance Gates)

No release goes out unless every gate below is green. Each gate names the
exact command; "green" means the stated exit/status, not "looks fine".

## 1. Mocked test suite (slices only)

Full-suite verification is CI's job. Locally, run one file at a time —
never bare `pytest tests/`, never `-n auto`/`-n 4+`, never `-m` overrides
(the default deselects `integration`/`live_llm` on purpose; see gate 5).
Rule source: `AGENTS.md` test-run rules.

```bash
python3 -m pytest tests/test_scope_gate.py -v -p no:cacheprovider -n 0   # one file (preferred)
python3 -m pytest tests/test_recon_pipeline.py::TestClass::test_method -n 0  # one test
```

Green: every slice exits 0. `-n 0` or `-n 2` max. Never run slices in
parallel across sessions (the operator laptop logs out on big runs).

## 2. Lint: ruff check + format

```bash
ruff check .                # must pass: 0 errors
ruff format --check .       # must pass: 0 diffs
```

Green: both exit 0, repo-wide. Per-file ignores document intentional
patterns (`pyproject.toml`); do not add heavy presets to quiet new code.

## 3. Types: mypy over tools/

```bash
mypy --follow-imports=skip tools   # must pass: 0 errors (with the documented disables)
```

Green: exit 0. Strict subsystems (`tools/validation_utils.py`,
`tools/exceptions.py`, `tools/mcp_shared.py`, `tools/kernel/*`,
`tools/sandbox/*`) carry zero disables; type-debt must not grow
(`python scripts/mypy_debt.py`, CI `types` job).

## 4. Coverage

```bash
python3 -m coverage run -m pytest tests/ -q -m "not integration and not live_llm"
python3 -m coverage report --fail-under=80
```

Green: report exits 0 (`fail_under = 80`, `pyproject.toml`). CI runs the
same pair in the `coverage` job and uploads the XML.

## 5. Integration / live_llm deselected by default

`pyproject.toml` ships `addopts = ["-m", "not integration and not live_llm"]`.
Docker-backed integration and live-LLM evals are opt-in only:

```bash
python -m pytest tests/test_browser_integration.py -v -m integration   # explicit single-file opt-in
```

Green: a bare local/CI run selects zero `integration`/`live_llm` tests.
New tests needing Docker, network, or API keys must carry the matching
marker, or they run (and fail) everywhere.

## 6. Docs truth

```bash
python scripts/docs_truth_audit.py --check versions   # versions single-sourced, installer pins current
python scripts/bump-version.py --check                # pyproject == tools/cli_args.py (__version__, re-exported by main.py) == webui/package.json == pins
python scripts/docs_truth_audit.py                    # links + versions (CI lint job runs this too)
python scripts/generate_config_reference.py --check   # generated config reference matches schema + config.yaml
python scripts/generate_safety_defaults.py --check    # generated safety defaults match schema
```

Green: all exit 0. README flags/config match `config.yaml`;
`pyproject.toml`/`requirements.txt` stay in sync (CI checks this);
release tags additionally require tag == tree version
(`release` workflow `Version truth` step — bump with
`python scripts/bump-version.py X.Y.Z` before tagging; sequence documented
in `docs/deployment.md`).

## After the gates

`python scripts/release_gate.py` (the beta GO/NO-GO contract: versions,
CI tiers, safety defaults, red-team suite, provenance, docs contract) must
print `GO`. Anything `EXTERNAL` stays NO-GO until a maintainer provisions
the evidence (eval provenance, sandbox digest, branch ruleset).

See also: `docs/release.md` (beta gate + artifacts), `docs/testing-guide.md`
(how to run tests), `docs/safety-model.md` (what the gates protect).
