# Python-elimination audit (honest status)

Goal: zero tracked first-party `.py` files; no Python to install/build/test/run.

## Current state: NOT ELIMINATED (by design, this phase)

- The Python tree (~1,121 files per audit) is still present. Deleting it now
  would destroy unported behavior (swarm, campaign, recon, reporting, eval,
  skills executors, sandbox netns, browser) with no native replacement.
- New native code (`cmd/`, `internal/`, `rust/`, `proto/`) does not import,
  spawn, or require Python. The Go daemon and Rust sidecar build and run
  without Python (Dockerfile.native installs none).
- Search for remaining execution references before each release:
  `python`, `python3`, `pip`, `pytest`, `uvicorn`, `.py` in Docker/CI/install
  paths. Active ones must be migrated or recorded as parity blockers.

## Active Python dependencies (must resolve before deletion)

- `pyproject.toml`, `requirements.txt`, `constraints-dev.txt` (packaging)
- `pytest` suite in `tests/` (~455 files; port to go test/cargo test)
- `ruff`/`mypy` config (replaced by gofmt/vet + cargo fmt/clippy)
- `scripts/*.py` codegen (catalogs, budgets, release gates)
- `skills/*/scripts/*.py` executors, `plugins/*/plugin.py` loaders
- `tools/sandbox/docker_backend` host `docker` argv (stays; it is not Python)
- `install.sh`/`install.ps1` venv+pip flows (replaced by native install)

## Rule

Do not delete Python files until the corresponding `docs/migration-map.md`
row is `done` AND covered by a passing native test. Historical docs may
mention Python; install/run docs must not require it.
