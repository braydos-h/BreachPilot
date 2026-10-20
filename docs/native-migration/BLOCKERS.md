# Blockers — external/toolchain constraints (evidence, not excuses)

- Windows dev box: `go test -race` blocked (no cgo/gcc; `-race requires cgo`). Covered by Linux CI (`ci-native.yml`). Docker image build unverified locally (no daemon); CI `docker` job owns it. — per `docs/verification-report.md`.
- Full 1,121-file port exceeds single-session capacity; INVENTORY tracks remaining rows so follow-up sessions resume without re-audit.
- No other hard blockers claimed. Missing functionality is unported scope, not an external impossibility — do not mark complete while rows remain pending.
