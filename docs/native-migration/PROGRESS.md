# Progress — append-only log (newest last)

- 2026-10-20: Audit baseline recorded (1,121 py = tests 455 + tools 420 + skills 174 + root 24 + scripts 18 + plugins 15 + legacy 14 + .claude 1; native 49 Go + 5 Rust). PLAN/INVENTORY/PARITY/PROGRESS/BLOCKERS created. `internal/mcp` already implements engine/defensive/assessment servers (superset of migration-map pending claim) — pending row narrowed to missing `cmd/bp-mcp-*` binaries/wiring.
- 2026-10-20: Foundation fixes: `Dockerfile.native` go 1.23→1.24 (matches go.mod + CI), ADR-002 superseded by migration objective, zero-python gate added (`scripts/zero-python-gate.sh/.ps1` + `internal/zeropython` scanner + `zero-python-gate` CI job report mode). Gate report correctly shows pending (1,121 py remain) — strict mode fails by design until cutover.
- 2026-10-20: Next: swarm/campaign + MCP binaries + recon/intel slices in dependency order; verify `go test ./internal/zeropython/` + `gofmt` + `go vet` before commit.
