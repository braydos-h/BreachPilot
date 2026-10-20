package mcpserve_test

// Slice 3 RED: shared MCP binary wiring must dispatch transports, enforce
// the loopback gate, verify config fingerprints, and build runnable servers
// from a config file — before the implementation exists.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/mcpserve"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const testCfg = `api:
  host: 127.0.0.1
  port: 8765
models:
  provider: ollama
  default_alias: glm
  registry:
    glm: glm-5.0:cloud
exploit:
  allowed_targets: [127.0.0.1, localhost]
  require_explicit_allowlist: true
sandbox:
  enabled: true
`

func TestBogusTransportErrors(t *testing.T) {
	cfg := writeConfig(t, testCfg)
	srv, _, err := mcpserve.DefensiveFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mcpserve.Serve(context.Background(), srv, "grpc", "127.0.0.1", 8000, false); err == nil {
		t.Fatal("bogus transport must error")
	}
}

func TestPublicBindRefusedWithoutFlag(t *testing.T) {
	cfg := writeConfig(t, testCfg)
	srv, _, err := mcpserve.DefensiveFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mcpserve.Serve(context.Background(), srv, "http", "0.0.0.0", 8000, false); err == nil {
		t.Fatal("non-loopback bind without --allow-public-bind must be refused")
	}
}

func TestConfigFingerprint(t *testing.T) {
	cfg := writeConfig(t, testCfg)
	raw, _ := os.ReadFile(cfg)
	sum := sha256.Sum256(raw)
	if err := mcpserve.CheckConfigFingerprint(cfg, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("matching fingerprint must pass: %v", err)
	}
	if err := mcpserve.CheckConfigFingerprint(cfg, "deadbeef"); err == nil {
		t.Fatal("mismatched fingerprint must fail")
	}
	if err := mcpserve.CheckConfigFingerprint(cfg, ""); err != nil {
		t.Fatalf("empty fingerprint must skip the check: %v", err)
	}
}

func TestDefensiveStdioSmoke(t *testing.T) {
	cfg := writeConfig(t, testCfg)
	srv, _, err := mcpserve.DefensiveFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_nmap_ping_sweep","arguments":{"subnet":"203.0.1.0/24"}}}`,
	}, "\n") + "\n"
	var out strings.Builder
	if err := srv.ServeStdio(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "run_nmap_triage_scan") {
		t.Fatalf("tools/list should advertise triage scan: %s", got)
	}
	if !strings.Contains(got, "not in scope") {
		t.Fatalf("out-of-scope subnet must be denied: %s", got)
	}
}
