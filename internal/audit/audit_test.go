package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/audit"
)

func TestChainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := audit.Append(dir, "r1", "tcp_scan", "127.0.0.1", "completed", "tcp_scan", "a1"); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Append(dir, "r1", "http_probe", "127.0.0.1", "completed", "http_probe", "a1"); err != nil {
		t.Fatal(err)
	}
	rows, err := audit.List(dir)
	if err != nil || len(rows) != 2 || rows[1].Sequence != 2 || rows[1].PrevHash != rows[0].Hash {
		t.Fatalf("rows: %+v %v", rows, err)
	}
	if ok, reason, _ := audit.Verify(dir); !ok {
		t.Fatalf("verify: %s", reason)
	}
}

func TestTamperDetected(t *testing.T) {
	dir := t.TempDir()
	_, _ = audit.Append(dir, "r1", "tcp_scan", "t", "completed", "c", "a")
	raw, _ := os.ReadFile(filepath.Join(dir, "exploit_audit.jsonl"))
	// Flip a byte in the status field.
	for i := range raw {
		if raw[i] == 'c' {
			raw[i] = 'x'
			break
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "exploit_audit.jsonl"), raw, 0o644)
	if ok, _, _ := audit.Verify(dir); ok {
		t.Fatal("tampered chain must not verify")
	}
}

func TestEmptyVerifies(t *testing.T) {
	if ok, _, _ := audit.Verify(t.TempDir()); !ok {
		t.Fatal("absent log must verify as empty chain")
	}
}
