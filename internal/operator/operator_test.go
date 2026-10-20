package operator_test

// Slice 13 RED: the native operator-connection registry must persist
// records to operator_connections.json (+ per-target shards), validate
// targets and methods, and support beacon/check/remove lifecycle with
// status+target filters — before the implementation exists.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/operator"
)

func openManager(t *testing.T) *operator.Manager {
	t.Helper()
	m, err := operator.Open(t.TempDir(), []string{"10.0.0.50"}, true)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCreatePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	m, err := operator.Open(dir, []string{"10.0.0.50"}, true)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Create(operator.CreateArgs{
		TargetIP: "10.0.0.50", Method: "linux_cron",
		CallbackHost: "127.0.0.1", CallbackPort: 4444,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "active" || rec.ListenerName == "" {
		t.Fatalf("bad record: %+v", rec)
	}
	if _, err := os.Stat(filepath.Join(dir, "operator_connections.json")); err != nil {
		t.Fatalf("store file missing: %v", err)
	}
	m2, err := operator.Open(dir, []string{"10.0.0.50"}, true)
	if err != nil {
		t.Fatal(err)
	}
	got := m2.Get(rec.ConnectionID)
	if got == nil || got.TargetIP != "10.0.0.50" {
		t.Fatalf("reload lost record: %+v", got)
	}
}

func TestCreateRejectsBadTarget(t *testing.T) {
	m := openManager(t)
	if _, err := m.Create(operator.CreateArgs{TargetIP: "not a target!!", Method: "x", CallbackHost: "h", CallbackPort: 1}); err == nil {
		t.Fatal("invalid target must be rejected")
	}
	if _, err := m.Create(operator.CreateArgs{TargetIP: "192.168.99.99", Method: "x", CallbackHost: "h", CallbackPort: 1}); err == nil {
		t.Fatal("out-of-allowlist target must be rejected when required")
	}
}

func TestLifecycleAndFilters(t *testing.T) {
	m := openManager(t)
	a, err := m.Create(operator.CreateArgs{TargetIP: "10.0.0.50", Method: "m1", CallbackHost: "h", CallbackPort: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Create(operator.CreateArgs{TargetIP: "10.0.0.50", Method: "m2", CallbackHost: "h", CallbackPort: 2})
	if err != nil {
		t.Fatal(err)
	}
	m.MarkBeacon(a.ConnectionID)
	if got := m.Get(a.ConnectionID); got.LastBeacon == 0 {
		t.Fatal("beacon must stamp last_beacon")
	}
	m.MarkCheck(b.ConnectionID, "no listener", false)
	if got := m.Get(b.ConnectionID); got.Status != "stale" {
		t.Fatalf("unhealthy check must mark stale, got %+v", got)
	}
	if !m.MarkRemoved(a.ConnectionID) {
		t.Fatal("mark_removed must succeed")
	}
	if got := m.Get(a.ConnectionID); got.Status != "removed" {
		t.Fatalf("expected removed, got %+v", got)
	}
	if n := len(m.List("", "active")); n != 0 {
		t.Fatalf("no active expected, got %d", n)
	}
	if n := len(m.List("10.0.0.50", "")); n != 2 {
		t.Fatalf("target filter must return both, got %d", n)
	}
	if !m.Remove(b.ConnectionID) || m.Get(b.ConnectionID) != nil {
		t.Fatal("remove must delete the record")
	}
}
