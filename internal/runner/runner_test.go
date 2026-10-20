package runner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func waitState(t *testing.T, db *store.DB, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		run, err := db.GetRun(id)
		if err != nil {
			t.Fatal(err)
		}
		if run["state"] == want {
			return run
		}
		if run["state"] == "failed" && want != "failed" {
			t.Fatalf("run failed unexpectedly")
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s (now %s)", want, run["state"])
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestReconRunCompletes(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	req := `{"target":"127.0.0.1","mode":"recon","goal":"","kind":"agent","yes":true}`
	if err := db.CreateRun("run-t1", "queued", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-t1")
	waitState(t, db, "run-t1", "completed")
	for _, f := range []string{"recon_assessment.json", "goal_suggestions.json", "run.json", "session_summary.md", "activity.jsonl", "session_state.json", "enhanced_report.json", "enhanced_report.md", "enhanced_report.html"} {
		if _, err := os.Stat(filepath.Join(dir, "reports", "run-t1", f)); err != nil {
			t.Fatalf("missing artifact %s: %v", f, err)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "reports", "run-t1", "recon_assessment.json")); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(string(raw), `"udp_ports"`) {
		t.Fatalf("assessment must carry udp_ports: %s", raw)
	}
	evts := reg.GetOrCreate("run-t1").Replay(0)
	seen := map[string]bool{}
	for _, e := range evts {
		seen[e.Type] = true
	}
	// run_created is appended by the API create path; the runner owns
	// recon_completed/run_completed/state here.
	if !seen["recon_completed"] || !seen["run_completed"] {
		t.Fatalf("event trail incomplete: %v", seen)
	}
}

func TestScopeDeniedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	// Empty union + required => every target denied.
	r := runner.New(db, reg, filepath.Join(dir, "reports"), nil, true, 2)
	req := `{"target":"127.0.0.1","mode":"recon","kind":"agent","yes":true}`
	if err := db.CreateRun("run-t2", "queued", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-t2")
	waitState(t, db, "run-t2", "failed")
}

func TestCancelUnknown(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := runner.New(db, events.NewRegistry(), filepath.Join(dir, "reports"), nil, false, 1)
	if r.Cancel("nope") {
		t.Fatal("cancel of unknown run must report false")
	}
	// Ensure is a no-op for non-queued runs.
	r.Ensure("nope")
}
