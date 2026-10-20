package runner_test

// Slice 2: --swarm / "swarm":true must execute the native multi-agent
// campaign (not the single-agent path, not a no-op note).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func readOutcome(t *testing.T, dir, runID string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "reports", runID, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, _ := v["outcome"].(map[string]any)
	if out == nil {
		t.Fatalf("run.json has no outcome: %s", raw)
	}
	return out
}

func TestSwarmRunExecutesCampaign(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	req := `{"target":"127.0.0.1","mode":"attack","goal":"","kind":"agent","yes":true,"swarm":true}`
	if err := db.CreateRun("run-sw1", "queued", "127.0.0.1", "attack", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-sw1")
	waitState(t, db, "run-sw1", "completed")
	out := readOutcome(t, dir, "run-sw1")
	if out["swarm"] != true {
		t.Fatalf("outcome missing swarm=true: %v", out)
	}
	if out["attack_executed"] != true {
		t.Fatalf("swarm run must execute the campaign, got: %v", out)
	}
	for _, f := range []string{"swarm_workspace/swarm_state.json", "swarm_workspace/attack_states.json"} {
		if _, err := os.Stat(filepath.Join(dir, "reports", "run-sw1", f)); err != nil {
			t.Fatalf("missing swarm checkpoint %s: %v", f, err)
		}
	}
}

func TestNonSwarmAttackUnchanged(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	req := `{"target":"127.0.0.1","mode":"attack","goal":"","kind":"agent","yes":true}`
	if err := db.CreateRun("run-sw2", "queued", "127.0.0.1", "attack", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-sw2")
	waitState(t, db, "run-sw2", "completed")
	out := readOutcome(t, dir, "run-sw2")
	if _, hasSwarm := out["swarm"]; hasSwarm {
		t.Fatalf("non-swarm run must not claim swarm: %v", out)
	}
}
