package runner_test

// Slice 6 RED: resuming a swarm run must adopt the prior run's swarm
// checkpoints (attack_states.json / swarm_state.json) and recover via the
// campaign Resume path — in-flight tasks demoted to pending — instead of
// silently restarting from scratch.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func seedInterruptedSwarmRun(t *testing.T, reportsDir, runID string) {
	t.Helper()
	dir := filepath.Join(reportsDir, runID)
	if err := os.MkdirAll(filepath.Join(dir, "swarm_workspace"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("recon_assessment.json", `{"target_ip":"127.0.0.1","open_ports":[80],"services":[{"port":80,"protocol":"tcp","service":"http","version":"","banner":""}],"cve_findings":[]}`)
	states := `{"updated_at":"2026-10-20T00:00:00Z","states":{"127.0.0.1":{"target":"127.0.0.1","current_phase":"validation","aggression":"normal","privilege_level":"none","recon_completed":true,"recon_result":{"target_ip":"127.0.0.1","open_ports":[80],"services":[],"cve_findings":[]},"tasks":[{"task_id":"ATK-00001","phase":"recon","specialist":"ReconAgent","module_name":"SeedMarker","target":"127.0.0.1","status":"completed","created_at":"2026-10-20T00:00:00Z"},{"task_id":"ATK-00002","phase":"validation","specialist":"ValidationAgent","module_name":"InterruptedProbe","target":"127.0.0.1","status":"running","created_at":"2026-10-20T00:00:00Z"}],"failed_attempts":{},"strategy_shift":"standard","task_counter":2}}}`
	write("attack_states.json", states)
	write("swarm_state.json", `{"updated_at":"2026-10-20T00:00:00Z","blackboard":{},"states":{"127.0.0.1":{"target":"127.0.0.1"}}}`)
	write(filepath.Join("swarm_workspace", "attack_states.json"), states)
}

func taskStatus(t *testing.T, runDir, wantID string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, "swarm_workspace", "attack_states.json"))
	if err != nil {
		t.Fatalf("read adopted checkpoints: %v", err)
	}
	var wrapper struct {
		States map[string]struct {
			Tasks []struct {
				TaskID string `json:"task_id"`
				Status string `json:"status"`
			} `json:"tasks"`
		} `json:"states"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	for _, st := range wrapper.States {
		for _, task := range st.Tasks {
			if task.TaskID == wantID {
				return task.Status
			}
		}
	}
	return "<missing>"
}

func TestSwarmResumeAdoptsCheckpoints(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	seedInterruptedSwarmRun(t, filepath.Join(dir, "reports"), "run-prior")

	// Prior run row must exist for the resume reference to be meaningful.
	if err := db.CreateRun("run-prior", "failed", "127.0.0.1", "attack", "", `{"target":"127.0.0.1"}`); err != nil {
		t.Fatal(err)
	}
	req := `{"target":"127.0.0.1","mode":"attack","goal":"","kind":"agent","yes":true,"swarm":true,"resume":"run-prior"}`
	if err := db.CreateRun("run-resume1", "queued", "127.0.0.1", "attack", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-resume1")
	waitState(t, db, "run-resume1", "completed")

	// Recon must have been adopted, not rescanned.
	evts := reg.GetOrCreate("run-resume1").Replay(0)
	reused := false
	for _, e := range evts {
		if e.Type == "recon_completed" && e.Payload["reused"] == true {
			reused = true
		}
	}
	if !reused {
		t.Fatal("expected recon_completed with reused=true for resumed run")
	}
	// Seed marker adopted; interrupted task demoted running -> pending.
	if got := taskStatus(t, filepath.Join(dir, "reports", "run-resume1"), "ATK-00001"); got != "completed" {
		t.Fatalf("seed marker task = %q, want completed (adopted)", got)
	}
	if got := taskStatus(t, filepath.Join(dir, "reports", "run-resume1"), "ATK-00002"); got != "pending" {
		t.Fatalf("interrupted task = %q, want pending (demoted on resume)", got)
	}
}
