package runner_test

// Slice 12 RED: recon-first goal selection — with no operator goal the runner
// must auto-select the top compatible suggestion, tag the assessment, and
// emit the goal_suggestions + fast_recon_goal_selected events the WebUI
// renders. Today ChosenGoal stays empty and no such events fire.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func TestReconAutoSelectsGoal(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	req := `{"target":"127.0.0.1","mode":"recon","goal":"","kind":"agent","yes":true}`
	if err := db.CreateRun("run-goal1", "queued", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-goal1")
	waitState(t, db, "run-goal1", "completed")

	raw, err := os.ReadFile(filepath.Join(dir, "reports", "run-goal1", "recon_assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var assess struct {
		ChosenGoal string `json:"chosen_goal"`
	}
	if err := json.Unmarshal(raw, &assess); err != nil {
		t.Fatal(err)
	}
	if assess.ChosenGoal == "" {
		t.Fatalf("assessment must carry an auto-selected chosen_goal: %s", raw)
	}
	seen := map[string]bool{}
	for _, e := range reg.GetOrCreate("run-goal1").Replay(0) {
		seen[e.Type] = true
	}
	if !seen["goal_suggestions"] {
		t.Fatal("expected goal_suggestions event for the WebUI row")
	}
	if !seen["fast_recon_goal_selected"] {
		t.Fatal("expected fast_recon_goal_selected event")
	}
}

func TestReconHonorsCustomGoal(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	req := `{"target":"127.0.0.1","mode":"recon","goal":"","custom_goal":" Map it all ","kind":"agent","yes":true}`
	if err := db.CreateRun("run-goal2", "queued", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-goal2")
	waitState(t, db, "run-goal2", "completed")
	raw, err := os.ReadFile(filepath.Join(dir, "reports", "run-goal2", "recon_assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var assess struct {
		ChosenGoal string `json:"chosen_goal"`
	}
	if err := json.Unmarshal(raw, &assess); err != nil {
		t.Fatal(err)
	}
	if assess.ChosenGoal != "custom" {
		t.Fatalf("custom goal must win, got %q", assess.ChosenGoal)
	}
}
