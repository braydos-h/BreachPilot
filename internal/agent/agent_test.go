package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/agent"
)

func TestEmptyAssessmentNoFindings(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := agent.Run(ctx, agent.RunEnv{
		RunID: "r1", Target: "127.0.0.1", Entries: []string{"127.0.0.1"},
		RunDir: dir, Assess: agent.AssessmentView{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["attack_executed"] != true || int(out["probes"].(float64)) != 0 {
		t.Fatalf("outcome: %v", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "proposed.json"))
	if err != nil {
		t.Fatalf("proposed.json missing: %v", err)
	}
	var findings []any
	if err := json.Unmarshal(raw, &findings); err != nil || len(findings) != 0 {
		t.Fatalf("proposed: %s %v", raw, err)
	}
}

func TestOutOfScopeSkipped(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	denied := []string{}
	out, err := agent.Run(ctx, agent.RunEnv{
		RunID: "r1", Target: "10.9.9.9", Entries: []string{"127.0.0.1"},
		RunDir: dir,
		Assess: agent.AssessmentView{Services: []agent.ServiceView{{Port: 80, Service: "http"}}},
		Emit: func(typ string, payload map[string]any) {
			if typ == "tool_denied" {
				denied = append(denied, typ)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if int(out["probes"].(float64)) != 0 || len(denied) != 1 {
		t.Fatalf("scope must skip probes with denial event: %v", out)
	}
}
