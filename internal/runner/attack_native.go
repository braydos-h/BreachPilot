package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/braydos-h/BreachPilot/internal/agent"
)

// NativeAttack is the default AttackFunc: it loads the recon assessment from
// the run dir and executes the native agent loop (safe probes +
// verification). Plugged in by cmd/bp.
func NativeAttack(ctx context.Context, env *Env) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(env.RunDir, "recon_assessment.json"))
	if err != nil {
		return nil, err
	}
	var a struct {
		OpenPorts []int `json:"open_ports"`
		Services  []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			Banner  string `json:"banner"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	av := agent.AssessmentView{OpenPorts: a.OpenPorts}
	for _, s := range a.Services {
		av.Services = append(av.Services, agent.ServiceView{Port: s.Port, Service: s.Service, Banner: s.Banner})
	}
	return agent.Run(ctx, agent.RunEnv{
		RunID: env.RunID, Target: env.Target, Entries: env.Entries,
		RunDir: env.RunDir, Assess: av, Emit: env.Emit,
	})
}
