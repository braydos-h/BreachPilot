package agent_test

// Slice 20 RED: LLM-calling agent loop + budget-capped multi-model peer
// consultation across configured model aliases.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/agent"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/providers"
)

type stubModelClient struct {
	name  string
	calls atomic.Int32
	fail  bool
}

func (s *stubModelClient) Name() string { return s.name }
func (s *stubModelClient) Chat(_ context.Context, model string, messages []map[string]string) (providers.Response, error) {
	s.calls.Add(1)
	if s.fail {
		return providers.Response{}, context.DeadlineExceeded
	}
	return providers.Response{
		Model:   model,
		Message: "Advisory from " + model + ": inspect HTTP headers on port 80",
		Usage:   map[string]any{"total_tokens": 42},
	}, nil
}

func TestAgentLoopCallsModelAndMultiModelConsult(t *testing.T) {
	cfg := config.Default()
	if !cfg.MultiModel.Enabled || len(cfg.MultiModel.ConsultAliases) == 0 {
		t.Fatalf("expected default multi_model config enabled with consult_aliases, got %+v", cfg.MultiModel)
	}

	client := &stubModelClient{name: "stub"}
	res, err := agent.ConsultPeers(context.Background(), agent.PeerConsultConfig{
		Enabled:          true,
		Aliases:          []string{"kimi", "deepseek", "glm"},
		Registry:         map[string]string{"kimi": "kimi-k2", "deepseek": "deepseek-v3", "glm": "glm-5"},
		MaxConsultations: 2, // budget caps to 2 peers
		MaxQuestionChars: 200,
		MaxAnswerChars:   500,
		Client:           client,
	}, "How should we validate port 80?", "nginx 1.18 banner observed")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Consulted) != 2 {
		t.Fatalf("expected budget cap of 2 consulted peers, got %v", res.Consulted)
	}
	if !strings.Contains(res.AdvisoryText, "Advisory from") {
		t.Fatalf("missing advisory text: %s", res.AdvisoryText)
	}

	// Run agent with ModelClient attached -> ModelConsulted must be true
	dir := t.TempDir()
	out, err := agent.Run(context.Background(), agent.RunEnv{
		RunID:       "run-llm-1",
		Target:      "127.0.0.1",
		Entries:     []string{"127.0.0.1"},
		RunDir:      dir,
		Assess:      agent.AssessmentView{OpenPorts: []int{22}, Services: []agent.ServiceView{{Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_8.9"}}},
		ModelClient: client,
		ModelName:   "glm-5",
		PeerConsult: &agent.PeerConsultConfig{
			Enabled:          true,
			Aliases:          []string{"kimi"},
			Registry:         map[string]string{"kimi": "kimi-k2"},
			MaxConsultations: 2,
			Client:           client,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["model_consulted"] != true {
		t.Fatalf("expected model_consulted=true when ModelClient is provided, got %v", out)
	}
	if out["model_advisory"] == nil || out["peer_consult"] == nil {
		t.Fatalf("expected model_advisory and peer_consult in outcome: %v", out)
	}
}
