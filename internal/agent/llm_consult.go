package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/braydos-h/BreachPilot/internal/providers"
)

// PeerConsultConfig configures multi-model peer consultation.
type PeerConsultConfig struct {
	Enabled          bool
	Aliases          []string
	Registry         map[string]string
	MaxConsultations int
	MaxQuestionChars int
	MaxAnswerChars   int
	Client           providers.Client
}

// PeerConsultResult holds the aggregated peer-consultation outcome.
type PeerConsultResult struct {
	Consulted    []string `json:"consulted"`
	Skipped      []string `json:"skipped"`
	AdvisoryText string   `json:"advisory_text"`
}

func truncateChars(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

// ConsultPeers fans out an advisory security-review query across configured
// peer model aliases, respecting MaxConsultations and character caps.
// Peers are strictly advisory: they never execute tools or modify allowlists.
func ConsultPeers(ctx context.Context, cfg PeerConsultConfig, question, contextText string) (PeerConsultResult, error) {
	out := PeerConsultResult{Consulted: []string{}, Skipped: []string{}}
	if !cfg.Enabled || cfg.Client == nil || len(cfg.Aliases) == 0 {
		return out, nil
	}
	maxConsult := cfg.MaxConsultations
	if maxConsult <= 0 {
		maxConsult = 10
	}
	maxQ := cfg.MaxQuestionChars
	if maxQ <= 0 {
		maxQ = 4000
	}
	maxA := cfg.MaxAnswerChars
	if maxA <= 0 {
		maxA = 8000
	}
	q := strings.TrimSpace(truncateChars(question, maxQ))
	if q == "" {
		return out, nil
	}
	selected := cfg.Aliases
	if len(selected) > maxConsult {
		selected = selected[:maxConsult]
	}

	msgs := []map[string]string{
		{
			"role": "system",
			"content": "You are a peer reviewer for an authorized security assessment. " +
				"Give concise assessment or verification advice only. " +
				"Do not claim to execute tools, do not request tool calls, and flag assumptions or safety concerns.",
		},
		{
			"role":    "user",
			"content": fmt.Sprintf("Question:\n%s\n\nContext:\n%s", q, contextText),
		},
	}

	type oneRes struct {
		alias string
		text  string
		err   error
	}
	results := make([]oneRes, len(selected))
	var wg sync.WaitGroup
	for i, alias := range selected {
		i, alias := i, alias
		wg.Add(1)
		go func() {
			defer wg.Done()
			modelSpec := alias
			if cfg.Registry != nil {
				if m, ok := cfg.Registry[alias]; ok && m != "" {
					modelSpec = m
				}
			}
			resp, err := cfg.Client.Chat(ctx, modelSpec, msgs)
			results[i] = oneRes{alias: alias, text: truncateChars(strings.TrimSpace(resp.Message), maxA), err: err}
		}()
	}
	wg.Wait()

	var sections []string
	for _, r := range results {
		if r.err != nil || r.text == "" {
			out.Skipped = append(out.Skipped, r.alias)
			continue
		}
		out.Consulted = append(out.Consulted, r.alias)
		sections = append(sections, fmt.Sprintf("### Peer [%s]\n%s", r.alias, r.text))
	}
	out.AdvisoryText = strings.Join(sections, "\n\n")
	return out, nil
}
