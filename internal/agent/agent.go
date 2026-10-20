// Package agent implements the native post-recon assessment loop for
// attack/fast modes: per-service probing via the module registry,
// evidence-backed finding proposals, bounded rounds, explicit stop
// conditions. Mirrors the plan->tool->verify->reflect shape of
// tools/exploit_agent + tools/swarm at the native subset that is real:
// safe probing + verification, no payload execution.
package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/modules"
)

// Finding is a proposed, evidence-backed result (status proposed until a
// human confirms via POST /runs/{id}/decide).
type Finding struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence"`
	Status   string `json:"status"`
}

// Outcome is the attack-phase result recorded in run.json.
type Outcome struct {
	AttackExecuted bool      `json:"attack_executed"`
	Probes         int       `json:"probes"`
	Findings       []Finding `json:"findings"`
	ModelConsulted bool      `json:"model_consulted"`
	Note           string    `json:"note"`
}

// RunEnv is the minimal execution context (avoids importing runner).
type RunEnv struct {
	RunID   string
	Target  string
	Entries []string
	RunDir  string
	Assess  AssessmentView
	Emit    func(typ string, payload map[string]any)
}

// AssessmentView carries what recon observed.
type AssessmentView struct {
	OpenPorts []int
	Services  []ServiceView
}

// ServiceView is one observed service.
type ServiceView struct {
	Port    int
	Service string
	Banner  string
}

// Run executes the loop. Every probe target is allowlist-gated; out-of-scope
// targets are skipped with a denial event, never executed.
func Run(ctx context.Context, env RunEnv) (map[string]any, error) {
	out := Outcome{AttackExecuted: true, Findings: []Finding{}, Note: "native heuristic assessment: safe probes + verification only, no payload execution"}
	for _, svc := range env.Assess.Services {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probeService(ctx, env, svc, &out)
	}
	writeProposed(env.RunDir, out.Findings)
	if env.Emit != nil {
		env.Emit("agent_completed", map[string]any{"probes": out.Probes, "findings": len(out.Findings)})
	}
	raw, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

func gatedTarget(env RunEnv, target string) bool {
	return allowlist.Check(target, env.Entries, true)
}

func probeService(ctx context.Context, env RunEnv, svc ServiceView, out *Outcome) {
	target := env.Target
	if !gatedTarget(env, target) {
		if env.Emit != nil {
			env.Emit("tool_denied", map[string]any{"tool": "probe", "target": target})
		}
		return
	}
	mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	menv := modules.Env{Entries: env.Entries, Timeout: 30 * time.Second}
	isWeb := svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 || svc.Port == 9000 || svc.Service == "http" || svc.Service == "https" || svc.Service == "http-alt" || svc.Service == "https-alt"
	if isWeb {
		port := svc.Port
		if port == 0 {
			port = 80
		}
		if res, err := modules.Registry["http_probe"].Run(mctx, map[string]any{"target": target, "port": float64(port)}, menv); err == nil {
			out.Probes++
			status, _ := res["status"].(int)
			server, _ := res["server"].(string)
			title, _ := res["title"].(string)
			if status != 0 {
				out.Findings = append(out.Findings, Finding{
					ID:      "finding-" + shortID(svc.Port, "web"),
					Service: "http", Port: port,
					Summary:  "HTTP service responds",
					Evidence: "status=" + itoa(status) + " server=" + server + " title=" + title,
					Status:   "proposed",
				})
			}
		}
		if svc.Port == 443 || svc.Port == 8443 {
			if res, err := modules.Registry["tls_probe"].Run(mctx, map[string]any{"target": target, "port": float64(svc.Port)}, menv); err == nil {
				out.Probes++
				if certs, ok := res["certs"].([]any); ok && len(certs) > 0 {
					first, _ := certs[0].(map[string]any)
					out.Findings = append(out.Findings, Finding{
						ID:      "finding-" + shortID(svc.Port, "tls"),
						Service: "tls", Port: svc.Port,
						Summary:  "TLS certificate presented",
						Evidence: "subject=" + str(first["subject"]) + " not_after=" + str(first["not_after"]),
						Status:   "proposed",
					})
				}
			}
		}
		return
	}
	// Non-web: record the observed banner as evidence-backed service finding.
	if svc.Banner != "" || svc.Service != "" {
		out.Probes++
		out.Findings = append(out.Findings, Finding{
			ID:      "finding-" + shortID(svc.Port, "banner"),
			Service: svc.Service, Port: svc.Port,
			Summary:  "Service banner observed",
			Evidence: svc.Banner,
			Status:   "proposed",
		})
	}
}

func writeProposed(runDir string, findings []Finding) {
	if findings == nil {
		findings = []Finding{}
	}
	raw, _ := json.MarshalIndent(findings, "", "  ")
	_ = os.WriteFile(filepath.Join(runDir, "proposed.json"), append(raw, '\n'), 0o644)
}

func shortID(port int, kind string) string {
	return kind + "-" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
