// Package runner is the native run service: lifecycle, background execution,
// cancellation, resume, and artifact persistence. Mirrors
// tools/run_service/ (prepare/execute/tasks) + tools/api/run_manager.py
// state machine: preparing -> awaiting_confirmation -> queued -> running ->
// completed|failed|cancelled.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/recon"
	"github.com/braydos-h/BreachPilot/internal/store"
)

// Request mirrors the persisted run request.
type Request struct {
	Target     string `json:"target"`
	Mode       string `json:"mode"`
	Goal       string `json:"goal"`
	CustomGoal string `json:"custom_goal"`
	Resume     string `json:"resume"`
	Yes        bool   `json:"yes"`
}

// AttackFunc executes the post-recon agent phase for attack/fast modes.
// It is a hook so the agent engine (internal/agent) plugs in without an
// import cycle. When nil, the runner records an honest outcome noting the
// attack phase did not execute rather than fabricating results.
type AttackFunc func(ctx context.Context, env *Env) (map[string]any, error)

// Env is the execution environment handed to the attack phase.
type Env struct {
	RunID      string
	Target     string
	ResolvedIP string
	Domain     string
	Mode       string
	Goal       string
	Entries    []string
	RunDir     string
	DB         *store.DB
	Broker     *events.Broker
	Emit       func(typ string, payload map[string]any)
}

// Runner executes runs with bounded concurrency.
type Runner struct {
	DB               *store.DB
	Events           *events.Registry
	ReportsDir       string
	AllowedTargets   []string
	RequireAllowlist bool
	MaxConcurrent    int
	Attack           AttackFunc

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	sem     chan struct{}
}

// New builds a runner. maxConcurrent <= 0 defaults to 4.
func New(db *store.DB, reg *events.Registry, reportsDir string, allowed []string, requireAllowlist bool, maxConcurrent int) *Runner {
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &Runner{DB: db, Events: reg, ReportsDir: reportsDir, AllowedTargets: allowed,
		RequireAllowlist: requireAllowlist, MaxConcurrent: maxConcurrent,
		cancels: map[string]context.CancelFunc{}, sem: make(chan struct{}, maxConcurrent)}
}

// Ensure starts the worker when the run is queued. No-op otherwise.
func (r *Runner) Ensure(runID string) {
	run, err := r.DB.GetRun(runID)
	if err != nil || run == nil || run["state"] != "queued" {
		return
	}
	go r.execute(runID)
}

// Cancel signals a queued/running run. Reports whether a worker was stopped.
func (r *Runner) Cancel(runID string) bool {
	r.mu.Lock()
	cancel, ok := r.cancels[runID]
	r.mu.Unlock()
	if ok && cancel != nil {
		cancel()
		return true
	}
	return false
}

func (r *Runner) brokerFor(runID string) *events.Broker {
	return r.Events.GetOrCreate(runID)
}

func (r *Runner) emit(runID, typ string, payload map[string]any) {
	if payload == nil {
		payload = map[string]any{}
	}
	r.brokerFor(runID).Append(runID, typ, payload)
}

func (r *Runner) execute(runID string) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		// At capacity: leave queued; a later Ensure (or completion) retries.
		return
	}
	if st, _ := r.DB.GetRun(runID); st == nil || st["state"] != "queued" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancels[runID] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.cancels, runID)
		r.mu.Unlock()
	}()
	_ = r.DB.SetRunState(runID, "running")
	r.emit(runID, "state", map[string]any{"state": "running"})

	outcome, err := r.runRecon(ctx, runID)
	if err != nil {
		if ctx.Err() != nil {
			_ = r.DB.SetRunState(runID, "cancelled")
			r.emit(runID, "run_cancelled", map[string]any{})
			return
		}
		_ = r.DB.SetRunState(runID, "failed")
		r.emit(runID, "run_failed", map[string]any{"error": err.Error()})
		_ = r.DB.LogAudit(runID, "run_failed", err.Error(), "{}")
		return
	}
	_ = r.DB.SetRunState(runID, "completed")
	r.emit(runID, "run_completed", outcome)
}

// runRecon performs the genuine recon phase shared by all modes.
func (r *Runner) runRecon(ctx context.Context, runID string) (map[string]any, error) {
	run, err := r.DB.GetRun(runID)
	if err != nil || run == nil {
		return nil, fmt.Errorf("run not found")
	}
	req := parseRequest(run)
	if req.Target == "" {
		return nil, fmt.Errorf("run has no target")
	}
	host, _, err := recon.ParseTarget(req.Target)
	if err != nil {
		return nil, err
	}
	ip, domain, err := recon.Resolve(ctx, req.Target)
	if err != nil {
		failDir(r.ReportsDir, runID, "resolution", err.Error())
		return nil, err
	}
	entries := allowlist.ApprovalEntries(r.AllowedTargets, nil)
	gate := ip
	if gate == "" {
		gate = host
	}
	if !allowlist.Check(gate, entries, r.RequireAllowlist) {
		msg := fmt.Sprintf("target %s not in allowlist", req.Target)
		failDir(r.ReportsDir, runID, "scope", msg)
		_ = r.DB.LogAudit(runID, "scope_denied", msg, "{}")
		r.emit(runID, "scope_denied", map[string]any{"target": req.Target})
		return nil, fmt.Errorf("%s", msg)
	}
	if domain != "" && !allowlist.Check(domain, entries, r.RequireAllowlist) {
		msg := fmt.Sprintf("domain %s not in allowlist", domain)
		failDir(r.ReportsDir, runID, "scope", msg)
		return nil, fmt.Errorf("%s", msg)
	}

	runDir := filepath.Join(r.ReportsDir, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, err
	}
	writeJSON(runDir, "session_state.json", map[string]any{"session_id": runID, "started_at": nowISO()})
	appendActivity(runDir, map[string]any{"phase": "recon_start", "target": req.Target, "mode": req.Mode})

	// Resume reuse: adopt a matching prior assessment instead of rescanning.
	if req.Resume != "" {
		if adopted := tryAdoptAssessment(r.ReportsDir, req.Resume, host, runDir); adopted {
			r.emit(runID, "recon_completed", map[string]any{"resumed_from": req.Resume, "reused": true})
			return r.finishAttack(ctx, runID, req, host, ip, domain, entries, runDir)
		}
	}

	results := recon.ScanPorts(ctx, ipOr(host, ip), recon.DefaultFastPorts)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	assessment := recon.BuildAssessment(ipOr(host, ip), results)
	if req.Goal != "" {
		assessment.ChosenGoal = req.Goal
	}
	writeJSON(runDir, "recon_assessment.json", assessment)
	suggestions := recon.SuggestGoals(assessment.OpenPorts, req.Mode)
	writeJSON(runDir, "goal_suggestions.json", suggestions)
	r.emit(runID, "recon_completed", map[string]any{"open_ports": assessment.OpenPorts, "services": len(assessment.Services)})
	appendActivity(runDir, map[string]any{"phase": "recon_complete", "open_ports": assessment.OpenPorts})

	return r.finishAttack(ctx, runID, req, host, ip, domain, entries, runDir)
}

func ipOr(host, ip string) string {
	if ip != "" {
		return ip
	}
	return host
}

// finishAttack runs the agent phase for attack/fast modes, or finalizes
// recon runs. When no attack function is plugged in, the outcome records
// that explicitly instead of fabricating exploit results.
func (r *Runner) finishAttack(ctx context.Context, runID string, req Request, host, ip, domain string, entries []string, runDir string) (map[string]any, error) {
	outcome := map[string]any{"target": req.Target, "mode": req.Mode, "recon_complete": true}
	if req.Mode == "recon" {
		finalizeRun(runDir, runID, req, outcome)
		return outcome, nil
	}
	if r.Attack == nil {
		outcome["attack_executed"] = false
		outcome["note"] = "attack engine not plugged in: recon completed, no exploit phase executed"
		finalizeRun(runDir, runID, req, outcome)
		return outcome, nil
	}
	env := &Env{RunID: runID, Target: req.Target, ResolvedIP: ip, Domain: domain,
		Mode: req.Mode, Goal: req.Goal, Entries: entries, RunDir: runDir,
		DB: r.DB, Broker: r.brokerFor(runID)}
	env.Emit = func(typ string, payload map[string]any) { r.emit(runID, typ, payload) }
	res, err := r.Attack(ctx, env)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		outcome["attack_error"] = err.Error()
		finalizeRun(runDir, runID, req, outcome)
		return outcome, nil
	}
	for k, v := range res {
		outcome[k] = v
	}
	finalizeRun(runDir, runID, req, outcome)
	return outcome, nil
}

func parseRequest(run map[string]any) Request {
	var req Request
	if raw, ok := run["request"].(string); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &req)
	}
	// GetRun exposes target/mode/goal columns; prefer them when present.
	if t, ok := run["target"].(string); ok && t != "" {
		req.Target = t
	}
	if m, ok := run["mode"].(string); ok && m != "" {
		req.Mode = m
	}
	if g, ok := run["goal_name"].(string); ok && g != "" && req.Goal == "" {
		req.Goal = g
	}
	if req.Mode == "" {
		req.Mode = "attack"
	}
	return req
}

// tryAdoptAssessment reuses a prior run's recon_assessment.json when the
// target matches, mirroring the resume-reuse path.
func tryAdoptAssessment(reportsDir, resumeFrom, host, runDir string) bool {
	src := filepath.Join(reportsDir, resumeFrom, "recon_assessment.json")
	raw, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return false
	}
	var a map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		return false
	}
	tip, _ := a["target_ip"].(string)
	if tip == "" || (tip != host && !equalFoldStr(tip, host)) {
		return false
	}
	_ = os.WriteFile(filepath.Join(runDir, "recon_assessment.json"), raw, 0o644)
	if sg, err := os.ReadFile(filepath.Join(reportsDir, resumeFrom, "goal_suggestions.json")); err == nil {
		_ = os.WriteFile(filepath.Join(runDir, "goal_suggestions.json"), sg, 0o644)
	}
	return true
}

func equalFoldStr(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func finalizeRun(runDir, runID string, req Request, outcome map[string]any) {
	writeJSON(runDir, "run.json", map[string]any{"run_id": runID, "target": req.Target,
		"mode": req.Mode, "goal": req.Goal, "outcome": outcome, "completed_at": nowISO()})
	summary := "# BreachPilot run " + runID + "\n\n- target: " + req.Target + "\n- mode: " + req.Mode + "\n- goal: " + req.Goal + "\n- completed: " + nowISO() + "\n"
	_ = os.WriteFile(filepath.Join(runDir, "session_summary.md"), []byte(summary), 0o644)
	appendActivity(runDir, map[string]any{"phase": "completed", "outcome": outcome})
}

func failDir(reportsDir, runID, kind, msg string) {
	dir := filepath.Join(reportsDir, runID)
	_ = os.MkdirAll(dir, 0o755)
	appendActivity(dir, map[string]any{"phase": "failed", "kind": kind, "error": msg})
	_ = os.WriteFile(filepath.Join(dir, "session_error.log"), []byte(msg+"\n"), 0o644)
}

func writeJSON(dir, name string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o644)
}

func appendActivity(dir string, row map[string]any) {
	row["at"] = nowISO()
	raw, _ := json.Marshal(row)
	f, err := os.OpenFile(filepath.Join(dir, "activity.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(raw, '\n'))
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339Nano) }
