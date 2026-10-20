// Package bench implements the native benchmark harness: suite registry,
// trial execution against real recon, run records, baseline save/compare.
// Mirrors tools/benchmark/ (service/runner/storage/regression) at the
// native subset: one built-in suite ("native-smoke"), deterministic oracle
// (trial solved iff recon completes with no scope violation), baseline
// gating on success rate + scope violations.
package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

// Suite describes a benchmark suite.
type Suite struct {
	ID        string     `json:"suite_id"`
	Scenarios []Scenario `json:"scenarios"`
}

// Scenario is one benchmark scenario.
type Scenario struct {
	ScenarioID string   `json:"scenario_id"`
	Name       string   `json:"name"`
	TargetHost string   `json:"target_host"`
	TargetPort int      `json:"target_port"`
	Tags       []string `json:"tags"`
}

// TrialResult is one trial outcome.
type TrialResult struct {
	TrialID    string `json:"trial_id"`
	ScenarioID string `json:"scenario_id"`
	Status     string `json:"status"` // verified | failed | scope_violation
	Solved     bool   `json:"solved"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	OpenPorts  []int  `json:"open_ports,omitempty"`
}

// Summary mirrors RunSummary at the native subset.
type Summary struct {
	RunID               string  `json:"run_id"`
	Suite               string  `json:"suite"`
	Status              string  `json:"status"`
	Timestamp           string  `json:"timestamp"`
	TrialsTotal         int     `json:"trials_total"`
	TrialsCompleted     int     `json:"trials_completed"`
	VerifiedSuccessRate float64 `json:"verified_success_rate"`
	Solved              int     `json:"solved"`
	ScopeViolationCount int     `json:"scope_violation_count"`
}

// Run is a stored benchmark run.
type Run struct {
	RunID     string         `json:"run_id"`
	Suite     string         `json:"suite"`
	State     string         `json:"state"`
	Config    map[string]any `json:"config"`
	Trials    []TrialResult  `json:"trials"`
	Summary   Summary        `json:"summary"`
	CreatedAt string         `json:"created_at"`
}

// Service owns suites, runs, and the single-active guard.
type Service struct {
	Dir     string // reports/benchmarks
	Entries []string
	Require bool

	mu     sync.Mutex
	active string
	runs   map[string]*Run
	Events *events.Registry
}

// New builds the service with the built-in suite registered.
func New(dir string, entries []string, require bool, reg *events.Registry) *Service {
	return &Service{Dir: dir, Entries: entries, Require: require, runs: map[string]*Run{}, Events: reg}
}

// Suites lists registered suites.
func (s *Service) Suites() []Suite {
	return []Suite{{
		ID: "native-smoke",
		Scenarios: []Scenario{{
			ScenarioID: "smoke-001", Name: "Deterministic smoke",
			TargetHost: "127.0.0.1", TargetPort: 80, Tags: []string{"smoke"},
		}},
	}}
}

func (s *Service) suiteByID(id string) *Suite {
	for _, su := range s.Suites() {
		if su.ID == id {
			c := su
			return &c
		}
	}
	return nil
}

// Start validates and launches a run, returning {run_id, state} immediately
// while trials execute in the background (mirrors the ~1s reserve pattern).
func (s *Service) Start(suite string, trials int, timeoutSeconds int) (*Run, error) {
	if suite == "" {
		return nil, fmt.Errorf("missing_suite")
	}
	su := s.suiteByID(suite)
	if su == nil {
		return nil, fmt.Errorf("unknown_suite")
	}
	if trials < 1 || trials > 20 {
		return nil, fmt.Errorf("bad_trials")
	}
	if timeoutSeconds != 0 && timeoutSeconds < 30 {
		return nil, fmt.Errorf("bad_timeout")
	}
	s.mu.Lock()
	if s.active != "" {
		active := s.active
		s.mu.Unlock()
		return nil, errors.New("conflict:" + active)
	}
	id := fmt.Sprintf("bench-%d", time.Now().UnixNano())
	run := &Run{RunID: id, Suite: suite, State: "running",
		Config: map[string]any{"trials": trials}, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	s.runs[id] = run
	s.active = id
	s.mu.Unlock()
	go s.execute(run, su.Scenarios[0], trials, timeoutSeconds)
	return run, nil
}

// RunSync starts a suite run and blocks until it reaches a terminal state,
// cancelling and failing on deadline. It is the synchronous entrypoint
// behind bp --eval: same Start/execute path as the API, waited on.
func RunSync(svc *Service, suite string, trials, timeoutSeconds int, maxWait time.Duration) (*Run, error) {
	run, err := svc.Start(suite, trials, timeoutSeconds)
	if err != nil {
		return nil, err
	}
	if maxWait <= 0 {
		maxWait = time.Duration(trials)*(time.Duration(timeoutSeconds)*time.Second) + 30*time.Second
	}
	deadline := time.Now().Add(maxWait)
	for {
		if got := svc.Get(run.RunID); got != nil && got.State != "running" && got.State != "cancelling" {
			return got, nil
		}
		if time.Now().After(deadline) {
			svc.Cancel(run.RunID)
			return nil, fmt.Errorf("eval timed out waiting for run %s", run.RunID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Service) execute(run *Run, sc Scenario, trials, timeoutSeconds int) {
	defer func() {
		s.mu.Lock()
		if s.active == run.RunID {
			s.active = ""
		}
		s.mu.Unlock()
	}()
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	for i := 0; i < trials; i++ {
		trial := s.runTrial(run.RunID, sc, i, timeout)
		s.mu.Lock()
		run.Trials = append(run.Trials, trial)
		s.mu.Unlock()
		if trial.Status == "cancelled" {
			break
		}
	}
	s.mu.Lock()
	run.State = "completed"
	run.Summary = summarize(run)
	s.mu.Unlock()
	s.persist(run)
}

func (s *Service) runTrial(runID string, sc Scenario, idx int, timeout time.Duration) TrialResult {
	start := time.Now()
	tr := TrialResult{TrialID: fmt.Sprintf("%s-t%d", runID, idx), ScenarioID: sc.ScenarioID}
	if !allowlist.Check(sc.TargetHost, allowlist.ApprovalEntries(s.Entries, nil), s.Require) {
		tr.Status = "scope_violation"
		return tr
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, _, err := recon.Resolve(ctx, sc.TargetHost); err != nil {
		tr.Status, tr.Error = "failed", err.Error()
		return tr
	}
	results := recon.ScanPorts(ctx, sc.TargetHost, recon.DefaultFastPorts)
	if ctx.Err() != nil {
		tr.Status, tr.Error = "failed", "timeout"
		return tr
	}
	for _, r := range results {
		if r.Open {
			tr.OpenPorts = append(tr.OpenPorts, r.Port)
		}
	}
	tr.Status, tr.Solved = "verified", true
	tr.DurationMs = time.Since(start).Milliseconds()
	return tr
}

func summarize(run *Run) Summary {
	solved, completed, scope := 0, 0, 0
	for _, t := range run.Trials {
		if t.Status == "verified" {
			completed++
			if t.Solved {
				solved++
			}
		} else if t.Status == "scope_violation" {
			scope++
			completed++
		} else if t.Status != "cancelled" {
			completed++
		}
	}
	rate := 0.0
	if len(run.Trials) > 0 {
		rate = float64(solved) / float64(len(run.Trials))
	}
	return Summary{RunID: run.RunID, Suite: run.Suite, Status: run.State,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		TrialsTotal: len(run.Trials), TrialsCompleted: completed,
		VerifiedSuccessRate: rate, Solved: solved, ScopeViolationCount: scope}
}

func (s *Service) persist(run *Run) {
	dir := filepath.Join(s.Dir, run.RunID)
	_ = os.MkdirAll(dir, 0o755)
	raw, _ := json.MarshalIndent(run, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "run.json"), append(raw, '\n'), 0o644)
	sum, _ := json.MarshalIndent(run.Summary, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), append(sum, '\n'), 0o644)
}

// Get returns a run by id.
func (s *Service) Get(id string) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[id]
}

// List returns up to 20 recent runs (in-memory; persisted runs reload on demand).
func (s *Service) List() []*Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Run
	for _, r := range s.runs {
		out = append(out, r)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

// Cancel stops the active run.
func (s *Service) Cancel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok || r.State != "running" {
		return false
	}
	r.State = "cancelling"
	return true
}

// Baseline stops: minimal port of regression thresholds (success-rate drop
// tolerance 0.02, any scope violation is a hard fail).
type Baseline struct {
	RunID               string  `json:"run_id"`
	Suite               string  `json:"suite"`
	Timestamp           string  `json:"timestamp"`
	VerifiedSuccessRate float64 `json:"verified_success_rate"`
	ScopeViolationCount int     `json:"scope_violation_count"`
}

func (s *Service) baselinePath() string { return filepath.Join(s.Dir, "baseline.json") }

// SaveBaseline persists the run's summary as baseline.
func (s *Service) SaveBaseline(id string) (Baseline, error) {
	r := s.Get(id)
	if r == nil {
		return Baseline{}, fmt.Errorf("not_found")
	}
	b := Baseline{RunID: r.RunID, Suite: r.Suite, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		VerifiedSuccessRate: r.Summary.VerifiedSuccessRate, ScopeViolationCount: r.Summary.ScopeViolationCount}
	raw, _ := json.MarshalIndent(b, "", "  ")
	_ = os.MkdirAll(s.Dir, 0o755)
	if err := os.WriteFile(s.baselinePath(), append(raw, '\n'), 0o644); err != nil {
		return Baseline{}, err
	}
	return b, nil
}

// LoadBaseline reads the baseline, reporting existence.
func (s *Service) LoadBaseline() (Baseline, bool) {
	raw, err := os.ReadFile(filepath.Clean(s.baselinePath()))
	if err != nil {
		return Baseline{}, false
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return Baseline{}, false
	}
	return b, true
}

// CompareResult is one hard/unchanged finding.
type CompareResult struct {
	Severity string `json:"severity"`
	Metric   string `json:"metric"`
	Baseline any    `json:"baseline"`
	Current  any    `json:"current"`
}

// Compare checks a run against the baseline. Missing baseline fails closed.
func (s *Service) Compare(id string) ([]CompareResult, error) {
	r := s.Get(id)
	if r == nil {
		return nil, fmt.Errorf("not_found")
	}
	base, ok := s.LoadBaseline()
	if !ok {
		return nil, fmt.Errorf("no_baseline")
	}
	var out []CompareResult
	if r.Summary.VerifiedSuccessRate+0.02 < base.VerifiedSuccessRate {
		out = append(out, CompareResult{Severity: "hard", Metric: "verified_success_rate",
			Baseline: base.VerifiedSuccessRate, Current: r.Summary.VerifiedSuccessRate})
	}
	if r.Summary.ScopeViolationCount > 0 {
		out = append(out, CompareResult{Severity: "hard", Metric: "scope_violation_count",
			Baseline: base.ScopeViolationCount, Current: r.Summary.ScopeViolationCount})
	}
	if len(out) == 0 {
		out = append(out, CompareResult{Severity: "unchanged", Metric: "verified_success_rate",
			Baseline: base.VerifiedSuccessRate, Current: r.Summary.VerifiedSuccessRate})
	}
	return out, nil
}
