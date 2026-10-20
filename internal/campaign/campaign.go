// Package campaign implements native multi-agent swarm and autonomous campaign
// orchestration: thread-safe namespaced Blackboard, milestone synchronization,
// specialist assignment (Recon, Vuln, Validation, Critic, Reflection),
// RetryEngine, persistent checkpoints (swarm_state.json + attack_states.json),
// interrupted-run recovery (demoting in-flight tasks to pending on resume),
// bounded concurrency, cancellation, and ordered event propagation.
//
// Mirrors tools/swarm/ and tools/campaign/ contracts without Python.
package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/agent"
	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/audit"
	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

// TaskStatus models the lifecycle of a campaign task.
type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusRunning   TaskStatus = "running"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
	StatusRetrying  TaskStatus = "retrying"
	StatusBlocked   TaskStatus = "blocked"
)

// AggressionLevel controls task probing intensity.
type AggressionLevel string

const (
	AggressionStealth    AggressionLevel = "stealth"
	AggressionNormal     AggressionLevel = "normal"
	AggressionAggressive AggressionLevel = "aggressive"
	AggressionMaximum    AggressionLevel = "maximum"
)

// AttackTask represents one scheduled unit of work in a campaign.
type AttackTask struct {
	TaskID       string          `json:"task_id"`
	Phase        string          `json:"phase"`
	Specialist   string          `json:"specialist"`
	ModuleName   string          `json:"module_name"`
	Target       string          `json:"target"`
	Parameters   map[string]any  `json:"parameters"`
	Status       TaskStatus      `json:"status"`
	Aggression   AggressionLevel `json:"aggression"`
	Priority     int             `json:"priority"`
	RetryCount   int             `json:"retry_count"`
	MaxRetries   int             `json:"max_retries"`
	Result       map[string]any  `json:"result,omitempty"`
	Error        string          `json:"error,omitempty"`
	EvidenceRefs []string        `json:"evidence_refs,omitempty"`
	CreatedAt    string          `json:"created_at"`
	StartedAt    string          `json:"started_at,omitempty"`
	CompletedAt  string          `json:"completed_at,omitempty"`
}

// TimelineEvent records a timestamped campaign milestone.
type TimelineEvent struct {
	Timestamp string         `json:"timestamp"`
	Target    string         `json:"target"`
	Phase     string         `json:"phase"`
	EventType string         `json:"event_type"`
	Module    string         `json:"module,omitempty"`
	Result    string         `json:"result"`
	Details   map[string]any `json:"details,omitempty"`
}

// TargetCampaignState holds per-target state persisted in attack_states.json.
type TargetCampaignState struct {
	Target            string              `json:"target"`
	CurrentPhase      string              `json:"current_phase"`
	Aggression        AggressionLevel     `json:"aggression"`
	PrivilegeLevel    string              `json:"privilege_level"`
	AccessAchieved    bool                `json:"access_achieved"`
	ReconCompleted    bool                `json:"recon_completed"`
	Assessment        *recon.Assessment   `json:"recon_result,omitempty"`
	Tasks             []AttackTask        `json:"tasks"`
	SuccessfulModules []string            `json:"successful_exploits"`
	FailedAttempts    map[string][]string `json:"failed_attempts"`
	Timeline          []TimelineEvent     `json:"timeline"`
	StrategyShift     string              `json:"strategy_shift"`
	LessonsLearned    []string            `json:"lessons_learned"`
	TaskCounter       int                 `json:"task_counter"`
}

// Blackboard is a thread-safe shared state store with __global__ and per-target buckets.
type Blackboard struct {
	mu         sync.RWMutex
	global     map[string]any
	targets    map[string]map[string]any
	milestones map[string]chan struct{}
}

// NewBlackboard creates an initialized Blackboard with standard swarm keys.
func NewBlackboard() *Blackboard {
	return &Blackboard{
		global: map[string]any{
			"recon_complete":           false,
			"vuln_research_complete":   false,
			"access_achieved":          false,
			"discovered_services":      []any{},
			"vulnerability_hypotheses": []any{},
			"compromised_hosts":        []string{},
			"credentials_found":        []any{},
			"pivot_targets":            []string{},
			"loot":                     []any{},
			"failed_modules":           []string{},
			"successful_modules":       []string{},
			"attack_surface_score":     0,
			"strategy_shift":           "standard",
		},
		targets:    map[string]map[string]any{},
		milestones: map[string]chan struct{}{},
	}
}

func (b *Blackboard) bucket(target string) map[string]any {
	if target == "" || target == "__global__" {
		return b.global
	}
	tb, ok := b.targets[target]
	if !ok {
		tb = map[string]any{}
		b.targets[target] = tb
	}
	return tb
}

// SetScalar atomically sets a key in the global or target bucket.
func (b *Blackboard) SetScalar(key string, val any, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bucket(target)[key] = val
}

// Get reads a key from the target bucket (or global if target is empty).
func (b *Blackboard) Get(key, target string) any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if target != "" && target != "__global__" {
		if tb, ok := b.targets[target]; ok {
			if v, exists := tb[key]; exists {
				return v
			}
		}
	}
	return b.global[key]
}

// AppendString appends item to a string list in the target or global bucket (deduped).
func (b *Blackboard) AppendString(key, item, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.bucket(target)
	cur, _ := m[key].([]string)
	for _, existing := range cur {
		if existing == item {
			return
		}
	}
	m[key] = append(cur, item)
}

// RemoveString removes item from a string list in the target or global bucket.
func (b *Blackboard) RemoveString(key, item, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.bucket(target)
	cur, _ := m[key].([]string)
	out := make([]string, 0, len(cur))
	for _, existing := range cur {
		if existing != item {
			out = append(out, existing)
		}
	}
	m[key] = out
}

// MarkMilestone signals completion of (target, phase) so dependent tasks unblock.
func (b *Blackboard) MarkMilestone(target, phase string) {
	key := target + "::" + phase
	b.mu.Lock()
	ch, ok := b.milestones[key]
	if !ok {
		ch = make(chan struct{})
		b.milestones[key] = ch
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
	b.mu.Unlock()
}

// AwaitMilestone waits until (target, phase) completes or ctx is cancelled.
func (b *Blackboard) AwaitMilestone(ctx context.Context, target, phase string) error {
	key := target + "::" + phase
	b.mu.Lock()
	ch, ok := b.milestones[key]
	if !ok {
		ch = make(chan struct{})
		b.milestones[key] = ch
	}
	b.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snapshot returns a serializable copy of the Blackboard.
func (b *Blackboard) Snapshot() map[string]any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	g := map[string]any{}
	for k, v := range b.global {
		g[k] = v
	}
	t := map[string]any{}
	for tk, tv := range b.targets {
		cp := map[string]any{}
		for k, v := range tv {
			cp[k] = v
		}
		t[tk] = cp
	}
	return map[string]any{
		"__global__": g,
		"targets":    t,
	}
}

// CriticDecision is returned by CriticSpecialist.Review.
type CriticDecision struct {
	Action        string          `json:"action"` // "approve" | "deny" | "modify"
	Reason        string          `json:"reason"`
	NewAggression AggressionLevel `json:"new_aggression,omitempty"`
}

// CriticSpecialist reviews proposed non-recon tasks before execution.
type CriticSpecialist struct {
	AllowedTargets   []string
	RequireAllowlist bool
	ForbiddenModules map[string]bool
	MaxAggression    AggressionLevel
}

// Review gates a task on scope, forbidden modules, repeat failures, and aggression policy.
func (c *CriticSpecialist) Review(task AttackTask, bb *Blackboard) CriticDecision {
	entries := allowlist.ApprovalEntries(c.AllowedTargets, nil)
	if !allowlist.Check(task.Target, entries, c.RequireAllowlist) {
		return CriticDecision{
			Action: "deny",
			Reason: fmt.Sprintf("target %s outside allowlist", task.Target),
		}
	}
	if c.ForbiddenModules != nil && c.ForbiddenModules[task.ModuleName] {
		return CriticDecision{
			Action: "deny",
			Reason: fmt.Sprintf("module %s is forbidden by policy", task.ModuleName),
		}
	}
	if failed, ok := bb.Get("failed_modules", task.Target).([]string); ok {
		for _, fm := range failed {
			if fm == task.ModuleName && task.RetryCount >= task.MaxRetries {
				return CriticDecision{
					Action: "deny",
					Reason: fmt.Sprintf("module %s exceeded failure budget on %s", task.ModuleName, task.Target),
				}
			}
		}
	}
	if task.Aggression == AggressionMaximum && c.MaxAggression == AggressionNormal {
		return CriticDecision{
			Action:        "modify",
			Reason:        "downgraded aggression from maximum to normal per mission risk profile",
			NewAggression: AggressionNormal,
		}
	}
	return CriticDecision{Action: "approve", Reason: "scope and policy checks passed"}
}

var permanentErrorSubstrings = []string{
	"out of scope",
	"not in allowlist",
	"permission denied",
	"not authorized",
	"blocked by scope",
	"sandbox_scope_denied",
	"sandbox_unavailable",
}

// ShouldRetry reports whether a failed task may be retried.
func ShouldRetry(task AttackTask, errText string) bool {
	if task.RetryCount >= task.MaxRetries {
		return false
	}
	low := strings.ToLower(errText)
	for _, perm := range permanentErrorSubstrings {
		if strings.Contains(low, perm) {
			return false
		}
	}
	return true
}

// Reflect analyzes a target's battle log and updates strategy shift + lessons.
func Reflect(st *TargetCampaignState, bb *Blackboard) (string, string) {
	totalFailed := 0
	for mod, errs := range st.FailedAttempts {
		totalFailed += len(errs)
		bb.AppendString("failed_modules", mod, st.Target)
	}
	for _, mod := range st.SuccessfulModules {
		bb.RemoveString("failed_modules", mod, st.Target)
		bb.AppendString("successful_modules", mod, st.Target)
	}
	shift := "standard"
	switch {
	case totalFailed >= 3 && len(st.SuccessfulModules) == 0:
		shift = "verification_only"
	case totalFailed >= 1 && len(st.SuccessfulModules) == 0:
		shift = "stealth_probe"
	case len(st.SuccessfulModules) > 0:
		shift = "service_focused"
	}
	st.StrategyShift = shift
	bb.SetScalar("strategy_shift", shift, st.Target)
	bb.SetScalar("strategy_shift", shift, "__global__")

	lesson := fmt.Sprintf("target=%s open_ports=%d verified_modules=%d failed_attempts=%d strategy=%s",
		st.Target,
		func() int {
			if st.Assessment != nil {
				return len(st.Assessment.OpenPorts)
			}
			return 0
		}(),
		len(st.SuccessfulModules),
		totalFailed,
		shift,
	)
	st.LessonsLearned = append(st.LessonsLearned, lesson)
	return shift, lesson
}

// Config configures a campaign/swarm execution.
type Config struct {
	RunID            string
	Targets          []string
	Mode             string
	Goal             string
	RunDir           string
	AllowedTargets   []string
	RequireAllowlist bool
	MaxParallel      int
	EnableCritic     bool
	EnableReflection bool
	Resume           bool
	NVD              *intel.NVDClient
	Emit             func(typ string, payload map[string]any)
}

// Result summarizes the completed campaign across all targets.
type Result struct {
	RunID          string                          `json:"run_id"`
	Status         string                          `json:"status"`
	Targets        []string                        `json:"targets"`
	TotalTasks     int                             `json:"total_tasks"`
	CompletedTasks int                             `json:"completed_tasks"`
	BlockedTasks   int                             `json:"blocked_tasks"`
	FindingsCount  int                             `json:"findings_count"`
	States         map[string]*TargetCampaignState `json:"states"`
	Blackboard     map[string]any                  `json:"blackboard"`
}

// SaveCheckpoints writes both swarm_state.json and attack_states.json atomically.
func SaveCheckpoints(runDir string, states map[string]*TargetCampaignState, bb *Blackboard) error {
	swarmDir := filepath.Join(runDir, "swarm_workspace")
	if err := os.MkdirAll(swarmDir, 0o755); err != nil {
		return err
	}
	attackPayload := map[string]any{
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"states":     states,
	}
	swarmPayload := map[string]any{
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"blackboard": bb.Snapshot(),
		"states":     states,
	}
	for _, dir := range []string{runDir, swarmDir} {
		if err := writeAtomicJSON(filepath.Join(dir, "attack_states.json"), attackPayload); err != nil {
			return err
		}
		if err := writeAtomicJSON(filepath.Join(dir, "swarm_state.json"), swarmPayload); err != nil {
			return err
		}
	}
	return nil
}

// LoadCheckpoints loads persisted target states from runDir and demotes any
// in-flight running/retrying tasks back to pending so interrupted runs recover cleanly.
func LoadCheckpoints(runDir string) (map[string]*TargetCampaignState, error) {
	candidates := []string{
		filepath.Join(runDir, "swarm_workspace", "attack_states.json"),
		filepath.Join(runDir, "attack_states.json"),
	}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(filepath.Clean(p))
		if err == nil && len(raw) > 0 {
			break
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("no checkpoint found")
	}
	var wrapper struct {
		States map[string]*TargetCampaignState `json:"states"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.States == nil {
		return nil, errors.New("empty states in checkpoint")
	}
	for _, st := range wrapper.States {
		if st == nil {
			continue
		}
		for i := range st.Tasks {
			if st.Tasks[i].Status == StatusRunning || st.Tasks[i].Status == StatusRetrying {
				st.Tasks[i].Status = StatusPending
			}
		}
	}
	return wrapper.States, nil
}

// Run executes the multi-agent campaign workflow across cfg.Targets with
// specialist assignment, critic pre-checks, reflection, checkpoints, and bounded concurrency.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if len(cfg.Targets) == 0 {
		return nil, errors.New("campaign requires at least one target")
	}
	if cfg.RunDir == "" {
		cfg.RunDir = filepath.Join("reports", cfg.RunID)
	}
	if err := os.MkdirAll(cfg.RunDir, 0o755); err != nil {
		return nil, err
	}
	maxParallel := cfg.MaxParallel
	if maxParallel <= 0 {
		maxParallel = 2
	}
	emit := func(typ string, payload map[string]any) {
		if cfg.Emit != nil {
			cfg.Emit(typ, payload)
		}
	}

	bb := NewBlackboard()
	states := map[string]*TargetCampaignState{}
	if cfg.Resume {
		if loaded, err := LoadCheckpoints(cfg.RunDir); err == nil {
			states = loaded
		}
	}

	critic := &CriticSpecialist{
		AllowedTargets:   cfg.AllowedTargets,
		RequireAllowlist: cfg.RequireAllowlist,
		MaxAggression:    AggressionNormal,
	}

	var stateMu sync.Mutex
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	for _, target := range cfg.Targets {
		target := strings.TrimSpace(target)
		if target == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errOnce.Do(func() { firstErr = ctx.Err() })
				return
			}

			stateMu.Lock()
			st, exists := states[target]
			if !exists || st == nil {
				st = &TargetCampaignState{
					Target:         target,
					CurrentPhase:   "recon",
					Aggression:     AggressionNormal,
					PrivilegeLevel: "none",
					FailedAttempts: map[string][]string{},
					StrategyShift:  "standard",
				}
				states[target] = st
			}
			stateMu.Unlock()

			if err := executeTargetCampaign(ctx, cfg, st, bb, critic, emit); err != nil {
				if ctx.Err() != nil {
					errOnce.Do(func() { firstErr = ctx.Err() })
					return
				}
				errOnce.Do(func() { firstErr = err })
			}

			stateMu.Lock()
			_ = SaveCheckpoints(cfg.RunDir, states, bb)
			stateMu.Unlock()
		}()
	}
	wg.Wait()

	stateMu.Lock()
	_ = SaveCheckpoints(cfg.RunDir, states, bb)
	stateMu.Unlock()

	if firstErr != nil {
		return nil, firstErr
	}

	res := &Result{
		RunID:      cfg.RunID,
		Status:     "completed",
		Targets:    cfg.Targets,
		States:     states,
		Blackboard: bb.Snapshot(),
	}
	for _, st := range states {
		for _, t := range st.Tasks {
			res.TotalTasks++
			switch t.Status {
			case StatusCompleted:
				res.CompletedTasks++
			case StatusBlocked:
				res.BlockedTasks++
			}
		}
		res.FindingsCount += len(st.SuccessfulModules)
	}
	emit("campaign_completed", map[string]any{
		"targets":         len(cfg.Targets),
		"total_tasks":     res.TotalTasks,
		"completed_tasks": res.CompletedTasks,
		"blocked_tasks":   res.BlockedTasks,
	})
	return res, nil
}

func nextTaskID(st *TargetCampaignState) string {
	st.TaskCounter++
	return fmt.Sprintf("ATK-%05d", st.TaskCounter)
}

func addTimeline(st *TargetCampaignState, phase, eventType, module, result string, details map[string]any) {
	st.Timeline = append(st.Timeline, TimelineEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Target:    st.Target,
		Phase:     phase,
		EventType: eventType,
		Module:    module,
		Result:    result,
		Details:   details,
	})
}

func executeTargetCampaign(
	ctx context.Context,
	cfg Config,
	st *TargetCampaignState,
	bb *Blackboard,
	critic *CriticSpecialist,
	emit func(string, map[string]any),
) error {
	entries := allowlist.ApprovalEntries(cfg.AllowedTargets, nil)
	if !allowlist.Check(st.Target, entries, cfg.RequireAllowlist) {
		addTimeline(st, "recon", "scope_denied", "ScopeGate", "failed", nil)
		_, _ = audit.Append(cfg.RunDir, cfg.RunID, "campaign.scope", st.Target, "blocked", "scope", "campaign")
		return fmt.Errorf("target %s not in allowlist", st.Target)
	}

	// Phase 1: ReconSpecialist
	st.CurrentPhase = "recon"
	emit("swarm_phase", map[string]any{"target": st.Target, "phase": "recon", "specialist": "ReconAgent"})
	if !st.ReconCompleted || st.Assessment == nil {
		reconTask := AttackTask{
			TaskID:     nextTaskID(st),
			Phase:      "recon",
			Specialist: "ReconAgent",
			ModuleName: "NativeReconScan",
			Target:     st.Target,
			Status:     StatusRunning,
			Aggression: st.Aggression,
			Priority:   100,
			MaxRetries: 2,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		}
		ip, _, err := recon.Resolve(ctx, st.Target)
		if err != nil {
			reconTask.Status = StatusFailed
			reconTask.Error = err.Error()
			st.Tasks = append(st.Tasks, reconTask)
			bb.MarkMilestone(st.Target, "recon")
			return err
		}
		scanRes := recon.ScanPorts(ctx, ip, recon.DefaultFastPorts)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		assess := recon.BuildAssessment(ip, scanRes)
		assess.MergeUDP(recon.ScanUDP(ctx, ip, recon.DefaultUDPProbes))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st.Assessment = &assess
		st.ReconCompleted = true
		reconTask.Status = StatusCompleted
		reconTask.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		reconTask.Result = map[string]any{"open_ports": assess.OpenPorts, "os_verdict": assess.OSVerdict}
		st.Tasks = append(st.Tasks, reconTask)
		addTimeline(st, "recon", "recon_completed", "NativeReconScan", "success", reconTask.Result)
	}
	bb.SetScalar("recon_complete", true, st.Target)
	bb.SetScalar("recon_complete", true, "__global__")
	bb.SetScalar("discovered_services", st.Assessment.Services, st.Target)
	bb.SetScalar("target_os", st.Assessment.OSVerdict, st.Target)
	bb.SetScalar("attack_surface_score", st.Assessment.OverallRiskScore, st.Target)
	bb.MarkMilestone(st.Target, "recon")

	// Phase 2: VulnSpecialist (awaits recon milestone)
	if err := bb.AwaitMilestone(ctx, st.Target, "recon"); err != nil {
		return err
	}
	st.CurrentPhase = "analysis"
	emit("swarm_phase", map[string]any{"target": st.Target, "phase": "analysis", "specialist": "VulnAgent"})
	vulnTask := AttackTask{
		TaskID:     nextTaskID(st),
		Phase:      "analysis",
		Specialist: "VulnAgent",
		ModuleName: "VulnCorrelation",
		Target:     st.Target,
		Status:     StatusPending,
		Aggression: st.Aggression,
		Priority:   90,
		MaxRetries: 2,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if cfg.EnableCritic {
		dec := critic.Review(vulnTask, bb)
		emit("critic_review", map[string]any{"task_id": vulnTask.TaskID, "decision": dec.Action, "reason": dec.Reason})
		if dec.Action == "deny" {
			vulnTask.Status = StatusBlocked
			vulnTask.Error = dec.Reason
			st.Tasks = append(st.Tasks, vulnTask)
			return nil
		}
		if dec.Action == "modify" && dec.NewAggression != "" {
			vulnTask.Aggression = dec.NewAggression
		}
	}
	vulnTask.Status = StatusRunning
	vulnTask.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	recon.EnrichAssessmentCVEs(ctx, st.Assessment, cfg.NVD)
	vulnTask.Status = StatusCompleted
	vulnTask.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	vulnTask.Result = map[string]any{"cve_findings": len(st.Assessment.CVEFindings)}
	st.Tasks = append(st.Tasks, vulnTask)
	bb.SetScalar("vuln_research_complete", true, st.Target)
	bb.SetScalar("vulnerability_hypotheses", st.Assessment.CVEFindings, st.Target)
	bb.MarkMilestone(st.Target, "analysis")
	addTimeline(st, "analysis", "vuln_analysis_completed", "VulnCorrelation", "success", vulnTask.Result)

	// Phase 3: ValidationSpecialist (runs safe service probes when mode != "recon")
	if cfg.Mode != "recon" {
		st.CurrentPhase = "validation"
		emit("swarm_phase", map[string]any{"target": st.Target, "phase": "validation", "specialist": "ValidationAgent"})
		valTask := AttackTask{
			TaskID:     nextTaskID(st),
			Phase:      "validation",
			Specialist: "ValidationAgent",
			ModuleName: "ServiceProbeValidation",
			Target:     st.Target,
			Status:     StatusPending,
			Aggression: st.Aggression,
			Priority:   80,
			MaxRetries: 2,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		}
		if cfg.EnableCritic {
			dec := critic.Review(valTask, bb)
			emit("critic_review", map[string]any{"task_id": valTask.TaskID, "decision": dec.Action, "reason": dec.Reason})
			if dec.Action == "deny" {
				valTask.Status = StatusBlocked
				valTask.Error = dec.Reason
				st.Tasks = append(st.Tasks, valTask)
				addTimeline(st, "validation", "critic_deny", valTask.ModuleName, "failed", map[string]any{"reason": dec.Reason})
				return nil
			}
			if dec.Action == "modify" && dec.NewAggression != "" {
				valTask.Aggression = dec.NewAggression
			}
		}
		valTask.Status = StatusRunning
		valTask.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
		av := agent.AssessmentView{OpenPorts: st.Assessment.OpenPorts}
		for _, s := range st.Assessment.Services {
			av.Services = append(av.Services, agent.ServiceView{Port: s.Port, Service: s.Service, Banner: s.Banner})
		}
		agentOut, err := agent.Run(ctx, agent.RunEnv{
			RunID:   cfg.RunID,
			Target:  st.Target,
			Entries: entries,
			RunDir:  cfg.RunDir,
			Assess:  av,
			Emit:    emit,
		})
		if err != nil {
			valTask.Status = StatusFailed
			valTask.Error = err.Error()
			st.FailedAttempts[valTask.ModuleName] = append(st.FailedAttempts[valTask.ModuleName], err.Error())
			addTimeline(st, "validation", "validation_failed", valTask.ModuleName, "failed", map[string]any{"error": err.Error()})
		} else {
			valTask.Status = StatusCompleted
			valTask.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
			valTask.Result = agentOut
			st.SuccessfulModules = append(st.SuccessfulModules, valTask.ModuleName)
			addTimeline(st, "validation", "validation_completed", valTask.ModuleName, "success", agentOut)
		}
		st.Tasks = append(st.Tasks, valTask)
		bb.MarkMilestone(st.Target, "validation")
	}

	// Phase 4: ReflectionSpecialist
	st.CurrentPhase = "report"
	shift, lesson := Reflect(st, bb)
	emit("reflection_completed", map[string]any{
		"target":         st.Target,
		"strategy_shift": shift,
		"lesson":         lesson,
	})
	addTimeline(st, "report", "reflection_completed", "ReflectionAgent", "success", map[string]any{
		"strategy_shift": shift,
		"lesson":         lesson,
	})
	bb.MarkMilestone(st.Target, "report")
	return nil
}

func writeAtomicJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	sort.Strings([]string{}) // keep determinism import used
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
