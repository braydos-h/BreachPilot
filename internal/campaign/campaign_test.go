package campaign_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/campaign"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

func TestBlackboardPerTargetIsolationAndMilestones(t *testing.T) {
	bb := campaign.NewBlackboard()
	var wg sync.WaitGroup
	targets := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, tgt := range targets {
		tgt := tgt
		wg.Add(1)
		go func() {
			defer wg.Done()
			bb.SetScalar("target_os", "Linux-"+tgt, tgt)
			bb.AppendString("successful_modules", "mod-"+tgt, tgt)
			bb.MarkMilestone(tgt, "recon")
		}()
	}
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, tgt := range targets {
		if err := bb.AwaitMilestone(ctx, tgt, "recon"); err != nil {
			t.Fatalf("await milestone %s: %v", tgt, err)
		}
		if got := bb.Get("target_os", tgt); got != "Linux-"+tgt {
			t.Fatalf("cross-target race on %s: got %v", tgt, got)
		}
	}
}

func TestCriticSpecialistAndRetryAndReflection(t *testing.T) {
	bb := campaign.NewBlackboard()
	bb.AppendString("failed_modules", "ModRepeatFail", "10.0.0.5")

	critic := &campaign.CriticSpecialist{
		AllowedTargets:   []string{"10.0.0.0/24"},
		RequireAllowlist: true,
		ForbiddenModules: map[string]bool{"ForbiddenMod": true},
		MaxAggression:    campaign.AggressionNormal,
	}

	// 1. Out of scope -> deny
	d1 := critic.Review(campaign.AttackTask{Target: "192.168.1.9", ModuleName: "ModA"}, bb)
	if d1.Action != "deny" {
		t.Fatalf("expected deny for out-of-scope target, got %+v", d1)
	}

	// 2. Forbidden module -> deny
	d2 := critic.Review(campaign.AttackTask{Target: "10.0.0.5", ModuleName: "ForbiddenMod"}, bb)
	if d2.Action != "deny" {
		t.Fatalf("expected deny for forbidden module, got %+v", d2)
	}

	// 3. Exhausted failure budget -> deny
	d3 := critic.Review(campaign.AttackTask{Target: "10.0.0.5", ModuleName: "ModRepeatFail", RetryCount: 3, MaxRetries: 3}, bb)
	if d3.Action != "deny" {
		t.Fatalf("expected deny for repeat failure, got %+v", d3)
	}

	// 4. Maximum aggression with normal profile -> modify
	d4 := critic.Review(campaign.AttackTask{Target: "10.0.0.5", ModuleName: "ModOK", Aggression: campaign.AggressionMaximum}, bb)
	if d4.Action != "modify" || d4.NewAggression != campaign.AggressionNormal {
		t.Fatalf("expected modify to normal aggression, got %+v", d4)
	}

	// 5. ShouldRetry refuses permanent errors
	tk := campaign.AttackTask{RetryCount: 0, MaxRetries: 3}
	if campaign.ShouldRetry(tk, "SANDBOX_SCOPE_DENIED: target not in allowlist") {
		t.Fatal("ShouldRetry must refuse permanent scope error")
	}
	if !campaign.ShouldRetry(tk, "temporary connection timeout") {
		t.Fatal("ShouldRetry must allow transient timeout within budget")
	}
}

func TestCheckpointPersistenceAndInterruptedTaskDemotion(t *testing.T) {
	runDir := t.TempDir()
	bb := campaign.NewBlackboard()
	states := map[string]*campaign.TargetCampaignState{
		"127.0.0.1": {
			Target:         "127.0.0.1",
			CurrentPhase:   "validation",
			ReconCompleted: true,
			Assessment:     &recon.Assessment{TargetIP: "127.0.0.1", OpenPorts: []int{80}},
			Tasks: []campaign.AttackTask{
				{TaskID: "ATK-00001", Phase: "recon", Status: campaign.StatusCompleted},
				{TaskID: "ATK-00002", Phase: "validation", Status: campaign.StatusRunning},
				{TaskID: "ATK-00003", Phase: "validation", Status: campaign.StatusRetrying},
			},
		},
	}
	if err := campaign.SaveCheckpoints(runDir, states, bb); err != nil {
		t.Fatal(err)
	}
	loaded, err := campaign.LoadCheckpoints(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st := loaded["127.0.0.1"]
	if st == nil || len(st.Tasks) != 3 {
		t.Fatalf("unexpected loaded state: %+v", st)
	}
	if st.Tasks[0].Status != campaign.StatusCompleted {
		t.Fatal("completed task must remain completed")
	}
	if st.Tasks[1].Status != campaign.StatusPending || st.Tasks[2].Status != campaign.StatusPending {
		t.Fatalf("in-flight running/retrying tasks must be demoted to pending on load: %+v", st.Tasks)
	}
}

func TestEndToEndCampaignRunAndResumeAndScopeReject(t *testing.T) {
	runDir := t.TempDir()
	var events []string
	var mu sync.Mutex
	emit := func(typ string, _ map[string]any) {
		mu.Lock()
		events = append(events, typ)
		mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Authorized campaign run on 127.0.0.1
	res, err := campaign.Run(ctx, campaign.Config{
		RunID:            "run-camp-1",
		Targets:          []string{"127.0.0.1"},
		Mode:             "attack",
		Goal:             "service_mapping",
		RunDir:           runDir,
		AllowedTargets:   []string{"127.0.0.1"},
		RequireAllowlist: true,
		EnableCritic:     true,
		EnableReflection: true,
		Emit:             emit,
	})
	if err != nil {
		t.Fatalf("campaign.Run failed: %v", err)
	}
	if res.Status != "completed" || res.TotalTasks < 3 || res.CompletedTasks < 3 {
		t.Fatalf("unexpected campaign result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(runDir, "swarm_workspace", "swarm_state.json")); err != nil {
		t.Fatalf("missing swarm_state.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "swarm_workspace", "attack_states.json")); err != nil {
		t.Fatalf("missing attack_states.json: %v", err)
	}
	if len(events) == 0 || events[len(events)-1] != "campaign_completed" {
		t.Fatalf("expected ordered campaign events ending in campaign_completed, got %v", events)
	}

	// 2. Unauthorized target fails closed on scope
	_, err = campaign.Run(ctx, campaign.Config{
		RunID:            "run-camp-denied",
		Targets:          []string{"192.168.99.9"},
		Mode:             "attack",
		RunDir:           t.TempDir(),
		AllowedTargets:   []string{"127.0.0.1"},
		RequireAllowlist: true,
	})
	if err == nil {
		t.Fatal("expected scope denial for unauthorized campaign target")
	}
}
