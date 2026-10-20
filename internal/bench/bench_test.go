package bench_test

import (
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/bench"
	"github.com/braydos-h/BreachPilot/internal/events"
)

func testService(t *testing.T) *bench.Service {
	t.Helper()
	return bench.New(t.TempDir(), []string{"127.0.0.1"}, true, events.NewRegistry())
}

func waitDone(t *testing.T, s *bench.Service, id string) *bench.Run {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		r := s.Get(id)
		if r == nil {
			t.Fatal("run vanished")
		}
		if r.State == "completed" {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for completion (state %s)", r.State)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func TestStartValidation(t *testing.T) {
	s := testService(t)
	if _, err := s.Start("", 1, 0); err == nil || err.Error() != "missing_suite" {
		t.Fatalf("empty suite: %v", err)
	}
	if _, err := s.Start("nope", 1, 0); err == nil {
		t.Fatal("unknown suite must fail")
	}
	if _, err := s.Start("native-smoke", 0, 0); err == nil {
		t.Fatal("bad trials must fail")
	}
	if _, err := s.Start("native-smoke", 1, 10); err == nil {
		t.Fatal("short timeout must fail")
	}
}

func TestSmokeTrialsSolve(t *testing.T) {
	s := testService(t)
	run, err := s.Start("native-smoke", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != "running" {
		t.Fatalf("state: %s", run.State)
	}
	done := waitDone(t, s, run.RunID)
	if done.Summary.Solved != 2 || done.Summary.VerifiedSuccessRate != 1.0 || done.Summary.ScopeViolationCount != 0 {
		t.Fatalf("summary: %+v", done.Summary)
	}
	for _, tr := range done.Trials {
		if tr.Status != "verified" || !tr.Solved {
			t.Fatalf("trial: %+v", tr)
		}
	}
}

func TestSingleActiveGuard(t *testing.T) {
	s := testService(t)
	r1, err := s.Start("native-smoke", 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start("native-smoke", 1, 0); err == nil {
		t.Fatal("second concurrent run must conflict")
	}
	waitDone(t, s, r1.RunID)
	if _, err := s.Start("native-smoke", 1, 0); err != nil {
		t.Fatalf("run after completion: %v", err)
	}
}

func TestScopeViolationRecorded(t *testing.T) {
	s := bench.New(t.TempDir(), nil, true, events.NewRegistry())
	run, err := s.Start("native-smoke", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, s, run.RunID)
	if done.Summary.ScopeViolationCount != 1 || done.Summary.Solved != 0 {
		t.Fatalf("scope trial: %+v", done.Summary)
	}
}

func TestBaselineCompare(t *testing.T) {
	s := testService(t)
	run, err := s.Start("native-smoke", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, s, run.RunID)
	if _, err := s.SaveBaseline("nope"); err == nil {
		t.Fatal("baseline of unknown run must fail")
	}
	base, err := s.SaveBaseline(done.RunID)
	if err != nil || base.VerifiedSuccessRate != 1.0 {
		t.Fatalf("save: %+v %v", base, err)
	}
	if _, ok := s.LoadBaseline(); !ok {
		t.Fatal("baseline must load")
	}
	cmp, err := s.Compare(done.RunID)
	if err != nil || len(cmp) != 1 || cmp[0].Severity != "unchanged" {
		t.Fatalf("compare same: %+v %v", cmp, err)
	}
	if _, err := s.Compare("nope"); err == nil {
		t.Fatal("compare unknown run must fail")
	}
	// Scope-violating run vs clean baseline => hard fail.
	s2 := bench.New(t.TempDir(), nil, true, events.NewRegistry())
	bad, _ := s2.Start("native-smoke", 1, 0)
	waitDone(t, s2, bad.RunID)
	if _, err := s2.SaveBaseline(bad.RunID); err != nil {
		t.Fatal(err)
	}
	cmp2, err := s2.Compare(bad.RunID)
	if err != nil || len(cmp2) == 0 || cmp2[0].Severity != "hard" {
		t.Fatalf("scope baseline compare: %+v %v", cmp2, err)
	}
}
