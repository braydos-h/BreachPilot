package bench_test

// Slice 7 RED: a synchronous eval entrypoint must exist — start the suite,
// wait for completion, and return the graded run (or fail on bad suite and
// on timeout) — before the --eval CLI can be wired to it.

import (
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/bench"
	"github.com/braydos-h/BreachPilot/internal/events"
)

func TestRunSyncCompletes(t *testing.T) {
	svc := bench.New(t.TempDir(), []string{"127.0.0.1", "localhost", "::1"}, true, events.NewRegistry())
	run, err := bench.RunSync(svc, "native-smoke", 1, 60, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != "completed" {
		t.Fatalf("state = %q, want completed", run.State)
	}
	if run.Summary.TrialsCompleted != 1 {
		t.Fatalf("trials completed = %d, want 1: %+v", run.Summary.TrialsCompleted, run.Summary)
	}
}

func TestRunSyncRejectsUnknownSuite(t *testing.T) {
	svc := bench.New(t.TempDir(), nil, false, events.NewRegistry())
	if _, err := bench.RunSync(svc, "nope", 1, 60, time.Second); err == nil {
		t.Fatal("unknown suite must fail")
	}
}

func TestRunSyncReportsGradedSummary(t *testing.T) {
	svc := bench.New(t.TempDir(), []string{"127.0.0.1", "localhost", "::1"}, true, events.NewRegistry())
	run, err := bench.RunSync(svc, "native-smoke", 1, 60, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if run.Summary.Suite != "native-smoke" || run.Summary.TrialsTotal != 1 {
		t.Fatalf("ungraded summary: %+v", run.Summary)
	}
}
