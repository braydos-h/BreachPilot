package memory_test

import (
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/memory"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func TestMemoryAliasesRetrieveAndCrossMissionSimilarity(t *testing.T) {
	tmp := t.TempDir()
	db, err := store.Open(filepath.Join(tmp, "mem.db"), filepath.Join(tmp, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m1 := memory.New(db, "mission-1")
	rec, err := m1.Remember("10.0.0.5", "Apache 2.4.49 path traversal observed on /cgi-bin", "vuln_research", []string{"apache", "http_80"}, 0.9, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Alias "vuln_research" must normalize to "hypothesis" and preserve original_memory_type in metadata + tags.
	if rec.MemoryType != "hypothesis" {
		t.Fatalf("expected normalized type hypothesis, got %q", rec.MemoryType)
	}
	if rec.Metadata["original_memory_type"] != "vuln_research" {
		t.Fatalf("expected original_memory_type preserved in metadata, got %+v", rec.Metadata)
	}

	// Escaped LIKE tag filter with underscore in tag ("http_80")
	got, err := m1.Retrieve("10.0.0.5", "hypothesis", []string{"http_80"}, 10)
	if err != nil || len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("retrieve by tag failed: %v %+v", err, got)
	}

	// Cross-mission similarity fallback from mission-2
	m2 := memory.New(db, "mission-2")
	rel, err := m2.RetrieveRelevant("10.0.0.99", "investigating apache cgi-bin traversal on port 80", 5)
	if err != nil || len(rel) != 1 || rel[0].ID != rec.ID {
		t.Fatalf("expected cross-mission similarity recall of mission-1 memory, got %+v (err=%v)", rel, err)
	}

	// Store and list semantic lessons
	les, err := m2.StoreLesson("10.0.0.99", "reflection", "Use safe header probes before version checks", []string{"recon", "http"})
	if err != nil || les.ID == "" {
		t.Fatalf("StoreLesson failed: %v", err)
	}
	lessons, err := m2.ListLessons(10)
	if err != nil || len(lessons) != 1 || lessons[0].Summary != les.Summary {
		t.Fatalf("ListLessons mismatch: %+v %v", lessons, err)
	}
}
