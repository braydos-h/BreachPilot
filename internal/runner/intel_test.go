package runner_test

// Slice 5: wiring the Intel client into recon runs. The NVD server is a
// local stub; the assertion is structural (assessment carries the
// cve_findings key and the run completes) so it holds with or without live
// version banners on loopback.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func TestReconRunEnrichesWithIntel(t *testing.T) {
	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2021-41773","published":"2021-10-05","descriptions":[{"lang":"en","value":"Path traversal"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}]}`))
	}))
	defer nvdSrv.Close()

	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := events.NewRegistry()
	r := runner.New(db, reg, filepath.Join(dir, "reports"), []string{"127.0.0.1"}, true, 2)
	s := intel.DefaultSettings()
	s.NVDBaseURL = nvdSrv.URL
	r.Intel = intel.NewNVDClient(s)

	req := `{"target":"127.0.0.1","mode":"recon","goal":"","kind":"agent","yes":true}`
	if err := db.CreateRun("run-intel1", "queued", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	r.Ensure("run-intel1")
	waitState(t, db, "run-intel1", "completed")
	raw, err := os.ReadFile(filepath.Join(dir, "reports", "run-intel1", "recon_assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"cve_findings"`) {
		t.Fatalf("assessment must carry cve_findings key: %s", raw)
	}
}
