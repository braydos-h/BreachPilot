package bench_test

// Slice 20 RED: graded oracle evaluation (loading eval_targets/*.oracle.json,
// scoring true/false positives + negative controls, and live HTTP flag checks).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/bench"
)

func TestLoadOraclesAndScore(t *testing.T) {
	oracles, err := bench.LoadOracles(filepath.Join("..", "..", "eval_targets"))
	if err != nil {
		t.Fatal(err)
	}
	if len(oracles) < 5 {
		t.Fatalf("expected at least 5 oracle targets in eval_targets/, got %d", len(oracles))
	}

	var dvwa, secureWeb *bench.OracleTarget
	for i := range oracles {
		switch oracles[i].TargetID {
		case "dvwa":
			dvwa = &oracles[i]
		case "secure_web":
			secureWeb = &oracles[i]
		}
	}
	if dvwa == nil || secureWeb == nil {
		t.Fatalf("missing dvwa or secure_web oracle")
	}

	// Score DVWA with matching findings
	sc := bench.ScoreAgainstOracle(*dvwa, []int{80}, []string{"http"}, []string{"sqli", "xss", "unlisted_vuln"})
	if sc.TruePositives != 2 || sc.FalsePositives != 1 || !sc.Success {
		t.Fatalf("unexpected DVWA score: %+v", sc)
	}

	// Score negative-control target (secure_web): 0 findings => success; 1 finding => failure
	ncPass := bench.ScoreAgainstOracle(*secureWeb, nil, nil, nil)
	if !ncPass.NegativeControlPassed || !ncPass.Success {
		t.Fatalf("negative control with 0 findings must pass: %+v", ncPass)
	}
	ncFail := bench.ScoreAgainstOracle(*secureWeb, nil, nil, []string{"sqli"})
	if ncFail.NegativeControlPassed || ncFail.Success || ncFail.FalsePositives != 1 {
		t.Fatalf("negative control with hallucinated finding must fail: %+v", ncFail)
	}
}

func TestVerifyOracleFlagsLiveHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/setup.php" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	oracle := bench.OracleTarget{
		TargetID: "test_web",
		Flags: []bench.OracleFlag{
			{
				ID:          "setup_exposed",
				Description: "setup page reachable",
				Check: bench.OracleCheck{
					Type:         "http_request",
					URL:          srv.URL + "/setup.php",
					ExpectStatus: 200,
				},
			},
		},
	}
	res := bench.VerifyOracleFlags(context.Background(), oracle)
	if res.FlagsPassed != 1 || res.FlagsTotal != 1 {
		t.Fatalf("expected 1/1 flag passed, got %+v", res)
	}
}
