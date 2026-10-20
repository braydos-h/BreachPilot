package recon_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

func TestParseTarget(t *testing.T) {
	h, isIP, err := recon.ParseTarget("10.0.0.5")
	if err != nil || !isIP || h != "10.0.0.5" {
		t.Fatalf("ip: %q %v %v", h, isIP, err)
	}
	h, isIP, err = recon.ParseTarget("Example.COM")
	if err != nil || isIP || h != "example.com" {
		t.Fatalf("domain: %q %v %v", h, isIP, err)
	}
	for _, bad := range []string{"", "not a host!", "-bad-.com", "1.2.3.999.5", "nodot"} {
		if _, _, err := recon.ParseTarget(bad); err == nil {
			t.Fatalf("must reject %q", bad)
		}
	}
}

func TestResolveLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip, _, err := recon.Resolve(ctx, "127.0.0.1")
	if err != nil || ip != "127.0.0.1" {
		t.Fatalf("loopback: %q %v", ip, err)
	}
}

func TestScanClosedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := recon.ScanPorts(ctx, "127.0.0.1", []int{1})
	if len(res) != 1 || res[0].Open {
		t.Fatalf("closed port reported open: %+v", res)
	}
}

func TestBuildAssessmentAndOSFingerprinting(t *testing.T) {
	a := recon.BuildAssessment("10.0.0.5", []recon.ScanResult{
		{Port: 22, Open: true, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
		{Port: 80, Open: true, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)"},
		{Port: 443, Open: false},
	})
	if len(a.OpenPorts) != 2 || a.OpenPorts[0] != 22 || a.OpenPorts[1] != 80 {
		t.Fatalf("ports: %+v", a.OpenPorts)
	}
	if a.OSVerdict != "Linux" {
		t.Fatalf("expected Linux OS verdict from Ubuntu banner, got %q", a.OSVerdict)
	}
	if a.Services[0].Version != "OpenSSH 8.9p1" || a.Services[1].Version != "Apache 2.4.49" {
		t.Fatalf("unexpected service versions: %+v", a.Services)
	}
	if len(a.CVEFindings) != 0 {
		t.Fatal("BuildAssessment alone must not fabricate CVE findings")
	}

	// Enrich with a controlled local NVD server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2021-41773","published":"2021-10-05","descriptions":[{"lang":"en","value":"Path traversal"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}]}`))
	}))
	defer srv.Close()

	s := intel.DefaultSettings()
	s.NVDBaseURL = srv.URL
	nvd := intel.NewNVDClient(s)
	recon.EnrichAssessmentCVEs(context.Background(), &a, nvd)
	if len(a.CVEFindings) == 0 {
		t.Fatal("expected CVE findings after enrichment")
	}
}

func TestApplyNmapPrivilegeDowngrade(t *testing.T) {
	args, note := recon.ApplyNmapPrivilege([]string{"nmap", "-sS", "-O", "--osscan-guess", "10.0.0.5"}, false, false, true)
	if note == "" {
		t.Fatal("expected downgrade note")
	}
	for _, a := range args {
		if a == "-sS" || a == "-O" || a == "--osscan-guess" {
			t.Fatalf("privileged flag %q not downgraded: %v", a, args)
		}
	}
	foundST := false
	for _, a := range args {
		if a == "-sT" {
			foundST = true
		}
	}
	if !foundST {
		t.Fatalf("expected -sT in downgraded args: %v", args)
	}

	sudoArgs, sudoNote := recon.ApplyNmapPrivilege([]string{"nmap", "-sS", "10.0.0.5"}, false, true, true)
	if sudoNote != "" || sudoArgs[0] != "sudo" || sudoArgs[1] != "-n" {
		t.Fatalf("expected sudo -n prefix, got %v", sudoArgs)
	}
}

func TestSuggestGoalsHonest(t *testing.T) {
	s := recon.SuggestGoals([]int{80, 443}, "recon")
	if len(s) == 0 {
		t.Fatal("web ports must yield suggestions")
	}
	empty := recon.SuggestGoals(nil, "recon")
	found := false
	for _, g := range empty {
		if g.Name == "recon_only" {
			found = true
		}
	}
	if !found {
		t.Fatal("empty scan must suggest recon_only")
	}
}
