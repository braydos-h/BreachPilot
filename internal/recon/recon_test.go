package recon_test

import (
	"context"
	"testing"
	"time"

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
	// Port 1 on loopback is effectively never open; scan must complete fast.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := recon.ScanPorts(ctx, "127.0.0.1", []int{1})
	if len(res) != 1 || res[0].Open {
		t.Fatalf("closed port reported open: %+v", res)
	}
}

func TestBuildAssessment(t *testing.T) {
	a := recon.BuildAssessment("10.0.0.5", []recon.ScanResult{
		{Port: 22, Open: true, Banner: "SSH-2.0-OpenSSH"},
		{Port: 80, Open: false},
	})
	if len(a.OpenPorts) != 1 || a.OpenPorts[0] != 22 {
		t.Fatalf("ports: %+v", a.OpenPorts)
	}
	if len(a.Services) != 1 || a.Services[0].Service != "ssh" {
		t.Fatalf("services: %+v", a.Services)
	}
	if len(a.CVEFindings) != 0 {
		t.Fatal("native recon must not fabricate CVE findings")
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
