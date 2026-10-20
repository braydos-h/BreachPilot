package recon_test

// Slice 11 RED: native UDP probing (no nmap subprocess) — open on reply,
// closed on ICMP refused, filtered on timeout — merged into the assessment
// as udp_ports + udp service entries.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/recon"
)

func startUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestScanUDPOpenAndClosed(t *testing.T) {
	open := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := recon.ScanUDP(ctx, "127.0.0.1", []int{open, 49999})
	byPort := map[int]recon.UDPResult{}
	for _, r := range res {
		byPort[r.Port] = r
	}
	if byPort[open].State != "open" {
		t.Fatalf("echo port should be open, got %+v", byPort[open])
	}
	if byPort[49999].State != "closed" && byPort[49999].State != "filtered" {
		t.Fatalf("silent high port must not be open, got %+v", byPort[49999])
	}
}

func TestMergeUDPIntoAssessment(t *testing.T) {
	a := recon.BuildAssessment("10.0.0.9", nil)
	a.MergeUDP([]recon.UDPResult{
		{Port: 53, State: "open"},
		{Port: 49999, State: "closed"},
	})
	found53 := false
	for _, p := range a.UDPPorts {
		if p == 53 {
			found53 = true
		}
		if p == 49999 {
			t.Fatalf("closed port must not land in udp_ports: %v", a.UDPPorts)
		}
	}
	if !found53 {
		t.Fatalf("open udp 53 missing: %+v", a.UDPPorts)
	}
	udpSvc := 0
	for _, s := range a.Services {
		if s.Protocol == "udp" {
			udpSvc++
		}
	}
	if udpSvc == 0 {
		t.Fatalf("expected udp service entries: %+v", a.Services)
	}
}
