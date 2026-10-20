package recon_test

// Slice 19 RED: native OS fingerprinting with graceful unprivileged fallback +
// masscan/rustscan native-compatible high-speed scanner integration.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/recon"
)

func TestNativeOSFingerprintUnprivilegedFallback(t *testing.T) {
	services := []recon.Service{
		{Port: 22, Protocol: "tcp", Service: "ssh", Version: "OpenSSH 8.9p1", Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"},
		{Port: 80, Protocol: "tcp", Service: "http", Version: "Apache 2.4.52", Banner: "Server: Apache/2.4.52 (Ubuntu)"},
	}
	fp := recon.FingerprintOS(context.Background(), "127.0.0.1", []int{22, 80}, services, recon.OSFingerprintOptions{
		AllowPrivilegedNmap: false,
	})
	if fp.Family != "Linux" {
		t.Fatalf("expected Linux family, got %+v", fp)
	}
	if fp.Distro != "Ubuntu" {
		t.Fatalf("expected Ubuntu distro, got %+v", fp)
	}
	if fp.Confidence < 0.7 {
		t.Fatalf("expected confidence >= 0.7, got %v", fp.Confidence)
	}
	if fp.PrivilegeMode != "unprivileged_native" {
		t.Fatalf("expected unprivileged_native mode, got %q", fp.PrivilegeMode)
	}
	if len(fp.CPEs) == 0 {
		t.Fatalf("expected CPEs in fingerprint: %+v", fp)
	}
}

func TestFastScannerNativeAndParser(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res := recon.RunFastScanner(ctx, "127.0.0.1", []int{openPort, 59998}, recon.FastScannerOptions{
		PreferExternal: false,
		Concurrency:    16,
		Timeout:        500 * time.Millisecond,
	})
	if res.Backend != "native_go" {
		t.Fatalf("expected native_go backend, got %q", res.Backend)
	}
	found := false
	for _, p := range res.OpenPorts {
		if p == openPort {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected open port %d in %v", openPort, res.OpenPorts)
	}

	// Verify masscan & rustscan output parsers
	masscanOut := "Discovered open port 443/tcp on 10.0.0.5\nDiscovered open port 8080/tcp on 10.0.0.5\n"
	mp := recon.ParseMasscanOutput(masscanOut)
	if len(mp) != 2 || mp[0] != 443 || mp[1] != 8080 {
		t.Fatalf("unexpected masscan parse: %v", mp)
	}
	rustscanOut := "Open 10.0.0.5:22\nOpen 10.0.0.5:80\n"
	rp := recon.ParseRustscanOutput(rustscanOut)
	if len(rp) != 2 || rp[0] != 22 || rp[1] != 80 {
		t.Fatalf("unexpected rustscan parse: %v", rp)
	}
}
