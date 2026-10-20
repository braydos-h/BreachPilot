package modules_test

// Slice: dns_enum — DNS enumeration via the Go resolver (no subprocess):
// A/AAAA/CNAME/MX/NS/TXT records, capped, allowlist-gated by callers like
// the other registry tools.

import (
	"context"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/modules"
)

func TestDNSEnumLocalhost(t *testing.T) {
	tool, ok := modules.Registry["dns_enum"]
	if !ok {
		t.Fatal("dns_enum must be registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// IP literals skip DNS and echo back; single-label names are rejected
	// by ParseTarget by design.
	out, err := tool.Run(ctx, map[string]any{"target": "127.0.0.1"}, modules.Env{})
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := out["a"].([]string)
	found := false
	for _, a := range addrs {
		if a == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("127.0.0.1 must resolve to itself: %+v", out)
	}
}

func TestDNSEnumRejectsBadTarget(t *testing.T) {
	tool, ok := modules.Registry["dns_enum"]
	if !ok {
		t.Fatal("dns_enum must be registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tool.Run(ctx, map[string]any{"target": "not a host!!"}, modules.Env{}); err == nil {
		t.Fatal("invalid target must be rejected")
	}
	if _, err := tool.Run(ctx, map[string]any{}, modules.Env{}); err == nil {
		t.Fatal("missing target must be rejected")
	}
}
